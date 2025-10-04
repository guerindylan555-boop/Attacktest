# AutomationController Internal API Contract

**Component**: `automation.services.automation_controller.AutomationController`  
**Purpose**: Control recording and replaying of automation workflows with duration enforcement and interaction gating

## Methods

### `start_recording() -> dict`

**Description**: Start a new recording session with automatic duration limit enforcement.

**Preconditions**:
- Required services (emulator, frida) must be in `running` state
- No recording currently in progress (`current_recording is None`)

**Behavior**:
1. Check service readiness via `service_manager.get_service_snapshot()`
2. If services not ready: return error
3. Create `AutomationRecording(duration_limit_seconds=1800)`
4. Call `recording.start_recording()`
5. Open incremental JSONL file for appending
6. Start duration enforcement timer (check every 60s)
7. Set `_record_in_progress = True`

**Returns**:
```python
# Success
{
    "status": "success",
    "session_id": "fd0a69b0-8f92-422c-8fdf-a70347cbfe12",
    "ui_state": {"record_button": "disable", "stop_button": "enable"}
}

# Failure (services not ready)
{
    "status": "error",
    "reason": "services_not_ready",
    "blocking_services": ["frida"],
    "ui_state": {"record_button": "disable", "stop_button": "disable"}
}
```

**Postconditions**:
- `self.current_recording` is set
- Incremental file exists at `automation/recordings/{timestamp}_{id}.jsonl`
- Duration timer is active

**Performance**: <100ms (file creation is fast)

---

### `stop_recording() -> dict`

**Description**: Stop active recording session and finalize persistence.

**Preconditions**:
- Recording must be in progress (`current_recording is not None`)

**Behavior**:
1. Call `current_recording.stop_recording()`
2. Close incremental JSONL file
3. Write final JSON summary via `recording.save_to_file()`
4. Stop duration enforcement timer
5. Set `_record_in_progress = False`
6. Clear `current_recording`

**Returns**:
```python
{
    "status": "success",
    "session_id": "fd0a69b0-...",
    "duration": 1234.5,
    "interactions_count": 456,
    "file_path": "/path/to/recording.json",
    "auto_stopped": False
}
```

**Postconditions**:
- Recording persisted to disk (both `.jsonl` and `.json` files)
- `current_recording` is `None`
- Duration timer stopped

---

### `add_interaction(interaction_type: str, **kwargs) -> dict`

**Description**: Capture a user interaction during active recording.

**Parameters**:
- `interaction_type`: `"click"`, `"type"`, or `"scroll"`
- `**kwargs`: Type-specific data (x, y for click; text for type; direction, amount for scroll)

**Preconditions**:
- Recording must be active (`_record_in_progress == True`)
- Interaction must be valid per InteractionEvent schema

**Behavior**:
1. Check if recording active; if not, return error
2. Validate interaction data (e.g., click has x, y coordinates)
3. Create interaction dict with timestamp
4. Append to `current_recording.interactions` (in-memory)
5. Immediately append to incremental JSONL file (disk)
6. Return success with interaction count

**Returns**:
```python
# Success
{
    "status": "success",
    "interaction_count": 457
}

# Error (recording not active)
{
    "status": "error",
    "reason": "recording_not_active",
    "message": "Recording must be started first"
}
```

**Performance**: <50ms (file append is fast)

**Error Handling**:
- If disk write fails: mark recording as failed, save partial data
- If validation fails: return error, do NOT add to recording

---

### `_enforce_duration_limit() -> None`

**Description**: Background timer callback that checks recording duration and auto-stops if limit reached.

**Behavior** (runs every 60 seconds):
1. If no recording active: return early
2. Calculate elapsed time: `now() - recording.start_time`
3. If elapsed >= `duration_limit_seconds`:
   - Set `recording.auto_stopped = True`
   - Call `stop_recording()`
   - Show warning message in UI log

**Side Effects**:
- Automatically stops recording
- Logs warning: `"[WARN] Recording auto-stopped: 30-minute limit reached"`

---

### `is_recording_allowed() -> dict`

**Description**: Check if starting a recording is currently allowed (services ready, no active recording).

**Returns**:
```python
{
    "allowed": True | False,
    "reason": "ok" | "services_not_ready" | "recording_in_progress",
    "blocking_services": ["frida"]  # if services not ready
}
```

**Performance**: <10ms (just checks flags)

---

### `is_interaction_allowed() -> dict`

**Description**: Check if user interactions should be processed (recording must be active).

**Returns**:
```python
{
    "allowed": True | False,
    "reason": "ok" | "recording_not_active"
}
```

**Used by**: Qt UI to block screen preview clicks when recording inactive (FR-021a)

---

### `get_action_states() -> dict`

**Description**: Get current state of all control actions (record, replay, capture_token) for UI.

**Returns**:
```python
{
    "actions": [
        {
            "action": "record",
            "enabled": False,
            "requires": ["emulator", "frida"],
            "blocking_services": ["frida"],
            "tooltip": "Frida service must be running"
        },
        {
            "action": "replay",
            "enabled": True,
            "requires": ["emulator", "proxy", "frida"],
            "blocking_services": [],
            "tooltip": "Ready to replay"
        }
    ],
    "services": [...]  # ServiceManagerSnapshot
}
```

**Performance**: <50ms (includes service snapshot refresh)

---

## State Machine

```
┌─────────┐
│  IDLE   │ (no recording)
└────┬────┘
     │ start_recording() [services ready]
     v
┌──────────┐
│RECORDING │ (current_recording != None)
│          │ <───┐
│ • add_interaction() allowed
│ • duration timer active
│ • incremental file open
└────┬─────┘    │
     │          │ (duration < limit)
     │ stop_recording() OR auto-stop (duration >= limit)
     v
┌─────────┐
│COMPLETED│
│         │ (recording saved to disk)
└─────────┘
```

---

## Interaction Gating (FR-021a)

**Requirement**: Block screen preview interactions when recording is NOT active.

**Implementation**:
1. Qt UI calls `is_interaction_allowed()` before processing click/type/scroll
2. If `allowed == False`:
   - Show error message: `"Recording must be started first"`
   - Do NOT relay interaction to Android device
   - Do NOT call `add_interaction()`

**Test Case**:
```python
# Given: recording not active
controller.is_recording_allowed()  # {"allowed": False, ...}

# When: user clicks screen preview
result = controller.add_interaction("click", x=540, y=960)

# Then: interaction rejected
assert result["status"] == "error"
assert result["reason"] == "recording_not_active"
assert len(controller.current_recording.interactions) == 0  # not added
```

---

## Duration Limit Enforcement (FR-017a/b)

**Requirement**: Auto-stop recording at 30 minutes with warning.

**Implementation**:
1. Timer checks duration every 60 seconds
2. At 29:00: log warning `"[WARN] Recording will auto-stop in 1 minute"`
3. At 30:00: 
   - Set `auto_stopped = True`
   - Call `stop_recording()`
   - Log: `"[WARN] Recording auto-stopped: 30-minute limit reached"`
   - Show UI message box

**Test Case**:
```python
# Given: recording active for 30 minutes
recording.start_time = now() - timedelta(minutes=30, seconds=1)

# When: duration timer fires
controller._enforce_duration_limit()

# Then: recording auto-stopped
assert controller.current_recording is None
assert recording.auto_stopped == True
assert recording.duration >= 1800
```

---

## Incremental Persistence (FR-016)

**Requirement**: Persist each interaction immediately to prevent data loss.

**Implementation**:
```python
def add_interaction(self, interaction_type, **kwargs):
    interaction = {
        "type": interaction_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **kwargs
    }
    
    # In-memory
    self.current_recording.interactions.append(interaction)
    
    # Disk (immediate)
    with open(self.current_recording.incremental_file, 'a') as f:
        f.write(json.dumps(interaction) + '\n')
        f.flush()  # force OS to write
```

**Crash Recovery**:
- If app crashes mid-recording: `.jsonl` file contains all interactions up to crash
- User can manually convert `.jsonl` to `.json` summary if needed

---

## Testing Contract

Tests MUST verify:
1. ✅ `start_recording()` fails if services not ready
2. ✅ `add_interaction()` fails if recording not active
3. ✅ Duration limit triggers auto-stop at 30 minutes
4. ✅ Incremental persistence writes after each interaction
5. ✅ `is_interaction_allowed()` returns False when idle
6. ✅ `stop_recording()` writes both `.jsonl` and `.json` files
7. ✅ Crash during recording: `.jsonl` file has partial data

