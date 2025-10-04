# Phase 1: Data Model - Control Center Reliability Fixes

**Date**: 2025-10-04  
**Feature**: 003-fix-the-app

## Entity Definitions

This document defines the data models required for service retry logic, recording duration enforcement, and interaction persistence. Entities are extracted from the feature specification's Key Entities section and clarification answers.

---

## 1. ServiceStatus

**Purpose**: Represents the runtime state of a managed background service (emulator, proxy, Frida hook) with retry awareness.

### Fields

| Field Name | Type | Required | Default | Description |
|------------|------|----------|---------|-------------|
| `name` | `str` | Yes | - | Service identifier (`"emulator"`, `"proxy"`, `"frida"`) |
| `state` | `ServiceState` | Yes | `pending` | Current state enum: `pending`, `starting`, `running`, `failed`, `stopped` |
| `pid` | `int \| None` | No | `None` | Process ID if service is running |
| `log_file` | `Path \| None` | No | `None` | Path to service log file for diagnostics |
| `error_message` | `str \| None` | No | `None` | Last error message if state is `failed` |
| `retry_count` | `int` | Yes | `0` | Number of retry attempts made (0-3) |
| `max_retries` | `int` | Yes | `3` | Maximum retry attempts before manual intervention |
| `retry_delay` | `float` | Yes | `5.0` | Delay in seconds between retry attempts |
| `last_retry_at` | `datetime \| None` | No | `None` | Timestamp of last retry attempt (ISO format) |
| `startup_time` | `float \| None` | No | `None` | Time in seconds taken to start successfully |

### State Transitions

```
pending → starting → running (success)
        ↓            ↓
        failed → starting (retry if retry_count < max_retries)
               → failed (permanent after max_retries)
        
running → stopped (manual stop or crash)
stopped → pending (reset for restart)
```

### Validation Rules

- `retry_count` must be >= 0 and <= `max_retries`
- `state` must be `failed` if `error_message` is set
- `last_retry_at` must be set when `retry_count` > 0
- `pid` must be `None` unless `state` is `running`

### Relationships

- **Parent**: `ServiceManager` owns collection of `ServiceStatus` instances (one per managed service)
- **Consumed by**: `ServiceManagerSnapshot` aggregates status for UI display
- **Used by**: `ControlActionState` checks service readiness for actions

---

## 2. AutomationRecording

**Purpose**: Represents a single automation recording session with incremental persistence and duration enforcement.

### Fields

| Field Name | Type | Required | Default | Description |
|------------|------|----------|---------|-------------|
| `id` | `str` | Yes | `uuid4()` | Unique session identifier (UUID) |
| `timestamp` | `str` | Yes | `now()` | ISO 8601 timestamp of recording start |
| `duration` | `float` | Yes | `0.0` | Total duration in seconds (calculated on stop) |
| `duration_limit_seconds` | `int` | Yes | `1800` | Maximum recording duration (30 minutes) |
| `auto_stopped` | `bool` | Yes | `False` | Flag indicating if recording was auto-stopped due to duration limit |
| `interactions` | `list[dict]` | Yes | `[]` | List of captured interaction events |
| `metadata` | `dict` | Yes | `{}` | Recording metadata (device info, app version, etc.) |
| `state` | `str` | Yes | `"pending"` | Recording state: `pending`, `recording`, `completed`, `failed` |
| `file_path` | `Path \| None` | No | `None` | Path to saved recording JSON file |
| `incremental_file` | `Path \| None` | No | `None` | Path to incremental JSONL file for live persistence |
| `last_error` | `str \| None` | No | `None` | Error message if state is `failed` |

### State Transitions

```
pending → recording → completed (manual stop)
                   → completed (auto-stop at duration_limit)
                   → failed (error during recording)
```

### Validation Rules

- `duration` must be >= 0
- `duration` must be <= `duration_limit_seconds` when state is `completed`
- `auto_stopped` must be `True` if `duration` >= `duration_limit_seconds`
- `state` must be `"recording"` to add interactions
- `file_path` must be set when state is `completed` or `failed`

### Relationships

- **Parent**: `AutomationController` manages current recording session
- **Contains**: List of `InteractionEvent` dictionaries (not a separate model)
- **Persisted to**: JSON file at `automation/recordings/{timestamp}_automation_recording_{id}.json`
- **Incremental persistence**: JSONL file at `automation/recordings/{timestamp}_automation_recording_{id}.jsonl`

---

## 3. InteractionEvent

**Purpose**: Represents a single user interaction captured during a recording session. (Not a separate class; dict structure within AutomationRecording)

### Structure (dict fields)

| Field Name | Type | Required | Description |
|------------|------|----------|-------------|
| `type` | `str` | Yes | Interaction type: `"click"`, `"type"`, `"scroll"` |
| `timestamp` | `str` | Yes | ISO 8601 timestamp when interaction occurred |
| `x` | `int` | Conditional | X coordinate (required for `type="click"`) |
| `y` | `int` | Conditional | Y coordinate (required for `type="click"`) |
| `text` | `str` | Conditional | Text content (required for `type="type"`) |
| `direction` | `str` | Conditional | Scroll direction: `"up"`, `"down"`, `"left"`, `"right"` (required for `type="scroll"`) |
| `amount` | `int` | Conditional | Scroll distance in pixels (required for `type="scroll"`) |

### Validation Rules

- `type` must be one of: `"click"`, `"type"`, `"scroll"`
- If `type="click"`: `x` and `y` must be present, both >= 0
- If `type="type"`: `text` must be present and non-empty
- If `type="scroll"`: `direction` and `amount` must be present, `amount` > 0

### Example Instances

```python
# Click interaction
{
    "type": "click",
    "timestamp": "2025-10-04T14:32:01.234Z",
    "x": 540,
    "y": 960
}

# Type interaction
{
    "type": "type",
    "timestamp": "2025-10-04T14:32:05.567Z",
    "text": "test@example.com"
}

# Scroll interaction
{
    "type": "scroll",
    "timestamp": "2025-10-04T14:32:10.890Z",
    "direction": "down",
    "amount": 300
}
```

---

## 4. ServiceManagerSnapshot

**Purpose**: Immutable snapshot of all managed services' status at a point in time (for UI consumption).

### Fields

| Field Name | Type | Required | Description |
|------------|------|----------|-------------|
| `timestamp` | `str` | Yes | ISO 8601 timestamp when snapshot was created |
| `services` | `list[dict]` | Yes | List of service status dictionaries (serialized from ServiceStatus) |
| `all_ready` | `bool` | Yes | True if all services are in `running` state, False otherwise |
| `failed_services` | `list[str]` | Yes | List of service names currently in `failed` state |
| `retry_in_progress` | `bool` | Yes | True if any service is currently retrying (has retry_count > 0 and < max_retries) |

### Validation Rules

- `all_ready` must be `True` only if all services in `services` have `state="running"`
- `failed_services` must contain names of all services with `state="failed"`
- `retry_in_progress` must be `True` if any service has `retry_count > 0` and `state != "running"`

### Relationships

- **Generated by**: `ServiceManager.get_service_snapshot()`
- **Consumed by**: Qt UI (control_center.py) for button enable/disable logic
- **Used by**: `AutomationController.get_action_states()` to determine action readiness

---

## 5. ControlActionState

**Purpose**: Represents the readiness state of a control action (record, replay, capture_token) based on service dependencies.

### Fields (Existing - No Changes)

| Field Name | Type | Required | Description |
|------------|------|----------|-------------|
| `action` | `str` | Yes | Action name: `"record"`, `"replay"`, `"capture_token"` |
| `enabled` | `bool` | Yes | True if action can be executed (all required services ready) |
| `requires` | `list[str]` | Yes | List of required service names |
| `blocking_services` | `list[str]` | Yes | List of services preventing action (not ready) |
| `tooltip` | `str` | Yes | User-facing message explaining state |

### Relationships

- **Generated by**: `AutomationController._state_for_action()`
- **Depends on**: `ServiceManagerSnapshot.all_ready` and per-service status
- **Consumed by**: Qt UI for button enable/disable and tooltip display

**Note**: This entity exists in current codebase (`automation/models/control_action.py`) and requires no schema changes for this feature.

---

## Data Flow Diagram

```
┌─────────────────┐
│ ServiceManager  │
│                 │
│ services: {     │
│   "emulator":   │
│     ServiceStatus(retry_count=1, state="starting")
│   "proxy":      │
│     ServiceStatus(retry_count=0, state="running")
│   "frida":      │
│     ServiceStatus(retry_count=3, state="failed")
│ }               │
└────────┬────────┘
         │ get_service_snapshot()
         v
┌────────────────────────┐
│ ServiceManagerSnapshot │
│                        │
│ all_ready: False       │
│ failed_services: ["frida"]
│ retry_in_progress: True│
└────────┬───────────────┘
         │
         v
┌─────────────────────┐        ┌──────────────────┐
│ AutomationController│───────>│ ControlActionState│
│                     │        │ enabled: False    │
│ current_recording:  │        │ blocking: ["frida"]│
│   AutomationRecording│       └──────────────────┘
│   (duration=1234.5s)│
│   (auto_stopped=False)
└─────────┬───────────┘
          │ add_interaction()
          v
┌─────────────────────┐
│ InteractionEvent    │
│ {type:"click",      │
│  x:540, y:960,      │
│  timestamp:"..."}   │
└─────────────────────┘
          │
          v (append to disk)
automation/recordings/20251004_143201_automation_recording_abc123.jsonl
```

---

## File Storage Schema

### Recording Files

**Location**: `automation/recordings/`

**Incremental File** (`.jsonl`):
```
{timestamp}_automation_recording_{uuid}.jsonl
```

Content: One JSON object per line (interaction event), appended during recording.

**Summary File** (`.json`):
```
{timestamp}_automation_recording_{uuid}.json
```

Content: Complete AutomationRecording.to_dict() output, written on recording stop.

### Example File Names

```
20251004_143201_automation_recording_fd0a69b0-8f92-422c-8fdf-a70347cbfe12.jsonl
20251004_143201_automation_recording_fd0a69b0-8f92-422c-8fdf-a70347cbfe12.json
```

---

## Migration Notes

### Changes to Existing Models

1. **ServiceStatus** (`automation/models/service_status.py`):
   - Add fields: `retry_count`, `max_retries`, `retry_delay`, `last_retry_at`
   - Add method: `should_retry() -> bool`
   - Backward compatible: new fields have defaults

2. **AutomationRecording** (`automation/models/recording.py`):
   - Add fields: `duration_limit_seconds`, `auto_stopped`, `incremental_file`
   - Add method: `_append_interaction_to_disk(interaction: dict)`
   - Backward compatible: new fields have defaults, existing JSON files still loadable

3. **ServiceManagerSnapshot** (`automation/models/service_status.py`):
   - Add fields: `retry_in_progress`
   - Backward compatible: UI can ignore new field if not displayed

No breaking changes to existing data files or serialization format.

---

## Conclusion

All entities defined with clear field types, validation rules, and relationships. Ready for contract definition and test generation.

