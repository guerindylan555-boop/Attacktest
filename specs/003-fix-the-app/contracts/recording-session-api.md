# AutomationRecording Session API Contract

**Component**: `automation.models.recording.AutomationRecording`  
**Purpose**: Manage recording session state with incremental persistence and duration limits

## Class Interface

### Constructor

```python
def __init__(
    self,
    recording_id: Optional[str] = None,
    duration_limit_seconds: int = 1800
):
    """
    Initialize a new recording session.
    
    Args:
        recording_id: Unique identifier (UUID). If None, generates new UUID.
        duration_limit_seconds: Maximum recording duration in seconds (default 30 min).
    """
```

---

## Methods

### `start_recording() -> dict`

**Description**: Start the recording session and initialize incremental file.

**Preconditions**:
- Recording must be in `pending` state
- Must not be called twice without `stop_recording()` in between

**Behavior**:
1. Set `_start_time = now()`
2. Set `_is_recording = True`
3. Set `state = "recording"`
4. Update `timestamp` and `metadata["recording_start_time"]`
5. Create incremental JSONL file at `automation/recordings/{timestamp}_{id}.jsonl`

**Returns**:
```python
{
    "status": "success",
    "recording_id": "fd0a69b0-8f92-422c-8fdf-a70347cbfe12",
    "start_time": "2025-10-04T14:32:01.234Z"
}
```

**Raises**:
- `ValueError` if already recording

---

### `stop_recording() -> dict`

**Description**: Stop the recording session and calculate final duration.

**Preconditions**:
- Recording must be active (`_is_recording == True`)

**Behavior**:
1. Calculate `duration = now() - _start_time`
2. Set `_is_recording = False`
3. Set `state = "completed"`
4. Update `metadata["recording_end_time"]` and `metadata["last_updated"]`
5. Close incremental file (if open)

**Returns**:
```python
{
    "status": "success",
    "recording_id": "fd0a69b0-...",
    "duration": 1234.5,
    "interactions_count": 456
}
```

**Raises**:
- `ValueError` if not currently recording

---

### `add_interaction(interaction_type: str, **kwargs) -> None`

**Description**: Add a user interaction to the recording (in-memory only; caller handles disk).

**Parameters**:
- `interaction_type`: `"click"`, `"type"`, or `"scroll"`
- `**kwargs`: Type-specific data

**Preconditions**:
- Recording must be active

**Behavior**:
1. Validate recording is active
2. Create interaction dict with timestamp
3. Append to `self.interactions` list

**Raises**:
- `ValueError` if recording not active

**Note**: Disk persistence is handled by caller (AutomationController) to avoid coupling model to file I/O.

---

### `append_interaction_to_disk(interaction: dict, file_path: Path) -> None`

**Description**: Append interaction to incremental JSONL file (static method for testability).

**Parameters**:
- `interaction`: Interaction dict to append
- `file_path`: Path to `.jsonl` file

**Behavior**:
1. Open file in append mode
2. Write `json.dumps(interaction) + '\n'`
3. Flush to ensure data is written

**Error Handling**:
- If write fails: raise IOError (caller should mark recording as failed)

---

### `mark_failed(message: str) -> dict`

**Description**: Mark the recording as failed and capture error for diagnostics.

**Parameters**:
- `message`: Error message describing failure

**Behavior**:
1. Set `_is_recording = False`
2. Set `state = "failed"`
3. Set `last_error = message`
4. Update `metadata["last_error"]` and `metadata["last_updated"]`

**Returns**:
```python
{
    "status": "error",
    "recording_id": "fd0a69b0-...",
    "error": message,
    "reason": "recording_failed"
}
```

---

### `save_to_file(recordings_dir: Path = None) -> Path`

**Description**: Save recording to JSON summary file (final persistence).

**Parameters**:
- `recordings_dir`: Directory to save file (default: `automation/recordings/`)

**Behavior**:
1. Create filename: `{timestamp}_automation_recording_{id}.json`
2. Write `self.to_dict()` as formatted JSON
3. Set `self.file_path = output_path`
4. Update `metadata["file_path"]` and `metadata["last_updated"]`

**Returns**: Path to saved file

**File Format**:
```json
{
  "id": "fd0a69b0-8f92-422c-8fdf-a70347cbfe12",
  "timestamp": "2025-10-04T14:32:01.234Z",
  "duration": 1234.5,
  "duration_limit_seconds": 1800,
  "auto_stopped": false,
  "interactions": [
    {"type": "click", "x": 540, "y": 960, "timestamp": "2025-10-04T14:32:02.123Z"},
    {"type": "type", "text": "hello", "timestamp": "2025-10-04T14:32:05.456Z"}
  ],
  "metadata": {
    "app_version": "1.0.0",
    "device_info": "emulator-5554",
    "recording_start_time": "2025-10-04T14:32:01.234Z",
    "recording_end_time": "2025-10-04T14:52:35.789Z",
    "last_updated": "2025-10-04T14:52:35.789Z",
    "file_path": "/path/to/file.json"
  },
  "state": "completed"
}
```

---

### `to_dict() -> dict`

**Description**: Convert recording to dictionary for serialization.

**Returns**: Complete recording state as dict (schema shown above in `save_to_file`)

---

### `validate() -> bool`

**Description**: Validate recording data integrity.

**Checks**:
- Required fields present (`id`, `timestamp`)
- Timestamp is valid ISO 8601 format
- Duration is non-negative
- Duration <= `duration_limit_seconds` (if `auto_stopped == True`)
- Interactions list is valid (each has `type` and `timestamp`)

**Returns**: `True` if valid, `False` otherwise

---

### `@classmethod load_from_file(cls, file_path: Path) -> AutomationRecording`

**Description**: Load recording from JSON summary file.

**Parameters**:
- `file_path`: Path to `.json` file

**Returns**: `AutomationRecording` instance populated from file

**Error Handling**:
- If file not found: raise `FileNotFoundError`
- If JSON invalid: raise `json.JSONDecodeError`

---

### `@classmethod list_recordings(cls, recordings_dir: Path = None) -> List[Path]`

**Description**: List all available recording files in directory.

**Parameters**:
- `recordings_dir`: Directory to search (default: `automation/recordings/`)

**Returns**: List of Path objects for `.json` files matching pattern `*_automation_recording_*.json`

**Performance**: <100ms for directory with 100 recordings

---

## New Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `duration_limit_seconds` | `int` | `1800` | Maximum recording duration (30 minutes) |
| `auto_stopped` | `bool` | `False` | True if recording was auto-stopped due to duration limit |
| `incremental_file` | `Path \| None` | `None` | Path to `.jsonl` file for live persistence |

---

## State Machine

```
pending → recording → completed
                   → failed (error during recording)
                   
auto_stopped flag set during recording→completed transition if duration >= limit
```

---

## File Persistence Strategy

### During Recording (Incremental)

**File**: `{timestamp}_automation_recording_{id}.jsonl`  
**Format**: JSON Lines (one interaction per line)  
**Purpose**: Prevent data loss if app crashes

```
{"type":"click","x":540,"y":960,"timestamp":"2025-10-04T14:32:02.123Z"}
{"type":"type","text":"hello","timestamp":"2025-10-04T14:32:05.456Z"}
{"type":"scroll","direction":"down","amount":300,"timestamp":"2025-10-04T14:32:08.789Z"}
```

### After Recording (Summary)

**File**: `{timestamp}_automation_recording_{id}.json`  
**Format**: Complete JSON document  
**Purpose**: Human-readable summary with metadata

---

## Backward Compatibility

### Loading Old Recordings

Old recordings (without `duration_limit_seconds`, `auto_stopped`, `incremental_file`) can still be loaded:

```python
# Old format (missing new fields)
old_recording = {
    "id": "...",
    "timestamp": "...",
    "duration": 123.4,
    "interactions": [...],
    "metadata": {...},
    "state": "completed"
}

# Load succeeds with defaults
recording = AutomationRecording.load_from_file("old_recording.json")
assert recording.duration_limit_seconds == 1800  # default
assert recording.auto_stopped == False  # default
assert recording.incremental_file is None  # default
```

---

## Testing Contract

Tests MUST verify:
1. ✅ `start_recording()` creates incremental file
2. ✅ `stop_recording()` calculates correct duration
3. ✅ `add_interaction()` fails if recording not active
4. ✅ `append_interaction_to_disk()` writes valid JSON Lines
5. ✅ `save_to_file()` creates valid JSON summary
6. ✅ `validate()` detects invalid recordings
7. ✅ `load_from_file()` handles old format (backward compatibility)
8. ✅ `auto_stopped` flag set correctly when duration >= limit
9. ✅ `mark_failed()` preserves partial interaction data

