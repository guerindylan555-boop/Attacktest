# Data Model: Simplified Automation App Interface

## Overview
The redesigned Control Center coordinates three subsystems: automatic service lifecycle management, automation recording/replay, and token capture evidence. The data model focuses on making retry state observable, keeping UI actions gated until required services are ready, and persisting artefacts that satisfy the constitution's evidence requirements.

## Core Entities

### ServiceStatus
**Purpose**: Represents the live health of a single background service (emulator, proxy, frida) as reported by `ServiceManager`.

**Fields**:
- `name` (`str`): One of `emulator`, `proxy`, `frida`.
- `status` (`Literal['starting','running','stopped','error']`): Current lifecycle state.
- `retry_attempt` (`int`): Zero-based counter of automatic retry attempts currently in flight.
- `max_retries` (`int`): Configured retry ceiling (defaults to `3`).
- `startup_time` (`float`): Seconds between the most recent start command and confirmation.
- `pid` (`Optional[int]`): Process identifier if the service exposes one.
- `last_check` (`datetime` ISO-8601): Timestamp of the last health poll.
- `last_transition` (`datetime` ISO-8601): Timestamp when `status` most recently changed.
- `error_message` (`Optional[str]`): Exact stderr or structured message from the last failed attempt.
- `last_error_code` (`Optional[int]`): Exit status or sentinel code for automated diagnostics.

**Validation Rules**:
- `name` must be a known service identifier.
- `status` transitions must follow the state machine defined below.
- `retry_attempt` must be between `0` and `max_retries`.
- `error_message` required when `status == 'error'`.

**State Transitions**:
- `stopped → starting` when initialization begins.
- `starting → running` on healthy start.
- `starting → error` if the underlying command fails (increments `retry_attempt`).
- `error → starting` while `retry_attempt < max_retries`.
- `error → stopped` once retries are exhausted; UI surfaces message and requires manual intervention.
- `running → stopped` on shutdown.
- `running → error` when a running service crashes; retries behave the same as startup failures.

### ServiceManagerSnapshot
**Purpose**: Aggregate structure returned by `ServiceManager.get_service_status()` for UI consumption and button gating.

**Fields**:
- `services` (`List[ServiceStatus]`): Per-service state payloads.
- `all_ready` (`bool`): Derived flag indicating all required services report `running`.
- `initializing` (`bool`): True if at least one service is `starting`.
- `last_updated` (`datetime` ISO-8601): Timestamp matching the most recent poll.
- `blocking_errors` (`List[str]`): Collection of messages from services stuck in the `error` state with exhausted retries.

**Validation Rules**:
- `services` must contain exactly one record per managed service.
- `all_ready` must equal `all(service.status == 'running' for service in services)`.
- `blocking_errors` populated only when `retry_attempt >= max_retries` for any service.

### AutomationRecording
**Purpose**: Captures user interactions for replay with associated metadata and filesystem evidence.

**Fields**:
- `id` (`str` UUID): Unique recording identifier.
- `state` (`Literal['pending','recording','completed']`): Controller state for UI toggles.
- `timestamp` (`datetime` ISO-8601): Start time of the current or most recent session.
- `duration` (`float`): Seconds recorded after completion.
- `interactions` (`List[RecordingInteraction]`): Ordered actions captured during the session.
- `metadata` (`dict`): Additional context (app version, device info, operator id, etc.).
- `file_path` (`Path`): Location of the persisted JSON artefact under `automation/recordings/`.

**Validation Rules**:
- `id` must remain stable for the duration of the session.
- `duration` only set when `state == 'completed'`.
- `interactions` may be empty while `state == 'recording'`, but must be present before replay.

**Related Types**:
- `RecordingInteraction`: `{type: str, timestamp: datetime, payload: dict}` representing clicks, text entry, scrolls, or custom automation events.

### TokenCaptureSession
**Purpose**: Tracks the authentication automation flow used to capture tokens and generate evidence.

**Fields**:
- `session_id` (`str` UUID): Unique session identifier.
- `status` (`Literal['pending','running','completed','failed']`): Lifecycle state.
- `start_time` / `end_time` (`datetime` ISO-8601): Timestamps marking session bounds.
- `captured_tokens` (`List[str]`): Tokens extracted by the capture script.
- `user_credentials` (`dict`): Credential material or references applied to the automation.
- `capture_log` (`List[CaptureEvent]`): Structured events for auditability.
- `evidence_files` (`List[Path]`): Paths to generated `CAPTURED_TOKEN_*.json` and `.txt` artefacts.
- `failure_reason` (`Optional[str]`): Populated when `status == 'failed'`.

**Validation Rules**:
- `status` transitions must follow the defined state machine.
- `captured_tokens` must be non-empty when `status == 'completed'`.
- `evidence_files` must exist on disk before the session is marked `completed`.

**Related Types**:
- `CaptureEvent`: `{timestamp: datetime, event_type: str, message: str, extra: dict}` used to store automation milestones, retries, and token summaries.

### ControlActionState
**Purpose**: Maintains UI-level readiness for each primary action button so the view layer can render disabled states with explanations.

**Fields**:
- `action` (`Literal['record','replay','capture_token']`).
- `enabled` (`bool`): Whether the button is interactive.
- `disabled_reason` (`Optional[str]`): Human-readable explanation shown in tooltips/logs.
- `requires_services` (`Set[str]`): Subset of services that must be `running` before enabling.
- `last_started_at` (`Optional[datetime]`): Timestamp of the most recent activation.
- `in_progress` (`bool`): Marks asynchronous operations that should block duplicate clicks.

**Validation Rules**:
- `requires_services` must be non-empty for actions that depend on background services.
- `enabled` must be `False` while any `requires_services` member is not running.
- `in_progress` implies `enabled == False`.

### EvidenceArtifact
**Purpose**: Unifies metadata about files emitted during automation runs for downstream reporting.

**Fields**:
- `path` (`Path`): Absolute filesystem location.
- `artifact_type` (`Literal['recording','token_json','token_text','log']`).
- `related_id` (`str`): `AutomationRecording.id` or `TokenCaptureSession.session_id` that produced the file.
- `created_at` (`datetime` ISO-8601): File creation timestamp.
- `hash` (`Optional[str]`): Integrity checksum recorded post-generation.

**Validation Rules**:
- `hash` required for externally shared artefacts.
- `artifact_type` must align with directory conventions (`automation/recordings/`, `automation/sessions/`, project root token files).

## Relationships

- **ServiceStatus ↔ ServiceManagerSnapshot**: Each snapshot aggregates exactly one `ServiceStatus` per managed service; `all_ready` derives from the collection.
- **ServiceStatus ↔ ControlActionState**: Buttons watch `requires_services`; if any required `ServiceStatus.status != 'running'`, the matching `ControlActionState.enabled` is forced to `False` and `disabled_reason` reflects either "initializing" or the exact `error_message`.
- **AutomationRecording ↔ ServiceStatus**: A recording can transition from `pending` to `recording` only when the snapshot reports `all_ready`.
- **TokenCaptureSession ↔ ServiceStatus**: Capture sessions require both `emulator` and `frida` statuses `running`; proxy errors are logged but do not block initiation if retries are still in flight.
- **AutomationRecording ↔ EvidenceArtifact**: Each completed recording produces at least one JSON artefact; additional references can be captured as `artifact_type == 'log'`.
- **TokenCaptureSession ↔ EvidenceArtifact**: Each completed session must register both a JSON and text token file under the session ID.

## Persistence and Storage

- `AutomationRecording` instances persist to JSON under `automation/recordings/` using the pattern `{timestamp}_automation_recording_{id}.json`.
- `TokenCaptureSession` instances persist to JSON under `automation/sessions/` using `{timestamp}_token_capture_{session_id}.json` and emit supplementary evidence files in the project root.
- `ServiceStatus`, `ServiceManagerSnapshot`, and `ControlActionState` remain in memory but are serializable to JSON for telemetry/testing snapshots.
- `EvidenceArtifact` metadata is appended to a rolling in-memory catalog for the session; optional persistence (CSV/JSON) can be added for audit exports.

## Derived Data and Invariants

- `ServiceManagerSnapshot.all_ready` implies every `ControlActionState` with matching dependencies can flip `enabled=True`, provided no action-specific `in_progress` guard is set.
- When a service exceeds `max_retries`, its `ServiceStatus.status` stays `error` and the UI must surface `ServiceStatus.error_message` verbatim while logging the exhausted state.
- Replay actions must confirm a non-empty set of persisted `AutomationRecording` artefacts before enabling `ControlActionState['replay']`.
- Token capture completion requires at least one token string plus both evidence files before `status` becomes `completed`.
- Shutdown should reset all `ControlActionState.in_progress` flags and persist any pending `EvidenceArtifact` records before stopping services.
