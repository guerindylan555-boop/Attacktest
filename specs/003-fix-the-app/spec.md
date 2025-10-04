# Feature Specification: Control Center Automatic Startup & Recording Reliability

**Feature Branch**: `003-fix-the-app`  
**Created**: 2025-10-04  
**Status**: Draft  
**Input**: User description: "fix the app so everything run properly when runing ./run_control_center.sh everything need should start automaticly launch the app lauchn frida and spwan mayndrive properly. Make sure the record automation is functilal work properly and that i can interact with androind and when. record"

## Execution Flow (main)
```
1. Parse user description from Input
   → Feature identified: Fix Control Center startup and recording automation
2. Extract key concepts from description
   → Actors: Security researcher
   → Actions: Launch Control Center, start services, record interactions, interact with Android
   → Data: Service status, recordings, interaction events
   → Constraints: Must start automatically, must be reliable
3. For each unclear aspect:
   → [RESOLVED] Service startup sequence clarified
   → [RESOLVED] Recording interaction types defined
4. Fill User Scenarios & Testing section
   → Clear user flow: Launch → Services start → Record → Interact → Stop
5. Generate Functional Requirements
   → Each requirement is testable
6. Identify Key Entities
   → Services, Recordings, Interactions
7. Run Review Checklist
   → No [NEEDS CLARIFICATION] markers
   → No implementation details exposed
8. Return: SUCCESS (spec ready for planning)
```

---

## ⚡ Quick Guidelines
- ✅ Focus on WHAT users need and WHY
- ❌ Avoid HOW to implement (no tech stack, APIs, code structure)
- 👥 Written for business stakeholders, not developers

---

## Clarifications

### Session 2025-10-04
- Q: Service Retry Policy - When a service fails to start during automatic initialization, how should the system handle retries? → A: 3 automatic retries with 5-second delays, then require manual retry
- Q: Screen Preview Refresh Rate - How frequently should the Android device screen preview update during recording? → A: 10 Hz (every 100ms) - fairly smooth with moderate resource usage
- Q: Recording Data Persistence - When should recordings be persisted to disk during an active recording session? → A: Continuous append to file after each interaction - safest but more I/O
- Q: Interaction Capture Behavior - What should happen when a user clicks the Android screen preview while recording is NOT active? → A: Block interaction completely - no relay to device, show error message
- Q: Recording Duration Limits - Should there be a maximum duration or size limit for a single recording session? → A: 30 minutes maximum - auto-stop with warning at limit

---

## User Scenarios & Testing *(mandatory)*

### Primary User Story
As a security researcher, when I launch the Control Center application, I need all required services (emulator, network proxy, dynamic analysis hooks) to start automatically without manual intervention, so I can immediately begin recording security test automation workflows that capture my interactions with the Android application under test.

### Current Problem
Currently, the Control Center displays a warning "Some services failed to start automatically" which prevents the researcher from immediately recording or interacting with the Android application. Services may fail to initialize in the correct order or may encounter timeout issues, requiring manual troubleshooting and service restarts.

### Acceptance Scenarios

1. **Given** the Control Center is not running and all services are stopped, **When** the researcher executes the startup script, **Then** the Control Center launches, displays "Automatic Service Initialization" message, starts the emulator, network proxy, and dynamic analysis hook service, launches the target Android application automatically, and displays all service indicators as "ready/running" within 90 seconds.

2. **Given** the Control Center is running with all services ready, **When** the researcher clicks "Start Recording", **Then** a new recording session begins with a unique session ID, the recording indicator shows "Recording in progress", and all Android interactions (taps, text input, scrolls) are captured with timestamps.

3. **Given** a recording session is active, **When** the researcher performs touch interactions on the Android device screen preview, **Then** each interaction (tap coordinates, text entered, scroll gestures) is logged to the recording with accurate coordinates and timing information.

4. **Given** a recording session is active with captured interactions, **When** the researcher clicks "Stop Recording", **Then** the recording is saved to persistent storage with all interaction data, metadata (duration, timestamp, device info), and a summary showing the total number of interactions captured.

5. **Given** the Control Center starts but one or more services fail, **When** the automatic startup completes, **Then** the UI clearly indicates which specific service failed, displays the error reason in the log panel, and provides a manual retry button for each failed service without requiring application restart.

6. **Given** services are starting automatically, **When** the emulator takes longer than expected to boot, **Then** the startup process waits appropriately (up to 90 seconds) without timing out prematurely, displays progress indicators, and only reports failure if the service genuinely cannot start.

7. **Given** a recording session has been active for 30 minutes, **When** the maximum duration is reached, **Then** the system automatically stops the recording, saves all captured data, and displays a warning message indicating the duration limit was reached.

### Edge Cases
- What happens when the emulator is already running before Control Center starts? (System should detect and attach rather than fail)
- How does the system handle recording when the Android application crashes mid-recording? (All interactions up to crash point are already persisted; recording should be marked as incomplete with crash timestamp)
- What happens if network proxy port is already in use? (Clear error message with port conflict details)
- How does the system respond when dynamic analysis hook script is missing? (Specific error indicating missing file path)
- What happens when user clicks Android screen while recording is not active? (Interaction is blocked completely with error message "Recording must be started first"; no relay to device)

## Requirements *(mandatory)*

### Functional Requirements

#### Service Initialization & Lifecycle
- **FR-001**: System MUST automatically start the emulator, network proxy, and dynamic analysis hook service when the Control Center launches via the startup script
- **FR-002**: System MUST start services in the correct dependency order (emulator first, then proxy and hooks)
- **FR-003**: System MUST wait up to 90 seconds for emulator boot completion before marking startup as failed
- **FR-004**: System MUST automatically launch the target Android application once the emulator and hook service are ready
- **FR-005**: System MUST display real-time status indicators for each service (emulator, proxy, hooks) showing pending/running/failed/stopped states
- **FR-006**: System MUST log all service startup attempts with timestamps, success/failure status, and error details to the UI log panel
- **FR-007**: System MUST automatically retry failed services up to 3 times with 5-second delays between attempts before requiring manual intervention
- **FR-008**: System MUST allow manual retry of failed services without restarting the entire Control Center application
- **FR-009**: System MUST detect when services are already running and attach to them rather than failing or attempting duplicate starts

#### Recording Automation
- **FR-010**: System MUST allow the researcher to start a new recording session that generates a unique session identifier
- **FR-011**: System MUST capture touch/tap interactions with screen coordinates (x, y) and timestamps
- **FR-012**: System MUST capture text input interactions with the entered text content and timestamps
- **FR-013**: System MUST capture scroll gestures with direction, distance, and timestamps
- **FR-014**: System MUST display recording status (idle, recording, stopped) clearly in the UI
- **FR-015**: System MUST allow the researcher to stop an active recording session at any time
- **FR-016**: System MUST incrementally persist each captured interaction to disk immediately after capture to prevent data loss
- **FR-016a**: System MUST save completed recordings to persistent storage in structured format (JSON) with all interaction data and metadata
- **FR-017**: System MUST calculate and store recording duration (total time from start to stop)
- **FR-017a**: System MUST enforce a maximum recording duration of 30 minutes and automatically stop recording when limit is reached
- **FR-017b**: System MUST display a warning message when recording is auto-stopped due to duration limit
- **FR-018**: System MUST prevent recording from starting if required services (emulator, hooks) are not in ready state
- **FR-019**: System MUST handle recording failures gracefully by saving partial recording data and marking the recording state as failed

#### Android Interaction During Recording
- **FR-020**: System MUST display a periodically-refreshed screen preview of the Android device at 10 Hz (100ms intervals)
- **FR-021**: System MUST allow the researcher to interact with the Android device via the screen preview (tap, type, scroll) only when recording is active
- **FR-021a**: System MUST block all screen preview interactions when recording is not active and display error message "Recording must be started first"
- **FR-022**: System MUST relay touch interactions from the screen preview to the actual Android device in real-time
- **FR-023**: System MUST ensure interaction coordinates are accurately mapped between preview display and actual device screen dimensions
- **FR-024**: System MUST provide visual feedback when interactions are successfully captured during recording

#### Error Handling & Diagnostics
- **FR-025**: System MUST display specific error messages when services fail to start (not generic "failed" status)
- **FR-026**: System MUST indicate which service dependency caused a failure (e.g., "Frida failed because emulator is not ready")
- **FR-027**: System MUST surface relevant diagnostic information (process IDs, log file paths, port numbers) in error messages
- **FR-028**: System MUST preserve service logs even when services fail, allowing post-mortem troubleshooting

### Key Entities *(include if feature involves data)*

- **Service**: Represents a managed background service (emulator, proxy, dynamic analysis hook). Has states: pending, starting, running, failed, stopped. Contains metadata: process ID, log file path, retry count, error messages.

- **Recording Session**: Represents a single automation recording workflow. Contains: unique session ID, start timestamp, end timestamp, duration, state (recording, completed, failed), list of interactions, metadata (device info, app version, file path).

- **Interaction Event**: Represents a single user interaction captured during recording. Contains: event type (click, type, scroll), timestamp, type-specific data (coordinates for click, text for input, direction/distance for scroll).

- **Service Status Snapshot**: Represents the current state of all managed services at a point in time. Contains: per-service status, overall readiness indicator (all services ready/not ready), retry attempts, last error per service.

---

## Review & Acceptance Checklist
*GATE: Automated checks run during main() execution*

### Content Quality
- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

### Requirement Completeness
- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous  
- [x] Success criteria are measurable
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

---

## Execution Status
*Updated by main() during processing*

- [x] User description parsed
- [x] Key concepts extracted
- [x] Ambiguities marked
- [x] User scenarios defined
- [x] Requirements generated
- [x] Entities identified
- [x] Review checklist passed

---
