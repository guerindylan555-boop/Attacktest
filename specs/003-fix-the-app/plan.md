# Implementation Plan: Control Center Automatic Startup & Recording Reliability

**Branch**: `003-fix-the-app` | **Date**: 2025-10-04 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/home/ubuntu/Desktop/Project/Attacktest/specs/003-fix-the-app/spec.md`

## Execution Flow (/plan command scope)
```
1. Load feature spec from Input path ✓
   → Feature spec loaded successfully
2. Fill Technical Context ✓
   → Python 3.10, PySide6, subprocess, adb tools detected
   → Single project structure identified
3. Fill Constitution Check section ✓
   → All principles verified for compliance
4. Evaluate Constitution Check section ✓
   → No violations detected
   → Progress Tracking: Initial Constitution Check PASS
5. Execute Phase 0 → research.md ✓
   → Service reliability patterns researched
6. Execute Phase 1 → contracts, data-model.md, quickstart.md ✓
   → Data model extracted from entities
   → Internal contracts defined
   → Quickstart scenarios created
7. Re-evaluate Constitution Check section ✓
   → No new violations introduced
   → Progress Tracking: Post-Design Constitution Check PASS
8. Plan Phase 2 → Describe task generation approach ✓
9. STOP - Ready for /tasks command ✓
```

**IMPORTANT**: The /plan command STOPS at step 9. Phases 2-4 are executed by other commands:
- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary

Fix Control Center reliability issues to ensure automatic service startup, proper Frida attachment, and functional recording automation. The primary requirement is reliable initialization of emulator, proxy, and Frida services with automatic retry logic (3 attempts, 5-second delays), followed by robust recording functionality that captures Android interactions with incremental persistence and 30-minute duration limits. The technical approach focuses on improving service orchestration timing, implementing proper state management with retry awareness, and adding recording session management with continuous disk writes to prevent data loss.

## Technical Context

**Language/Version**: Python 3.10 (Ubuntu 22.04 default interpreter)  
**Primary Dependencies**: PySide6 (Qt GUI), frida-tools, mitmproxy, subprocess, threading, QProcess  
**Storage**: Local JSON files in `automation/recordings/` and `automation/sessions/`, no database required  
**Testing**: pytest for unit/integration tests, manual testing via quickstart.md scenarios  
**Target Platform**: Linux (Ubuntu 22.04+), requires X11 or Wayland display for Qt GUI, Android emulator access via ADB  
**Project Type**: single - Desktop automation application with service orchestration  
**Performance Goals**: 
- Service startup within 90 seconds total (emulator boot dominant factor)
- Screen preview refresh at 10 Hz (100ms intervals)
- Recording persistence latency <50ms per interaction
- UI responsiveness maintained during service operations (non-blocking)  
**Constraints**:
- Must work with existing emulator/proxy/Frida infrastructure
- No changes to hook scripts (automation/hooks/general.js)
- Must preserve existing ServiceStatus, AutomationRecording models
- Recording file format must remain JSON for backward compatibility  
**Scale/Scope**:
- 3 managed services (emulator, proxy, Frida)
- Up to 30-minute recording sessions
- ~1800 max interactions per session at 1/second rate
- Single-user desktop application (no concurrency requirements)

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I: Security-First Testing
**Status**: ✅ PASS  
This feature enhances the automation infrastructure that enables security testing. Recording Android interactions provides evidence for security test reproduction. Service reliability ensures consistent test environment setup.

### Principle II: Automation-Driven Discovery
**Status**: ✅ PASS  
Fixes directly support automation goals: automatic service startup reduces manual setup, reliable recording captures test workflows for replay, improving test repeatability.

### Principle III: Evidence-Based Reporting
**Status**: ✅ PASS  
Recording functionality captures concrete evidence (interaction timestamps, coordinates, text) in structured JSON format with ISO timestamps. Incremental persistence prevents evidence loss.

### Principle IV: Multi-Vector Analysis
**Status**: ✅ PASS (Indirect)  
Control Center orchestrates tools for multi-vector testing (Frida for runtime analysis, mitmproxy for network traffic, emulator for application testing). This feature ensures those vectors are available and reliable.

### Principle V: Reproducible Test Environment
**Status**: ✅ PASS  
Automatic service startup and service health detection ensure consistent test environment initialization. Recording/replay enables reproducible test execution.

### Principle VI: Code & Artifact Hygiene
**Status**: ✅ PASS  
Implementation will improve existing code (fix bugs, add retry logic, enhance error reporting) without introducing duplicate workflows. Obsolete backup file `control_center.py.backup` should be removed during implementation.

**Gate Decision**: ✅ PROCEED - All principles satisfied, no violations.

## Project Structure

### Documentation (this feature)
```
specs/003-fix-the-app/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
│   ├── service-manager-api.md
│   ├── automation-controller-api.md
│   └── recording-session-api.md
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
automation/
├── models/              # Existing data models (extend for retry logic)
│   ├── service_status.py        # Add retry_count, last_retry_at fields
│   ├── recording.py             # Add duration_limit, auto_stopped fields
│   ├── control_action.py        # Existing, no changes
│   └── token_session.py         # Existing, no changes
├── services/            # Service orchestration (fix timing and retry)
│   ├── service_manager.py       # Fix: retry logic, attach detection, timing
│   ├── automation_controller.py # Fix: recording state machine, interaction blocking
│   └── token_controller.py      # Existing, minimal changes
├── scripts/             # Helper scripts (improve app launch reliability)
│   ├── run_hooks.py             # Fix: Frida spawn vs attach mode
│   └── run_appium_token_flow.py # Existing, no changes
├── ui/                  # Qt GUI (fix screen refresh rate, interaction handling)
│   ├── control_center.py        # Fix: auto-start trigger, screen refresh timer
│   └── qt_workers.py            # Fix: screen capture frequency
└── hooks/               # Frida hooks (no changes for this feature)
    └── general.js

tests/                   # Test suite
├── integration/         # New integration tests
│   ├── test_service_startup_reliability.py
│   ├── test_service_retry_logic.py
│   ├── test_recording_persistence.py
│   └── test_recording_duration_limits.py
└── unit/                # New unit tests
    ├── test_service_status_retry.py
    └── test_recording_auto_stop.py
```

**Structure Decision**: Single project structure with automation/ as primary codebase. Tests are organized by type (integration for service orchestration testing, unit for model logic). No backend/frontend split needed as this is a desktop application with embedded services.

## Phase 0: Outline & Research

**Output**: See [research.md](./research.md)

### Research Summary

1. **Service Startup Reliability** → Threading + health checks + retry backoff
2. **Frida Attach vs Spawn** → Attach mode with app pre-launch for stability
3. **Recording Incremental Persistence** → Append-only JSON lines with atomic writes
4. **Screen Refresh Performance** → QTimer at 100ms with background QThread capture
5. **Service State Management** → Retry-aware state machine with exponential backoff

All technical unknowns resolved. No NEEDS CLARIFICATION remain.

## Phase 1: Design & Contracts

*Prerequisites: research.md complete* ✓

**Outputs**: 
- [data-model.md](./data-model.md) - Entity definitions with retry/persistence fields
- [contracts/](./contracts/) - Internal API contracts for services
- [quickstart.md](./quickstart.md) - Manual test scenarios

### Design Summary

1. **ServiceStatus Model**: Add `retry_count`, `last_retry_at`, `max_retries=3`, `retry_delay=5.0` fields
2. **AutomationRecording Model**: Add `duration_limit_seconds=1800`, `auto_stopped=False`, `incremental_file` fields
3. **ServiceManager**: Implement `_retry_service()` method with exponential backoff, `_detect_running_services()` for attach logic
4. **AutomationController**: Add `_enforce_duration_limit()` timer, `_block_interactions_when_idle()` guard
5. **ScreenCaptureWorker**: Change refresh interval from 500ms to 100ms (10 Hz)

All contracts defined. Tests written (will fail until implementation).

## Phase 2: Task Planning Approach
*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:
- Load contracts from Phase 1 design docs
- ServiceStatus model changes → model update task [P]
- AutomationRecording model changes → model update task [P]
- ServiceManager retry logic → service layer task
- AutomationController duration enforcement → controller task
- ScreenCaptureWorker refresh rate → UI worker task
- Each contract → integration test task [P]
- Manual quickstart scenarios → validation task

**Ordering Strategy**:
- TDD order: Integration tests before implementation (tests will fail initially)
- Dependency order: Models first → Services → UI
- Mark [P] for parallel execution (different files):
  - Model updates can run parallel
  - Service fixes sequential (shared ServiceManager state)
  - Integration tests parallel (isolated test environments)

**Estimated Output**: 18-22 numbered, ordered tasks in tasks.md

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

## Phase 3+: Future Implementation
*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)  
**Phase 4**: Implementation (execute tasks.md following constitutional principles)  
**Phase 5**: Validation (run tests, execute quickstart.md, performance validation)

## Complexity Tracking
*Fill ONLY if Constitution Check has violations that must be justified*

No complexity violations detected. Standard Python/Qt desktop application with straightforward service orchestration improvements.

## Progress Tracking
*This checklist is updated during execution flow*

**Phase Status**:
- [x] Phase 0: Research complete (/plan command)
- [x] Phase 1: Design complete (/plan command)
- [x] Phase 2: Task planning complete (/plan command - describe approach only)
- [ ] Phase 3: Tasks generated (/tasks command)
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: PASS
- [x] Post-Design Constitution Check: PASS
- [x] All NEEDS CLARIFICATION resolved
- [x] Complexity deviations documented (N/A - no deviations)

---
*Based on Constitution v1.1.0 - See `.specify/memory/constitution.md`*
