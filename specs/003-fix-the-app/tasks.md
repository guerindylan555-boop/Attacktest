# Tasks: Control Center Automatic Startup & Recording Reliability

**Input**: Design documents from `/home/ubuntu/Desktop/Project/Attacktest/specs/003-fix-the-app/`
**Prerequisites**: plan.md, research.md, data-model.md, contracts/, quickstart.md

## Execution Flow (main)
```
1. Load plan.md from feature directory ✓
   → Tech stack: Python 3.10, PySide6, frida-tools, mitmproxy
   → Structure: Single project, automation/ directory
2. Load design documents ✓
   → data-model.md: 4 entities (ServiceStatus, AutomationRecording, etc.)
   → contracts/: 3 API contracts
   → quickstart.md: 8 test scenarios
3. Generate tasks by category ✓
   → Setup: 3 tasks (dependencies, linting, test structure)
   → Tests: 9 tasks (contract + integration tests) [P]
   → Core: 7 tasks (models + services + UI)
   → Polish: 3 tasks (unit tests, cleanup)
4. Apply task rules ✓
   → Different files = [P] for parallel
   → Same file = sequential (no [P])
   → Tests before implementation (TDD)
5. Number tasks sequentially ✓
6. Generate dependency graph ✓
7. Create parallel execution examples ✓
8. Validate task completeness ✓
9. Return: SUCCESS (tasks ready for execution) ✓
```

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Include exact file paths in descriptions

## Path Conventions
- **Single project**: `automation/`, `tests/` at repository root
- All paths relative to `/home/ubuntu/Desktop/Project/Attacktest/`

---

## Phase 3.1: Setup

- [x] **T001** Add PySide6 to requirements.txt (currently missing, needed for Qt GUI)
- [x] **T002** Create test directory structure: `tests/integration/` and `tests/unit/`
- [x] **T003** [P] Configure pytest for integration tests in pytest.ini (add markers for slow tests)

---

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3

**CRITICAL: These tests MUST be written and MUST FAIL before ANY implementation**

### Contract Tests (Parallel - Different Files)

- [x] **T004** [P] Contract test ServiceManager.start_all_services() in `tests/integration/test_service_manager_contract.py`
  - Verify retry logic triggers (3 attempts, 5s delays)
  - Verify dependency order (emulator → proxy → frida)
  - Verify attach detection for running services
  - Verify ServiceManagerSnapshot aggregation

- [x] **T005** [P] Contract test AutomationController.start_recording() in `tests/integration/test_automation_controller_contract.py`
  - Verify service readiness check before start
  - Verify incremental file creation
  - Verify duration timer activation
  - Verify interaction gating (block when not recording)

- [x] **T006** [P] Contract test AutomationRecording session lifecycle in `tests/integration/test_recording_session_contract.py`
  - Verify start_recording() initializes state
  - Verify stop_recording() calculates duration
  - Verify incremental persistence to JSONL
  - Verify auto-stop at 30-minute limit

### Integration Tests (Parallel - Different Files)

- [x] **T007** [P] Integration test service startup reliability in `tests/integration/test_service_startup_reliability.py`
  - Scenario 1: Clean startup (all services auto-start)
  - Scenario 8: Service order verification (emulator first)
  - Verify 90-second timeout enforcement

- [x] **T008** [P] Integration test service retry logic in `tests/integration/test_service_retry_logic.py`
  - Scenario 2: Attach detection (emulator already running)
  - Scenario 2: Port conflict retry (3 attempts with delays)
  - Scenario 2: Manual retry after failure

- [x] **T009** [P] Integration test recording persistence in `tests/integration/test_recording_persistence.py`
  - Scenario 3: Basic recording workflow (start, interact, stop)
  - Scenario 3: Incremental JSONL append after each interaction
  - Verify crash recovery (partial JSONL data preserved)

- [x] **T010** [P] Integration test recording duration limits in `tests/integration/test_recording_duration_limits.py`
  - Scenario 4: Auto-stop at 30 minutes
  - Scenario 4: Warning message display
  - Verify auto_stopped flag in JSON output

- [x] **T011** [P] Integration test interaction blocking in `tests/integration/test_interaction_blocking.py`
  - Scenario 5: Block interactions when recording inactive
  - Scenario 5: Error message "Recording must be started first"
  - Verify no ADB relay when blocked

- [x] **T012** [P] Integration test screen refresh rate in `tests/integration/test_screen_refresh_rate.py`
  - Scenario 6: Verify 10 Hz (100ms intervals)
  - Measure actual refresh timing with QTimer
  - Verify ADB screencap latency <100ms

---

## Phase 3.3: Core Implementation (ONLY after tests are failing)

### Model Updates (Parallel - Different Files)

- [x] **T013** [P] Add retry fields to ServiceStatus in `automation/models/service_status.py`
  - Fields: retry_count, max_retries=3, retry_delay=5.0, last_retry_at
  - Method: should_retry() -> bool
  - Method: begin_retry_attempt()
  - Update __init__ with new field defaults
  - Maintain backward compatibility (defaults for missing fields)

- [x] **T014** [P] Add duration limit fields to AutomationRecording in `automation/models/recording.py`
  - Fields: duration_limit_seconds=1800, auto_stopped=False, incremental_file
  - Method: append_interaction_to_disk(interaction, file_path)
  - Update start_recording() to create incremental JSONL file
  - Update stop_recording() to check duration vs limit
  - Maintain backward compatibility (load old recordings without new fields)

### Service Layer Updates (Sequential - Shared State)

- [x] **T015** Implement retry logic in ServiceManager._start_service() in `automation/services/service_manager.py`
  - Wrap service start in retry loop (up to max_retries)
  - Add 5-second sleep between retries via time.sleep(retry_delay)
  - Update ServiceStatus.retry_count and last_retry_at on each attempt
  - Log each retry attempt with "[INFO] Retry {count}/{max}" message

- [x] **T016** Implement attach detection in ServiceManager._detect_running_services() in `automation/services/service_manager.py`
  - Check emulator: parse `adb devices` output for emulator-*
  - Check proxy: use `subprocess` to check port 8080 listening (netstat or lsof)
  - Check Frida: run `frida-ps -U` and check exit code
  - Call before start_all_services() to skip already-running services

- [x] **T017** Implement duration enforcement in AutomationController._enforce_duration_limit() in `automation/services/automation_controller.py`
  - Add QTimer callback that fires every 60 seconds
  - Calculate elapsed = now() - recording.start_time
  - If elapsed >= duration_limit_seconds: call stop_recording(), set auto_stopped=True
  - Log warning: "[WARN] Recording auto-stopped: duration limit reached"
  - Start timer in start_recording(), stop in stop_recording()

- [x] **T018** Implement interaction gating in AutomationController.add_interaction() in `automation/services/automation_controller.py`
  - Add guard: if not _record_in_progress: return error
  - Return: {"status": "error", "reason": "recording_not_active", "message": "Recording must be started first"}
  - Add is_interaction_allowed() method for UI to check before processing clicks
  - Update start_recording() to set _record_in_progress = True
  - Update stop_recording() to set _record_in_progress = False

- [x] **T019** Implement incremental persistence in AutomationController.add_interaction() in `automation/services/automation_controller.py`
  - After appending to in-memory interactions list, immediately append to incremental file
  - Use: `with open(incremental_file, 'a') as f: f.write(json.dumps(interaction) + '\n'); f.flush()`
  - Handle IOError: if write fails, call recording.mark_failed(), log error
  - Ensure incremental_file is opened in start_recording(), closed in stop_recording()

### UI Layer Updates (Sequential - Shared QMainWindow)

- [x] **T020** Fix screen refresh rate in ScreenCaptureWorker in `automation/ui/qt_workers.py`
  - Change QTimer interval from 500ms to 100ms (10 Hz)
  - Line change: `self.timer.start(500)` → `self.timer.start(100)`
  - Add performance logging: measure ADB screencap duration, warn if >100ms

- [x] **T021** Fix auto-start trigger in ControlCenter.__init__() in `automation/ui/control_center.py`
  - Call `self._start_services_automatically()` at end of __init__()
  - Ensure called AFTER all UI components initialized
  - Verify service indicators and log panel exist before calling

- [x] **T022** Add interaction blocking UI logic in ControlCenter mouse event handlers in `automation/ui/control_center.py`
  - Before relaying click to device, call `automation_controller.is_interaction_allowed()`
  - If not allowed: show QMessageBox with "Recording must be started first"
  - Do NOT call ADB input command if blocked
  - Apply same logic to type/scroll interactions

---

## Phase 3.4: Integration & Cleanup

- [x] **T023** Update ServiceManagerSnapshot to include retry_in_progress field in `automation/models/service_status.py`
  - Add field: retry_in_progress: bool (True if any service has retry_count > 0 and state != running)
  - Update ServiceManager.get_service_snapshot() to calculate this field
  - Update UI tooltip to show "Retrying (2/3)" when retry_in_progress

- [x] **T024** Remove obsolete backup file `automation/ui/control_center.py.backup`
  - Delete file as per Constitution Principle VI (Code & Artifact Hygiene)
  - Verify no references to backup file in git history or docs

---

## Phase 3.5: Polish

- [x] **T025** [P] Unit test ServiceStatus retry logic in `tests/unit/test_service_status_retry.py`
  - Test should_retry() returns True when retry_count < max_retries
  - Test should_retry() returns False when retry_count >= max_retries
  - Test begin_retry_attempt() increments retry_count
  - Test last_retry_at timestamp updates

- [x] **T026** [P] Unit test AutomationRecording auto-stop logic in `tests/unit/test_recording_auto_stop.py`
  - Test duration calculation on stop_recording()
  - Test auto_stopped flag set when duration >= limit
  - Test validate() catches invalid recordings
  - Test backward compatibility: load old JSON without new fields

- [x] **T027** Run manual testing scenarios from quickstart.md
  - Execute all 8 scenarios from `specs/003-fix-the-app/quickstart.md`
  - Collect evidence (screenshots, logs, JSON files)
  - Store evidence in `test_evidence/003-fix-the-app/`
  - Document any failures or unexpected behavior

---

## Dependencies

**Must complete in order**:
1. T001-T003 (Setup) → blocks all other tasks
2. T004-T012 (Tests) → blocks T013-T022 (Implementation)
3. T013-T014 (Models) → blocks T015-T019 (Services using models)
4. T015-T019 (Services) → blocks T020-T022 (UI calling services)
5. T020-T022 (UI) → blocks T023-T024 (Integration)
6. T023-T024 (Integration) → blocks T025-T027 (Polish)

**Parallel groups** (can run simultaneously):
- Setup: T003 can run parallel with T001-T002 completion
- Tests: T004-T012 all parallel (different files)
- Models: T013-T014 parallel (different files)
- Polish: T025-T026 parallel (different files)

---

## Parallel Example

### Launch All Test Tasks Together (After Setup Complete):
```bash
# Terminal 1
pytest tests/integration/test_service_manager_contract.py -v

# Terminal 2
pytest tests/integration/test_automation_controller_contract.py -v

# Terminal 3
pytest tests/integration/test_recording_session_contract.py -v

# Terminal 4
pytest tests/integration/test_service_startup_reliability.py -v

# Terminal 5
pytest tests/integration/test_service_retry_logic.py -v

# Terminals 6-9
# ... remaining integration tests
```

Or use pytest-xdist:
```bash
pytest tests/integration/ -n auto -v  # runs all [P] tests in parallel
```

### Launch Model Update Tasks Together (After Tests Fail):
```bash
# Developer A: Edit automation/models/service_status.py (T013)
# Developer B: Edit automation/models/recording.py (T014)
# No conflicts - different files, can commit separately
```

---

## Notes

- [P] tasks = different files, no dependencies - safe for parallel execution
- Verify tests fail before implementing (TDD discipline)
- Commit after each task for atomic git history
- Run linter after each file edit: `ruff check automation/`
- Run all tests before merging: `pytest tests/ -v`

---

## Task Validation

### Completeness Checks

- ✅ All 3 contracts have corresponding contract test tasks (T004-T006)
- ✅ All 2 main entities have model update tasks (T013-T014)
- ✅ All 8 quickstart scenarios mapped to integration tests (T007-T012, T027)
- ✅ All 7 implementation files have corresponding tasks (T013-T022)
- ✅ Tests come before implementation (T004-T012 before T013-T022)
- ✅ Parallel tasks truly independent (different files)
- ✅ Each task specifies exact file path

### Coverage Matrix

| Contract | Test Task | Implementation Task |
|----------|-----------|-------------------|
| service-manager-api.md | T004 | T015, T016 |
| automation-controller-api.md | T005 | T017, T018, T019 |
| recording-session-api.md | T006 | T014 |

| Entity | Model Task | Service Task | UI Task |
|--------|-----------|--------------|---------|
| ServiceStatus | T013 | T015, T016 | T021, T023 |
| AutomationRecording | T014 | T017, T018, T019 | T022 |
| ScreenCapture (QTimer) | N/A | N/A | T020 |

| Quickstart Scenario | Integration Test Task |
|---------------------|---------------------|
| Scenario 1: Clean Startup | T007 |
| Scenario 2: Retry Logic | T008 |
| Scenario 3: Recording Workflow | T009 |
| Scenario 4: Duration Limit | T010 |
| Scenario 5: Interaction Blocking | T011 |
| Scenario 6: Screen Refresh | T012 |
| Scenario 7: Error Diagnostics | T008 (overlaps with retry) |
| Scenario 8: Service Order | T007 (overlaps with startup) |

---

## Estimated Effort

| Phase | Tasks | Estimated Hours | Parallel Factor |
|-------|-------|----------------|-----------------|
| 3.1 Setup | T001-T003 | 1-2 hours | 1.5x (some parallel) |
| 3.2 Tests | T004-T012 | 12-16 hours | 9x (all parallel) |
| 3.3 Core | T013-T022 | 16-20 hours | 1.5x (models parallel) |
| 3.4 Integration | T023-T024 | 2-3 hours | 1x (sequential) |
| 3.5 Polish | T025-T027 | 4-6 hours | 2x (unit tests parallel) |
| **Total** | **27 tasks** | **35-47 hours** | **~25-30 hours with parallelism** |

---

*Based on Constitution v1.1.0 - See `.specify/memory/constitution.md`*
*Generated from: plan.md, data-model.md, contracts/, quickstart.md*

