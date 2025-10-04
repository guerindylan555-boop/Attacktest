# Tasks: Simplified Automation App Interface

**Input**: Design documents from `/specs/002-i-want-the/`
**Prerequisites**: plan.md (required), research.md, data-model.md, contracts/

## Phase 3.1: Setup
- [X] T001 Bootstrap test scaffolding (`tests/`) with `tests/conftest.py`, `tests/contracts/`, `tests/integration/`, and `tests/unit/` directories aligned to pytest discovery.
- [X] T002 Create Qt event loop fixture in `tests/conftest.py` to support PySide6-driven integration tests.

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3
- [X] T003 [P] Write failing contract tests for automation controller endpoints in `tests/contracts/test_automation_control.py` per `contracts/automation-control.json`.
- [X] T004 [P] Write failing contract tests for service management endpoints in `tests/contracts/test_service_management.py` per `contracts/service-management.json`.
- [X] T005 [P] Add integration test covering automatic service startup, retry messaging, and button gating in `tests/integration/test_service_startup.py`.
- [X] T006 [P] Add integration test for record workflow evidence emission in `tests/integration/test_record_flow.py`.
- [X] T007 [P] Add integration test for replay workflow (action disable/enable lifecycle) in `tests/integration/test_replay_flow.py`.
- [X] T008 [P] Add integration test for token capture retries and evidence files in `tests/integration/test_token_capture.py`.

## Phase 3.3: Core Implementation (ONLY after tests are failing)
- [X] T009 Implement retry-aware `ServiceStatus` and introduce `ServiceManagerSnapshot` in `automation/models/service_status.py`.
- [X] T010 [P] Add `ControlActionState` and `EvidenceArtifact` models in `automation/models/control_action.py` to represent UI gating and artefact metadata.
- [X] T011 [P] Extend `AutomationRecording` lifecycle/state handling and file metadata in `automation/models/recording.py`.
- [X] T012 [P] Extend `TokenCaptureSession` to track evidence files, capture log entries, and failure reasons in `automation/models/token_session.py`.
- [X] T013 Update `automation/services/service_manager.py` to run startup retries via Qt-friendly processes, emit `ServiceManagerSnapshot`, and handle `/services/retry` flow.
- [X] T014 Update `automation/services/automation_controller.py` to expose action states, enforce service readiness, and orchestrate recording lifecycle with evidence registration.
- [X] T015 Update `automation/services/token_controller.py` to validate service readiness, surface credential errors, and capture evidence metadata consistently.
- [X] T016 Refactor `automation/ui/control_center.py` to use Qt-managed workers for screen capture, bind action states, and surface retry/error messaging per contracts.
- [X] T017 [P] Introduce helper module `automation/ui/qt_workers.py` encapsulating screencap and service polling workers.

## Phase 3.4: Integration
- [X] T018 Wire structured logging/evidence aggregation (including `EvidenceArtifact` registration) across controllers in `automation/services/automation_controller.py` and `automation/services/token_controller.py`.
- [X] T019 Ensure shutdown routine persists pending artefacts and stops services cleanly, updating `automation/ui/control_center.py` and `automation/services/service_manager.py` accordingly.

## Phase 3.5: Polish
- [X] T020 [P] Add unit coverage for new models and action-state helpers in `tests/unit/test_models.py`.
- [X] T021 [P] Add unit tests for ServiceManager retry edge cases in `tests/unit/test_service_manager.py`.
- [X] T022 [P] Update `specs/002-i-want-the/quickstart.md` and `CLAUDE.md` with any implementation-specific adjustments found during testing.
- [X] T023 [P] Run end-to-end manual verification following Quickstart Section 4 and capture notes in `IMPLEMENTATION_SUMMARY.md`.

## Dependencies
- Setup tasks (T001-T002) must complete before writing tests or implementation.
- Contract/integration tests (T003-T008) must be authored and failing before starting implementation tasks (T009-T017).
- Model updates (T009-T012) block service/controller refactors (T013-T016).
- UI refactor T016 depends on service/controller updates (T013-T015).
- Integration tasks (T018-T019) depend on completion of core implementation tasks for affected files.
- Polish tasks (T020-T023) depend on all prior phases.

## Parallel Execution Examples
```
# After T002, launch contract/integration tests in parallel:
Task: "T003 Write failing contract tests for automation controller endpoints in tests/contracts/test_automation_control.py"
Task: "T004 Write failing contract tests for service management endpoints in tests/contracts/test_service_management.py"
Task: "T005 Add integration test covering automatic service startup, retry messaging, and button gating in tests/integration/test_service_startup.py"
Task: "T006 Add integration test for record workflow evidence emission in tests/integration/test_record_flow.py"
Task: "T007 Add integration test for replay workflow (action disable/enable lifecycle) in tests/integration/test_replay_flow.py"
Task: "T008 Add integration test for token capture retries and evidence files in tests/integration/test_token_capture.py"

# After T016, polish tasks can run together:
Task: "T020 Add unit coverage for new models and action-state helpers in tests/unit/test_models.py"
Task: "T021 Add unit tests for ServiceManager retry edge cases in tests/unit/test_service_manager.py"
Task: "T022 Update specs/002-i-want-the/quickstart.md and CLAUDE.md with any implementation-specific adjustments found during testing"
Task: "T023 Run end-to-end manual verification following Quickstart Section 4 and capture notes in IMPLEMENTATION_SUMMARY.md"
```
