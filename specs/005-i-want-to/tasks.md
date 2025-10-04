# Tasks: Automation App Stabilization

**Input**: Design documents from `/specs/005-i-want-to/`
**Prerequisites**: plan.md (required), research.md, data-model.md, contracts/

## Phase 3.1: Setup
- [X] T001 Audit existing `automation/` tree; create new modules `automation/session`, `automation/replay`, `automation/ui_catalog`, and `automation/logs` with `__init__.py` stubs while documenting legacy moves in `automation/README.md`.
- [X] T002 Update `requirements.txt` to pin/confirm PySide6, Appium Python client, pydantic, loguru (or chosen structured logger), and Prometheus client; regenerate lock/config files if present.
- [X] T003 Establish shared logging + metrics bootstrap in `automation/logs/__init__.py` and wire minimal configuration into `automation/cli/control_center.py` (no behavioral changes yet).

## Phase 3.2: Tests First (TDD)
- [X] T004 [P] Author failing contract test for `session.restart` in `tests/session/test_restart_flow.py` validating timeout, hook, and UI readiness error paths per `contracts/restart_flow.yaml`.
- [X] T005 [P] Author failing contract test for `replay.run` in `tests/replay/test_replay_alignment.py` covering timing/coordinate drift detection using golden trace fixtures.
- [X] T006 [P] Author failing contract test for `catalog.export` in `tests/ui_catalog/test_catalog_export.py` asserting dual JSON/YAML outputs and label collision reporting.
- [X] T007 [P] Add failing integration test `tests/e2e/test_control_center_smoke.py` that orchestrates restart → replay → catalog export via CLI stubs and asserts structured logs/metrics are emitted.
- [X] T008 [P] Create unit tests for `SessionState` state machine in `tests/session/test_state_machine.py`, covering all transitions and error recovery paths.
- [X] T009 [P] Create unit tests for catalog label collision handling in `tests/ui_catalog/test_label_collisions.py` ensuring encryption of sensitive selectors when flagged.

## Phase 3.3: Core Implementation (ONLY after tests are failing)
- [X] T010 Implement `automation/session/state.py` models and transition helpers satisfying T008.
- [X] T011 Implement `automation/session/controller.py` restart workflow (Appium terminate/activate + ADB fallback) and readiness probes satisfying T004 & T007.
- [X] T012 Implement `automation/session/metrics.py` to emit Prometheus counters/histograms and integrate with logging bootstrap (T003, T007).
- [X] T013 Implement `automation/replay/player.py` with deterministic timing + coordinate checks and golden trace recording satisfying T005 & T007.
- [X] T014 Implement `automation/replay/validator.py` for drift reports and error surfacing referenced by replay scripts.
- [X] T015 Update `automation/cli/control_center.py` to drive new session/replay services, expose health indicators, and surface structured log paths while maintaining GUI layout.
- [X] T016 Implement `automation/ui_catalog/discovery.py` with Appium/Frida discovery pipeline using clarified emulator scope.
- [X] T017 Implement `automation/ui_catalog/catalog_sync.py` to generate synchronized JSON/YAML catalogs with screenshot exports and sensitive-field encryption satisfying T006 & T009.
- [X] T018 Implement `automation/ui_catalog/schema.py` pydantic models aligning with `data-model.md` definitions.
- [X] T019 Provide CLI/script entry points `automation/scripts/run_restart_healthcheck.py`, `run_replay_validation.py`, and `export_ui_catalog.py` wired to new services and producing structured logs per quickstart.

## Phase 3.4: Integration & Hygiene
- [X] T020 Migrate or archive superseded modules (`automation/sessions`, `automation/services`, legacy scripts) into `automation/archive/` with README explaining replacements.
- [X] T021 Update `README.md` and `AUTOMATIC_SETUP_GUIDE.md` with new restart/replay/catalog procedures, environment variables, and folder layout.
- [X] T022 Wire metrics endpoint exposure (e.g., using `prometheus_client.start_http_server`) and document port/configuration.
- [X] T023 Add encryption helpers for catalog exports, ensuring keys sourced from existing secure storage and documenting emergency rotation process.
- [X] T024 Refresh automation health summary (e.g., `FULL_AUTOMATION_SUMMARY.md`) with new status indicators and verification steps.

## Phase 3.5: Polish
- [ ] T025 [P] Add targeted performance test in `tests/replay/test_replay_performance.py` verifying replay completes within tolerance and logging overhead stays bounded.
- [ ] T026 [P] Add lint/type checks to CI or local scripts ensuring new modules comply (`python -m compileall`, `mypy` if configured).
- [ ] T027 [P] Clean up generated artifacts post-tests and ensure `.gitignore` covers new log/replay output directories.
- [ ] T028 Run full validation suite (`pytest` + quickstart scripts), capture evidence, and attach results to feature branch documentation.

## Dependencies
- T001 before all module creation tasks (T010–T019) to ensure structure exists.
- T004–T009 must precede their respective implementation tasks (T010–T017).
- T015 depends on T011–T014 to guarantee backend services available for GUI wiring.
- T017 depends on T016 and T018 for discovery data and schemas.
- T020 must follow core implementations to safely migrate/retire legacy code.
- T028 requires completion of all prior tasks.

## Parallel Execution Example
```
# After setup (T001–T003) complete, kick off parallel test authoring:
Task: T004 [P] Author failing contract test for session.restart
Task: T005 [P] Author failing contract test for replay.run
Task: T006 [P] Author failing contract test for catalog.export
Task: T008 [P] Create unit tests for SessionState state machine
```

**Task Generation Strategy**
- Tests first per module, followed by implementation and hygiene tasks, aligning with constitution-driven clean code and evidence requirements.
- Parallel marking `[P]` applied only when tasks touch distinct files to avoid merge conflicts.
