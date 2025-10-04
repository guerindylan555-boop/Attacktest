# Implementation Plan: Simplified Automation App Interface

**Branch**: `002-i-want-the` | **Date**: 2025-10-06 | **Spec**: `specs/002-i-want-the/spec.md`
**Input**: Feature specification from `/specs/002-i-want-the/spec.md`

## Execution Flow (/plan command scope)
```
1. Load feature spec from Input path
   → If not found: ERROR "No feature spec at {path}"
2. Fill Technical Context (scan for NEEDS CLARIFICATION)
   → Detect Project Type from file system structure or context (web=frontend+backend, mobile=app+api)
   → Set Structure Decision based on project type
3. Fill the Constitution Check section based on the content of the constitution document.
4. Evaluate Constitution Check section below
   → If violations exist: Document in Complexity Tracking
   → If no justification possible: ERROR "Simplify approach first"
   → Update Progress Tracking: Initial Constitution Check
5. Execute Phase 0 → research.md
   → If NEEDS CLARIFICATION remain: ERROR "Resolve unknowns"
6. Execute Phase 1 → contracts, data-model.md, quickstart.md, agent-specific template file (e.g., `CLAUDE.md` for Claude Code, `.github/copilot-instructions.md` for GitHub Copilot, `GEMINI.md` for Gemini CLI, `QWEN.md` for Qwen Code, or `AGENTS.md` for all other agents).
7. Re-evaluate Constitution Check section
   → If new violations: Refactor design, return to Phase 1
   → Update Progress Tracking: Post-Design Constitution Check
8. Plan Phase 2 → Describe task generation approach (DO NOT create tasks.md)
9. STOP - Ready for /tasks command
```

**IMPORTANT**: The /plan command STOPS at step 7. Phases 2-4 are executed by other commands:
- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary
The Control Center UI must mirror the simplified three-button workflow (Record, Replay, Capture Token) while automatically managing emulator, proxy, and Frida services. We will align the current auto-managed implementation with the behavior of the legacy manual interface (`automation/ui/control_center.py.backup`) to remove the segmentation fault, keep live service status, and enforce the clarified retry/error-handling rules.

## Technical Context
**Language/Version**: Python 3.10 (Ubuntu 22.04 default interpreter)  
**Primary Dependencies**: PySide6 for UI, subprocess/adb/tmux/mitmdump tooling, project-local automation scripts  
**Storage**: Local JSON/flat files under `automation/recordings/` and `automation/sessions/`  
**Testing**: pytest (configured via `pytest.ini`)  
**Target Platform**: Linux desktop with Android SDK tools, tmux, mitmproxy, Frida  
**Project Type**: single (Python application + tests)  
**Performance Goals**: Service startup < 2s, UI interactions < 500 ms (per spec)  
**Constraints**: Buttons disabled until services ready; automatic retries with exact error messaging during startup failures; evidence/logging must persist  
**Scale/Scope**: Single-operator control center; integrates with existing automation scripts

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*
- **Security-First Testing**: `data-model.md` keeps record/replay/capture flows first-class while documenting control gating, preserving attack workflows. ✔️
- **Automation-Driven Discovery**: `contracts/service-management.json` codifies retry-aware service APIs so automation stays the default path. ✔️
- **Evidence-Based Reporting**: `contracts/automation-control.json` and `quickstart.md` spell out evidence artefacts (recordings, CAPTURED_TOKEN files) and log visibility. ✔️
- **Multi-Vector Analysis**: Service schemas and prerequisites retain emulator, proxy, and Frida coverage in tandem. ✔️
- **Reproducible Test Environment**: `quickstart.md` now includes explicit tool checks and shutdown expectations for deterministic reruns. ✔️

Post-Design Constitution Check ✅
- Phase 1 documentation produced (`research.md`, `data-model.md`, `contracts/`, `quickstart.md`) and aligns with constraints.
- Retry/error handling written into contracts; buttons remain disabled until `ServiceManagerSnapshot.all_ready`.
- Evidence capture paths and logging are locked into design deliverables for later validation.

Progress Tracking: Post-Design Constitution Check ✅

## Project Structure

### Documentation (this feature)
```
specs/002-i-want-the/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
automation/
├── models/
│   ├── recording.py
│   ├── service_status.py
│   └── token_session.py
├── services/
│   ├── automation_controller.py
│   ├── service_manager.py
│   └── token_controller.py
└── ui/
    ├── control_center.py          # current simplified UI (to fix)
    └── control_center.py.backup   # legacy working reference

scripts/
└── automation/scripts/            # emulator/proxy/appium helpers

capture_working_final.py
pytest.ini
```

**Structure Decision**: Use existing single-project Python layout rooted at `automation/` with supporting scripts at repo root; enhancements focus on UI module + services beneath this structure.

## Phase 0: Outline & Research
1. Identify unknowns from Technical Context:
   - Validate PySide6 threading/process patterns causing segmentation fault during startup.
   - Confirm best practices for integrating ServiceManager retries with Qt event loop.
   - Document environment prerequisites (tmux, adb, mitmproxy, Frida) to reproduce auto startup.
2. Research tasks to dispatch (captured in `research.md`):
   - Investigate PySide6 segmentation fault causes when using ThreadPoolExecutor and QTimers concurrently.
   - Review legacy `control_center.py.backup` process management for insights on stable command execution.
   - Gather guidance on presenting live error messages within PySide6 QLabel updates.
   - Verify filesystem evidence paths align with constitutional logging requirements.
3. Consolidate findings in `research.md` with Decision / Rationale / Alternatives per topic.

## Phase 1: Design & Contracts
1. **Data Model (`data-model.md`)**
   - Document entities: `ServiceStatus`, `AutomationRecording`, `TokenCaptureSession`.
   - Capture new fields/behaviors: retry counters (max 3), error message display, button enablement states.
   - Specify relationships (UI consumes ServiceManager status objects; controllers depend on ServiceManager readiness).
2. **Contracts (`contracts/`)**
   - Produce interface contracts for controller methods (start/stop recording, replay, token capture) describing expected JSON/dict payloads and error reasons.
   - Define service health polling schema consumed by UI (status, error_message, retry_attempt, startup_time).
   - Include negative cases covering retries exhausted, missing credentials, and service initialization delays.
3. **Tests (scaffold only)**
   - Contract tests asserting controller outputs before implementation adjustments.
   - Integration test outline verifying auto-start, button disabling, retry messaging (failing until implementation catches up).
4. **Quickstart (`quickstart.md`)**
   - Summarize environment setup, launch steps, dependency checks, and how to observe retries/error messages.
5. **Agent Context**
   - Run `.specify/scripts/bash/update-agent-context.sh claude` to register new tech details (retry logic, PySide6 threading notes) after drafting docs.

Post-Design Constitution Check to verify automation + evidence requirements still met (document in Constitution Check section after Phase 1 artifacts exist).

## Phase 2: Task Planning Approach
*Do NOT execute now; describe approach for `/tasks`*
- Generate tasks directly from contracts and data-model outcomes.
- Enforce TDD order: create failing tests for auto-start retries, button gating, error visibility, then implement controllers/UI fixes.
- Group tasks:
  1. ServiceManager enhancements (retry loop, error propagation, status struct updates).
  2. UI fixes (safe threading, using Qt signals instead of raw threads, disable buttons until ready, display exact errors).
  3. Regression alignment with legacy reference (ensure tmux/adb commands invoked consistently).
  4. Evidence/logging validation tasks (token capture outputs, log messaging for retries).
- Identify parallelizable items with `[P]` (e.g., model/unit test updates vs UI integration tests).

## Phase 3+: Future Implementation
- Phase 3: Use `/tasks` to produce executable checklist.
- Phase 4: Implement code changes guided by tasks (refactor UI/service logic, remove segmentation faults, ensure retry messaging).
- Phase 5: Validation via pytest suites, manual UI smoke test, and verification of generated evidence files.

## Complexity Tracking
| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| *(none)* | *(n/a)* | *(n/a)* |

