# Implementation Plan: Automation App Stabilization

**Branch**: `005-i-want-to` | **Date**: 2025-10-04 | **Spec**: [Automation App Stabilization Spec](./spec.md)
**Input**: Feature specification from `/specs/005-i-want-to/spec.md`

## Summary
Stabilize the automation control center by hardening the kill/restart flow, restoring deterministic replay with ±250 ms tolerance, and establishing dual-format (JSON/YAML) UI catalogs so future vulnerability probes rely on clean state, reliable playback, and well-labeled UI metadata. The solution introduces modular session, replay, and discovery services with observability hooks and repository hygiene checkpoints in line with the Attacktest constitution v1.0.0.

## Technical Context
**Language/Version**: Python 3.10 (automation stack)
**Primary Dependencies**: PySide6, Appium Python client, Frida, ADB tooling, asyncio, pydantic (for schema validation)
**Storage**: Local filesystem artifacts (JSON + YAML catalogs, structured logs), optional encrypted vault for secrets
**Testing**: pytest with integration fixtures (Appium/session sandboxes), smoke scripts invoked via `automation/scripts`
**Target Platform**: Ubuntu workstation controlling Android emulator (Pixel), with optional USB device stubs for regression checks
**Project Type**: single (automation toolkit in repo root)
**Performance Goals**: Restart completes ≤30 s; replay drift ≤±250 ms; UI discovery catalog export ≤10 s for standard flows
**Constraints**: Must operate offline after initial setup; sensitive tokens encrypted/redacted; no destructive actions outside emulator scope; minimal manual intervention
**Scale/Scope**: Single operator sessions; supports one active device/emulator per run; catalog versioning for <500 UI nodes per release

## Constitution Check
- **I. Clean, Modular Automation Code**: Plan splits logic into `automation/session`, `automation/replay`, and `automation/ui_catalog`, each with typed interfaces, unit coverage, and lint enforcement.
- **II. Deterministic Session Control**: Introduce state machine service, health probes, and blocking guards to prevent crashes and guarantee idempotent restarts.
- **III. Security-First Exploit Research**: Secrets flow through encrypted catalog exports; restart scripts run with least privilege; audit logging anonymizes tokens.
- **IV. Evidence-Driven Discovery**: Replays emit structured JSON logs; discovery stores screenshots + selectors; metrics exposed for dashboards.
- **V. Sustainable Repository Hygiene**: Folder cleanup proposal relocates legacy scripts into archived buckets and documents new layout in README updates.

**Gate Status**: Initial Constitution Check PASS

## Project Structure

### Documentation (this feature)
```
specs/005-i-want-to/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
```

### Source Code (repository root)
```
automation/
├── session/
│   ├── __init__.py
│   ├── controller.py        # orchestrates kill/restart, health checks
│   ├── state.py             # finite-state machine + pydantic models
│   └── metrics.py           # structured logging + Prom-style metrics emitters
├── replay/
│   ├── __init__.py
│   ├── player.py            # deterministic playback with drift validation
│   ├── recorder.py          # ensures new recordings capture selectors + timing
│   └── validator.py         # compares runs against golden traces
├── ui_catalog/
│   ├── __init__.py
│   ├── discovery.py         # Appium/Frida-based discovery routines
│   ├── catalog_sync.py      # writes JSON/YAML + screenshot assets
│   └── schema.py            # shared pydantic models for catalog entries
├── cli/
│   └── control_center.py    # PySide6 bindings invoking new services
└── logs/
    └── __init__.py          # central logging configuration (structured)

automation/scripts/
├── run_restart_healthcheck.py
├── run_replay_validation.py
└── export_ui_catalog.py

automation/hooks/
└── general.js

tests/
├── session/
│   ├── test_restart_flow.py
│   └── test_state_machine.py
├── replay/
│   ├── test_replay_alignment.py
│   └── test_replay_error_paths.py
├── ui_catalog/
│   ├── test_catalog_export.py
│   └── test_label_collisions.py
└── e2e/
    └── test_control_center_smoke.py
```

**Structure Decision**: Single-project layout centered on `automation/` modules with mirrored `tests/` hierarchy; scripts orchestrate flows while UI catalog assets stay version-controlled.

## Phase 0: Outline & Research
1. Validate emulator restart strategy (ADB vs Appium driver) and confirm crash root causes; ensure idempotent session teardown.
2. Determine health probes required to assert “clean state” (e.g., login screen detection, hook attachment signals, metric beacons).
3. Define replay drift measurement approach (coordinate tolerance, timing window, log comparison) and storage for golden traces.
4. Specify dual-format catalog export process (JSON + YAML) and encryption/redaction pipeline for sensitive fields.
5. Evaluate observability stack (structured logging, metrics namespace) to surface restart/replay/labeling indicators.

**Output**: `research.md` capturing decisions, rationale, and alternatives.

## Phase 1: Design & Contracts
1. Model `SessionState`, `ReplayScript`, `UICatalogEntry`, and `UICatalogVersion` entities with schemas and transitions in `data-model.md`.
2. Document service contracts:
   - `session.restart` command (inputs, outputs, errors)
   - `replay.run` command with drift validation payloads
   - `catalog.export` command describing JSON/YAML schema and storage guarantees
3. Generate quickstart guide detailing pre-reqs, validation scripts, and smoke tests for restart/replay/catalog features.
4. Update agent context (`.specify/scripts/bash/update-agent-context.sh cursor`) so coding assistants know new modules and guardrails.
5. Confirm resulting design meets constitutional gates; log findings in Constitution Check (post-design).

**Output**: `data-model.md`, `contracts/*.yaml`, `quickstart.md`, updated agent context.

## Phase 2: Task Planning Approach
- `/tasks` will translate contracts and models into TDD tasks: session state machine tests precede controller implementation; replay validator tests precede drift logic; catalog export tests precede dual-format writers.
- Parallelize tasks by module (`session`, `replay`, `ui_catalog`) while sharing common logging utilities.
- Enforce hygiene actions (migrate old scripts into `automation/archive/` and update README) before implementation sign-off.

## Phase 3+: Future Implementation
- Phase 3: `/tasks` generates work breakdown (TDD-first).
- Phase 4: Implement modules following constitution guardrails, committing after each task.
- Phase 5: Run pytest suites, smoke scripts, and manual GUI verification; update health dashboard metrics.

## Complexity Tracking
_No deviations anticipated; section intentionally left blank._

## Progress Tracking

**Phase Status**:
- [x] Phase 0: Research complete (/plan command)
- [x] Phase 1: Design complete (/plan command)
- [ ] Phase 2: Task planning complete (/plan command - describe approach only)
- [ ] Phase 3: Tasks generated (/tasks command)
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: PASS
- [x] Post-Design Constitution Check: PASS
- [x] All NEEDS CLARIFICATION resolved
- [ ] Complexity deviations documented

---
*Based on Attacktest Automation Toolkit Constitution v1.0.0*
