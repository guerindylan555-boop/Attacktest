# Automation Module Layout

This directory hosts the tooling that orchestrates the MaynDrive automation flows. The structure is in the middle of a migration toward the consolidated modules defined in the Automation App Stabilization plan.

## Active Modules
- `session/` – new home for restart orchestration, session state models, and metrics emitters.
- `replay/` – deterministic playback, recording helpers, and drift validation utilities.
- `ui_catalog/` – UI discovery, catalog synchronisation, and export helpers (JSON + YAML).
- `logs/` – shared logging and metrics bootstrap for CLI and service modules.
- `scripts/` – operator entry points that will be updated to call into the modules above.
- `hooks/` – Frida/Appium hook assets (unchanged).

## Legacy Modules Pending Migration
- `sessions/` – previous restart/replay controllers; code will migrate into `session/` and `replay/` during implementation.
- `services/` – assorted helpers that will either move into dedicated modules or be archived if superseded.
- `models/` – legacy data structures; new pydantic models will live under `session/`, `replay/`, or `ui_catalog/`.
- `recordings/` & `ui/` – existing assets that will be reviewed and relocated or archived in later hygiene tasks.

Migration tasks are tracked in `specs/005-i-want-to/tasks.md` (see T020). Until those tasks are completed, both the new and legacy modules coexist. New code MUST target the module layout above.
