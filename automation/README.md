# Automation Module Layout

This directory hosts the tooling that orchestrates the MaynDrive automation flows. The structure now centres on the consolidated modules defined in the Automation App Stabilization plan.

## Active Modules
- `session/` – new home for restart orchestration, session state models, and metrics emitters.
- `replay/` – deterministic playback, recording helpers, and drift validation utilities.
- `ui_catalog/` – UI discovery, catalog synchronisation, and export helpers (JSON + YAML).
- `logs/` – shared logging and metrics bootstrap for CLI and service modules.
- `scripts/` – operator entry points that will be updated to call into the modules above.
- `hooks/` – Frida/Appium hook assets (unchanged).

## Archived / Legacy Content
- `archive/` – historical modules kept for reference (e.g. the former `automation/sessions`). Remove entries once downstream branches stop importing them.
- `services/` – legacy orchestration helpers still required by the PySide6 control centre; refactors will fold logic into `session/` and `replay/` over time.
- `models/` – data structures that continue to back the GUI and token workflows. Use alongside the new modules until a dedicated data layer replaces them.
- `recordings/` & `ui/` – existing assets retained for backward-compatible inspection and GUI support.

New code MUST target the active modules listed above. When retiring older helpers, move them into `automation/archive/` so historical branches retain a breadcrumb without polluting the primary automation surface.
