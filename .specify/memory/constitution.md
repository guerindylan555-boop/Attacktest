<!--
Sync Impact Report
- Version change: 0.0.0 → 1.0.0
- Modified principles: Initial publication (all five principles new)
- Added sections: Operational Standards; Collaboration & Review Workflow
- Removed sections: None
- Templates requiring updates:
  ⚠ .specify/templates/plan-template.md – refresh Constitution Check gates and version reference
  ⚠ .specify/templates/spec-template.md – highlight clean automation, restart/replay goals, UI labeling expectations
  ⚠ .specify/templates/tasks-template.md – bake in restart validation, replay fidelity, and folder hygiene tasks
- Follow-up TODOs:
  • Document a recurring folder cleanup checklist alongside automation scripts
-->

# Attacktest Automation Toolkit Constitution

## Core Principles

### I. Clean, Modular Automation Code
Mandates:
- Enforce small, composable modules with clear interfaces for exploit automation, UI control, and evidence capture.
- Keep every change covered by automated tests or explicit validation scripts before merging.
- Reject code that obscures intent, duplicates logic, or hides state transitions in global variables.
Rationale: Maintainable automation lets the team iterate quickly on new vulnerability probes without destabilizing proven workflows.

### II. Deterministic Session Control
Mandates:
- Provide idempotent routines to kill, restart, and reseed test environments without manual cleanup.
- Track and persist run states so replay scripts follow the exact recorded click or intent sequence.
- Block merges when restart or replay workflows crash, hang, or produce non-repeatable outcomes.
Rationale: Repeatable session control is foundational for verifying fixes, reproducing exploits, and expanding coverage safely.

### III. Security-First Exploit Research
Mandates:
- Treat captured credentials, tokens, and device artifacts as secrets; encrypt at rest and scrub from logs.
- Run tooling with least privilege, isolating destructive payloads from discovery-only scans.
- Document mitigation steps for every risky assumption in specs, plans, and code reviews.
Rationale: Automation that finds vulnerabilities must not create new ones or leak sensitive data in the process.

### IV. Evidence-Driven Discovery
Mandates:
- Capture structured output (JSON + human-readable logs) for every automation run and store alongside replay assets.
- Instrument UI discovery to label widgets with stable identifiers, screenshots, and locator metadata.
- Require observability hooks (metrics, traces, logs) before adding new exploitation branches.
Rationale: Rich evidence accelerates triage, reporting, and future exploit automation.

### V. Sustainable Repository Hygiene
Mandates:
- Propose folder cleanup with each significant change: deprecate dead scripts, relocate assets, and document new structure.
- Keep automation scripts, replay assets, and tooling configs grouped by function with READMEs at each level.
- Schedule quarterly hygiene passes to align directory layout with actively supported workflows.
Rationale: A predictable tree prevents drift, speeds onboarding, and keeps automation extensible.

## Operational Standards
- Apply type hints, linting, and formatting across Python, JS, and shell entry points to enforce consistency.
- Maintain golden-path automation scenarios (restart, replay, UI discovery) as executable examples with expected outputs.
- Bundle verification scripts (unit, integration, smoke) so any engineer can validate a change before and after folder moves.
- Store UI maps, selector catalogs, and replay definitions in version-controlled JSON/YAML with reviewable diffs.

## Collaboration & Review Workflow
- Specifications must state restart success criteria, replay accuracy tolerances, and UI labeling requirements before planning begins.
- Code reviews block on missing tests, absent observability hooks, or unexplained folder reorganizations.
- Document folder cleanup proposals in PR descriptions and update affected READMEs or onboarding guides.
- Share weekly automation health summaries covering crash rates, replay fidelity, and labeling drift to catch regressions early.

## Governance
- This constitution governs all automation, discovery scripts, and supporting infrastructure under the Attacktest repository.
- Amendments require consensus from engineering and security leads, an impact assessment, and updates to dependent templates.
- Versioning follows semantic rules: Major for principle changes, Minor for new guidance, Patch for clarifications.
- Compliance reviews occur monthly; violations trigger hotfix branches that restore alignment before new features land.

**Version**: 1.0.0 | **Ratified**: 2025-10-04 | **Last Amended**: 2025-10-04
