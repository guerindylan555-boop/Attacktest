---
description: Create a focused feature specification to stabilize the automation app's restart, replay, and UI labeling workflows.
---

The user input provided after `/specify` **must** be reviewed and reflected in the spec.

Context & Goals:
- Repair the kill/restart control so it resets the automation target cleanly without crashing.
- Restore the replay routine so it faithfully follows the recorded click path.
- Ensure the UI discovery pass captures widgets with durable, well-labeled identifiers to simplify future automation.

Execution Steps:
1. Study the conversation, existing docs, and any linked artefacts to understand the broken behaviors (crashing restart button, replay desync, missing UI labels).
2. Inventory traces or logs that describe the failures (crash dumps, replay recordings, discovery outputs) and note any gaps the spec must fill.
3. Run `.specify/scripts/bash/create-new-feature.sh --json "$ARGUMENTS"` exactly once from repo root and capture `BRANCH_NAME` and `SPEC_FILE` from its JSON output.
4. Open `.specify/templates/spec-template.md` and follow its structure when drafting the spec.
5. Populate the spec with concrete details:
   - Problem Statement covering each broken workflow and current impact.
   - Goals / Non-Goals clarifying stability, resilience, and labeling expectations.
   - Current Behavior & Root Cause hypotheses referencing observed crashes or replay drift.
   - Proposed Changes describing architecture updates (state management for restart, deterministic replay sequencing, UI discovery metadata schema).
   - Validation Plan specifying automated tests, replay scripts, and acceptance criteria (e.g., restart completes without crash, replay matches recorded clicks, UI elements persist labeled names/IDs).
   - Rollout / Monitoring guidelines ensuring regressions are caught quickly.
6. Save the completed spec to `SPEC_FILE` with no remaining template placeholders.
7. Report completion back to the user including the branch name, spec path, and any open questions or follow-up investigations.
