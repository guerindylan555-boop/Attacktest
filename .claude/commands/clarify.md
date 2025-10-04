---
description: Resolve open questions in the automation app spec related to restart stability, replay fidelity, and durable UI labeling.
---

The user input after `/clarify` **must** influence every decision below.

User input:

$ARGUMENTS

Goal: Surface and eliminate the most critical ambiguities in the active feature specification for repairing the automation app (kill/restart flow, replay routines, and UI discovery metadata). Record the answers directly in the spec so downstream planning and implementation stay aligned.

This clarification pass should finish **before** `/plan` unless the user explicitly waives it, in which case warn about elevated rework risk.

Execution steps:

1. From the repo root run `.specify/scripts/bash/check-prerequisites.sh --json --paths-only` exactly once. Capture from its JSON payload:
   - `FEATURE_DIR`
   - `FEATURE_SPEC`
   - (Optionally note `IMPL_PLAN`, `TASKS` for subsequent phases.)
   Abort if JSON parsing fails and instruct the user to re-run `/specify` or repair the feature branch context.

2. Load the current spec and perform an ambiguity scan emphasizing the automation workflows:

   Functional Scope & Behavior:
   - Restart/killswitch success criteria and clean-state definition
   - Replay fidelity expectations (timing, ordering, device/OS variance)
   - UI discovery outputs and labeling granularity
   - Out-of-scope declarations for manual overrides or unsupported widgets

   Domain & Data Model:
   - Session/state objects involved in restart and replay
   - Identifier schema for discovered UI elements (naming collision rules)
   - Persistence requirements for replay scripts and UI maps

   Interaction & UX Flow:
   - Kill → restart → ready sequence including confirmation dialogs
   - Replay setup, progress indication, and recovery steps when drift detected
   - UI labeling workflows in the recorder/discovery UI

   Non-Functional Quality Attributes:
   - Performance budgets for restart (time-to-ready) and replay (latency jitter)
   - Reliability goals (crash-free restarts, deterministic replays)
   - Observability signals (logs, metrics, traces for restart/replay/discovery)
   - Security/privacy when storing labeled UI metadata

   Integration & External Dependencies:
   - Target app/environment prerequisites for clean restart
   - Replay transport (e.g., WebSocket, adb) and version constraints
   - Storage backends for UI catalogs or replay archives

   Edge Cases & Failure Handling:
   - Restart mid-operation, missing permissions, hung processes
   - Replay desync, unavailable UI nodes, dynamic IDs
   - Conflicting labels or obsolete discovery snapshots

   Constraints & Tradeoffs:
   - Supported platforms and automation frameworks
   - Resource limits (memory, disk for snapshots)
   - Any deliberate exclusions (e.g., no multi-session parallelism)

   Terminology & Consistency:
   - Canonical names for restart modes, replay runs, and UI labels
   - Deprecated aliases to avoid in future specs

   Completion Signals:
   - Acceptance criteria: crash-free restart, replay accuracy tolerance (e.g., 100% click match), labeled UI coverage targets
   - Definition-of-done checkpoints (tests, monitoring hooks, documentation updates)

   Misc / Placeholders:
   - TODO markers, vague adjectives ("robust", "intuitive"), or unresolved dependency notes

   Categorize each item as Clear / Partial / Missing. Create an internal coverage map to drive question selection.

3. Generate an internal queue of up to 5 clarification questions targeting the highest impact gaps. Each must be answerable via:
   - A 2–5 option multiple-choice table (include a `Short` option only if a free-form alternative makes sense), or
   - A constrained short answer: `Format: Short answer (<=5 words)`.

   Focus on clarifications that affect architecture/state management, replay sequencing, UI metadata schema, validation strategy, or operations. Avoid stylistic or low-stakes inquiries.

4. Question loop:
   - Ask **one** question at a time, format per guidance above.
   - Validate responses map to an option or meet the <=5 word requirement.
   - If unclear, request quick disambiguation without counting as a new question.
   - Record accepted answers in working memory and continue until queue empty, user stops, or 5 questions asked.
   - Never hint at future queued questions.

5. After each accepted answer, immediately integrate it into the spec:
   - Ensure a `## Clarifications` section exists (create if missing) with `### Session YYYY-MM-DD` for today.
   - Append a bullet `- Q: <question> → A: <answer>`.
   - Update the relevant spec sections (Functional Requirements, Data Model, Interaction Flow, Non-Functional, Edge Cases, etc.) to reflect the clarification. Remove or revise conflicting text instead of duplicating it.
   - Save the spec back to `FEATURE_SPEC` after each integration, preserving formatting and heading order.

6. Validation checklist after each write and at the end:
   - ≤5 questions logged for the session.
   - No unresolved placeholders where an answer was meant to apply.
   - Clarification entries align with updated content; no contradictions remain.
   - Markdown structure intact; only new headings allowed are `## Clarifications` and `### Session YYYY-MM-DD`.
   - Terminology consistent (e.g., single name for the restart control).

7. Final report to user:
   - Number of questions asked/answered.
   - Path to the updated spec.
   - Sections modified.
   - Coverage summary table listing each taxonomy category with Status: Resolved, Clear, Deferred, or Outstanding.
   - Note any Deferred/Outstanding items and recommend whether to proceed to `/plan` or revisit `/clarify` later.
   - Suggest the next command.

Behavior notes:
- If no impactful ambiguities remain, reply: "No critical ambiguities detected worth formal clarification." Provide a concise coverage summary and suggest the next action.
- If `FEATURE_SPEC` is missing, instruct the user to run `/specify` first.
- Respect early termination commands ("stop", "done") and warn that unasked questions may carry risk.
- Do not exceed the 5-question total cap.
- Only request clarifications that materially influence stabilizing the automation app.
