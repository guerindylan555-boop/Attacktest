---
description: Ensure updates support a clean, maintainable vulnerability automation tool and highlight any folder cleanup needs.
---

The user input supplied directly or via command arguments **MUST** be read before acting.

Objective:
- Build or extend tooling that automates vulnerability testing and the discovery of new issues.
- Deliver clean, well-structured, and well-tested code changes.
- Audit the repository layout and propose folder cleanup or re-organization when it improves clarity or automation workflows.

Workflow:
1. **Clarify scope** by inspecting user prompts, existing docs, and repo context relevant to the requested automation feature.
2. **Design the solution** focusing on clean abstractions, predictable error handling, and security best practices.
3. **Assess the folder structure**; note dead code, duplicated utilities, or misplaced modules that hinder vulnerability tooling. Suggest concrete cleanup actions (rename, relocate, delete) with rationale.
4. **Implement or specify code updates** that align with the clean code design. Include tests, static analysis hooks, and documentation updates that prove the automation works.
5. **Validate** through available test suites or scripted checks. If execution is impossible, describe the verification steps the user should run.
6. **Summarize** the delivered changes alongside folder cleanup recommendations and next steps for expanding the automation surface.

Quality Guardrails:
- Keep code modular, typed when applicable, and compliant with the project's style guides.
- Prefer dependency injection and configuration-driven design to keep the automation adaptable to new vulnerability classes.
- Call out security-sensitive assumptions explicitly and document mitigations.
- Recommend CI or local scripts that continuously run the vulnerability discovery workflows.

Expected Output:
- A concise summary of implemented changes.
- Any proposed folder cleanup actions with justifications and risk notes.
- Testing or verification results (or instructions when tests cannot be run).
- Optional backlog ideas that extend automation coverage.
