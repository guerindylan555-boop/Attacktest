# Research Findings: Automation App Stabilization

## 1. Emulator Restart & Clean State Strategy
- **Decision**: Use Appium driver commands (`terminate_app`, `activate_app`) augmented with ADB shell fallback and snapshot restore to guarantee emulator-only support.
- **Rationale**: Appium maintains session context and surfaces exceptions, letting us mark restart failures before replay begins; ADB fallback handles hung processes.
- **Alternatives Considered**:
  - Pure ADB scripts: too brittle and silent on failures.
  - Full emulator reboot: exceeds 30 s budget and disrupts Frida attachments.

## 2. Health Probes & Session Readiness
- **Decision**: Define a `SessionState` poller that checks (a) Appium accessibility of login screen selectors, (b) Frida hook heartbeat, and (c) control-center metrics endpoint before declaring `ready`.
- **Rationale**: Combining UI availability with instrumentation assures hooks survived restart and prevents replay drift caused by missing contexts.
- **Alternatives Considered**:
  - Single UI selector check: misses hook failures.
  - Manual operator confirmation: slows automation and violates determinism.

## 3. Replay Drift Measurement
- **Decision**: Persist golden traces containing element labels, screen coordinates, and timestamps; validate runtime replays within ±250 ms timing and ±10 px spatial tolerance per step.
- **Rationale**: Aligns with clarified tolerance, allowing minor rendering jitter while flagging meaningful divergence; coordinates guard against layout shifts.
- **Alternatives Considered**:
  - Timing-only checks: cannot detect mis-clicks caused by layout drift.
  - Pixel-perfect screenshots: heavy storage + flakey on animations.

## 4. Dual-Format UI Catalog Exports
- **Decision**: Generate both JSON (machine consumption) and YAML (review-friendly) catalogs from a single pydantic model; encrypt sensitive node data before disk writes.
- **Rationale**: Satisfies downstream tooling and human reviewers, while constituting evidence for constitutional Principle IV (evidence-driven) and Principle III (security-first).
- **Alternatives Considered**:
  - JSON only: harder manual diffing.
  - YAML only: brittle for tooling.

## 5. Observability & Metrics
- **Decision**: Instrument restart/replay/discovery services with structured logging (`loguru` or standard logging + JSON formatter) and Prometheus-style counters/gauges exposed via local HTTP endpoint.
- **Rationale**: Provides evidence for golden-path health reports and enables automated regression checks, directly supporting constitutional observability mandates.
- **Alternatives Considered**:
  - Print/debug logs: lack machine readability.
  - External SaaS telemetry: conflicts with offline constraint.

## 6. Repository Hygiene & Folder Cleanup
- **Decision**: Move stale scripts into `automation/archive/` with README note, introduce module-specific READMEs, and document catalog storage location in root README.
- **Rationale**: Keeps actively maintained automation focused while respecting Principle V and easing onboarding.
- **Alternatives Considered**:
  - Leave legacy scripts in place: increases drift and operator confusion.
  - Delete immediately: risks losing historical context before migration.
