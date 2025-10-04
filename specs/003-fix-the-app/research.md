# Phase 0: Research - Control Center Reliability Fixes

**Date**: 2025-10-04  
**Feature**: 003-fix-the-app

## Research Questions & Decisions

### 1. Service Startup Reliability Patterns

**Question**: What are best practices for managing dependent service startup with automatic retries in Python desktop applications?

**Decision**: Threading + Health Checks + Retry Backoff

**Rationale**:
- Use Python `threading` module to start services in background without blocking Qt GUI
- Implement health check polling after service start (check process alive, network ports, ADB device ready)
- Use exponential backoff (5s, 10s, 15s) for retries to handle transient failures (port conflicts, slow emulator boot)
- Maximum 3 retries per clarification answer prevents infinite loops

**Alternatives Considered**:
- **asyncio**: More complex for Qt integration; PySide6 already has QThread for async operations
- **No retries**: Original approach; fails too easily on transient issues
- **Fixed retry interval**: Less adaptive; 5-second delay is optimal for emulator boot checks

**Implementation Notes**:
- ServiceManager already uses `subprocess.Popen` for service processes
- Add `ServiceStatus.retry_count` field to track attempts
- Health checks: emulator=`adb devices`, proxy=`netstat -tnlp | grep 8080`, Frida=process poll

---

### 2. Frida Attach vs Spawn Mode

**Question**: Should Frida attach to running app or spawn new instance? Current code has both modes but unclear which is more reliable.

**Decision**: Attach mode with pre-launched app

**Rationale**:
- Spawn mode (`frida -f package`) conflicts with automatic app launch from emulator startup scripts
- Attach mode (`frida -n package`) works with already-running app, reducing race conditions
- Pre-launch app via ADB (`am start -n package/activity`) ensures app is ready before Frida attaches
- Current code in `run_hooks.py` already implements attach mode with `auto_launch=True` flag

**Alternatives Considered**:
- **Spawn only**: Cleaner but requires stopping existing app instance first (more fragile)
- **Always spawn**: Doesn't work if app is already open from user interaction
- **Hybrid with detection**: Current approach is already hybrid; just needs bug fixes for timing

**Implementation Notes**:
- Keep `run_hooks.run_frida(attach_mode=True, auto_launch=True)` as default
- Fix `is_app_running()` check to wait 2-3 seconds after launch before declaring success
- Add 5-second stabilization delay after Frida attach before marking service as ready

---

### 3. Recording Incremental Persistence Strategy

**Question**: How to implement continuous disk persistence after each interaction without excessive I/O overhead?

**Decision**: Append-only JSON Lines with atomic writes

**Rationale**:
- JSON Lines format (`.jsonl`): each line is self-contained JSON object, easy to append
- Use Python `with open(file, 'a')` in append mode with `flush()` after each write
- Atomic writes via `tempfile + os.rename()` only for final metadata file (summary)
- For 30-minute session at ~1 interaction/second = 1800 writes = ~180KB total (minimal overhead)

**Alternatives Considered**:
- **SQLite**: Overkill for simple append-only workflow; adds dependency
- **Full JSON rewrite**: Too slow; loses data if crash during write
- **Batched writes (every 10 interactions)**: Violates requirement for immediate persistence

**Implementation Notes**:
- Keep existing `AutomationRecording.to_dict()` for final JSON summary
- Add `AutomationRecording._append_interaction_to_disk(interaction)` method
- File format: `{timestamp}_automation_recording_{id}.jsonl` for incremental, `.json` for summary

---

### 4. Screen Refresh Performance (Qt QTimer)

**Question**: How to achieve 10 Hz screen refresh rate without blocking Qt event loop?

**Decision**: QTimer at 100ms with background QThread screen capture

**Rationale**:
- PySide6 `QTimer` with 100ms interval triggers exactly 10 Hz refresh
- Existing `ScreenCaptureWorker` already runs in QThread (non-blocking)
- ADB screen capture (`adb exec-out screencap -p`) takes ~50-80ms; 100ms interval safe
- Current code uses 500ms (`self.screen_timer.start(500)`); just change to `100`

**Alternatives Considered**:
- **30 FPS real-time streaming**: Too expensive; requires `screenrecord` subprocess (FR clarification chose 10 Hz)
- **1 Hz (1000ms)**: Too slow for interactive feel
- **Manual refresh only**: Defeats purpose of "live preview"

**Implementation Notes**:
- Change `control_center.py:self.screen_timer.start(500)` → `start(100)`
- No other changes needed; QThread worker already handles async capture
- Add performance logging to detect if ADB capture exceeds 100ms (warning condition)

---

### 5. Service State Management with Retry Awareness

**Question**: How to track service state through multiple retry attempts while keeping UI updated?

**Decision**: Retry-aware state machine in ServiceStatus model

**Rationale**:
- Extend existing ServiceStatus model with `retry_count`, `last_retry_at` timestamp fields
- States: `pending → starting → (retry_delay if failed) → starting → running`
- UI polls ServiceStatus every 500ms; can display "Retrying (2/3)" in tooltip/status text
- Existing `ServiceManagerSnapshot` already aggregates status for UI consumption

**Alternatives Considered**:
- **Separate retry tracker**: More complex; state split across two objects
- **Event-based updates**: Requires Qt signals/slots refactor; current polling works fine
- **No retry visibility**: User confused why startup takes 15+ seconds

**Implementation Notes**:
- Add fields to `ServiceStatus.__init__`: `max_retries=3`, `retry_delay=5.0`, `retry_count=0`
- Add method: `ServiceStatus.should_retry() -> bool` (check retry_count < max_retries)
- ServiceManager checks `should_retry()` before each attempt, updates `retry_count`, sleeps `retry_delay`

---

## Technology Stack Confirmation

| Component | Technology | Version | Rationale |
|-----------|------------|---------|-----------|
| Language | Python | 3.10 | Ubuntu 22.04 default; existing codebase |
| GUI Framework | PySide6 | 6.5+ | Qt for Python; cross-platform, mature |
| Service Management | subprocess | stdlib | Native process spawning; no extra deps |
| Threading | threading + QThread | stdlib + PySide6 | Non-blocking service ops, Qt integration |
| Android Tooling | ADB (platform-tools) | 34.0+ | Emulator control, screen capture |
| Dynamic Analysis | Frida | 16.0+ | Runtime hooking; existing in requirements.txt |
| Network Proxy | mitmproxy | 10.0+ | Traffic capture; existing in requirements.txt |
| Data Format | JSON / JSON Lines | stdlib | Human-readable, easy parsing, existing format |
| Testing | pytest | 8.0+ | Python standard; existing in pytest.ini |

No new dependencies required beyond existing requirements.txt. PySide6 must be added to requirements.txt.

---

## External Dependencies

### 1. Android Emulator
- **Provider**: Android SDK
- **Failure Mode**: Emulator won't boot → service startup fails after 90s timeout
- **Mitigation**: Retry logic (up to 3 attempts), health check via `adb devices`

### 2. ADB (Android Debug Bridge)
- **Provider**: Android SDK platform-tools
- **Failure Mode**: ADB server not running → cannot detect emulator or capture screen
- **Mitigation**: Auto-start ADB server via `adb start-server`, check via `adb version`

### 3. Frida Server (on-device)
- **Provider**: Manually installed on emulator (`/data/local/tmp/frida-server`)
- **Failure Mode**: Server not running → Frida attach fails
- **Mitigation**: ServiceManager checks and restarts Frida server via `adb shell`

### 4. MaynDrive APK
- **Provider**: Manually installed on emulator (`fr.mayndrive.app`)
- **Failure Mode**: App not installed → Frida cannot attach, recording useless
- **Mitigation**: ServiceManager checks via `adb shell pm list packages`, warns user

---

## Performance Targets Validation

| Target | Specification | Feasibility | Notes |
|--------|---------------|-------------|-------|
| Service Startup | <90s total | ✅ Achievable | Emulator boot ~60-70s dominates; retries add 15s max |
| Screen Refresh | 10 Hz (100ms) | ✅ Achievable | ADB screencap ~50-80ms; margin safe |
| Persistence Latency | <50ms/interaction | ✅ Achievable | File append + flush ~5-10ms; well within target |
| UI Responsiveness | Non-blocking | ✅ Achievable | QThread workers + threading module prevent GUI freeze |

All performance targets validated as achievable with chosen technologies.

---

## Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Emulator boot timeout | Medium | High | Retry logic (3x), 90s timeout per attempt |
| Frida attach race condition | Low | Medium | Pre-launch app, 5s stabilization delay |
| Disk full during recording | Low | Medium | Check free space before recording start |
| Screen capture exceeds refresh rate | Low | Low | Log warning, increase interval dynamically |
| Port conflict (proxy) | Medium | Medium | Detect via netstat, show clear error with port number |

Primary risk: Emulator boot reliability on resource-constrained systems. Mitigated by generous timeout and retry attempts.

---

## Conclusion

All technical unknowns resolved. Stack validated. Ready for Phase 1 (Design & Contracts).

