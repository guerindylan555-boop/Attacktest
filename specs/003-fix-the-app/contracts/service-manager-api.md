# ServiceManager Internal API Contract

**Component**: `automation.services.service_manager.ServiceManager`  
**Purpose**: Manage lifecycle of background services (emulator, proxy, Frida) with retry logic

## Methods

### `start_all_services() -> dict`

**Description**: Start all managed services automatically with retry logic.

**Preconditions**:
- None (safe to call multiple times)

**Behavior**:
1. Start services in dependency order: emulator → proxy → frida
2. For each service:
   - Attempt start via `_start_service(name)`
   - If fails and `should_retry()` returns True: wait `retry_delay` seconds, retry
   - Repeat up to `max_retries` times
   - Track `retry_count` and `last_retry_at` in ServiceStatus
3. Aggregate results into ServiceManagerSnapshot

**Returns**:
```python
{
    "status": "success" | "partial" | "failed",
    "snapshot": ServiceManagerSnapshot,
    "started_services": ["emulator", "proxy"],  # names of services that started
    "failed_services": ["frida"]  # names of services that failed after retries
}
```

**Postconditions**:
- All services attempted start (may be in `running` or `failed` state)
- ServiceStatus objects updated with retry counts and errors
- `snapshot.all_ready == True` if all services running

**Performance**:
- Max duration: 90s (timeout) * 3 (services) * 3 (retries) = ~810s worst case
- Typical: 60-90s for clean startup

---

### `_start_service(service_name: str) -> ServiceStatus | dict`

**Description**: Start a single service with health check.

**Parameters**:
- `service_name`: One of `"emulator"`, `"proxy"`, `"frida"`

**Behavior**:
1. Call `ServiceStatus.begin_start_attempt()` to set state to `starting`
2. Dispatch to service-specific starter:
   - `_start_emulator()`: Launch via shell script, wait for `adb devices` confirmation
   - `_start_proxy()`: Launch mitmdump, check port 8080 listening
   - `_start_frida()`: Launch Frida hook script with auto-attach
3. If successful: call `ServiceStatus.mark_running(pid, startup_time)`
4. If failed: call `ServiceStatus.mark_error(error_message)`

**Returns**:
- `ServiceStatus` object with updated state
- OR `dict` with `{"success": bool, "error": str, "pid": int}`

**Error Handling**:
- Catches all exceptions, stores in `error_message`
- Does NOT retry (caller handles retry logic)

---

### `_detect_running_services() -> dict[str, bool]`

**Description**: Check which services are already running (attach instead of start).

**Returns**:
```python
{
    "emulator": True,   # adb devices shows device
    "proxy": False,     # port 8080 not listening
    "frida": True       # frida-ps -U succeeds
}
```

**Behavior**:
- Emulator: check `adb devices` output for emulator-* device
- Proxy: check `netstat -tnlp | grep :8080`
- Frida: check if `frida-ps -U` returns without error

**Performance**: <2s (all checks run in parallel)

---

### `get_service_snapshot(refresh: bool = False) -> ServiceManagerSnapshot`

**Description**: Get current snapshot of all service statuses for UI consumption.

**Parameters**:
- `refresh`: If True, run health checks before returning snapshot

**Returns**:
```python
ServiceManagerSnapshot(
    timestamp="2025-10-04T14:32:01Z",
    services=[
        {"name": "emulator", "state": "running", "retry_count": 1, ...},
        {"name": "proxy", "state": "running", "retry_count": 0, ...},
        {"name": "frida", "state": "failed", "retry_count": 3, ...}
    ],
    all_ready=False,
    failed_services=["frida"],
    retry_in_progress=False
)
```

**Performance**: <1s without refresh, <3s with refresh

---

### `retry_service(service_name: str) -> dict`

**Description**: Manually retry a failed service (called from UI retry button).

**Parameters**:
- `service_name`: Name of service to retry

**Preconditions**:
- Service must be in `failed` state

**Behavior**:
1. Reset `retry_count` to 0
2. Call `_start_service(service_name)`
3. Apply retry logic (up to 3 attempts)

**Returns**:
```python
{
    "status": "success" | "failed",
    "service_status": ServiceStatus
}
```

---

## State Transitions

```
BEFORE start_all_services():
  emulator: state=pending, retry_count=0
  proxy: state=pending, retry_count=0
  frida: state=pending, retry_count=0

AFTER start_all_services() (emulator slow boot, frida fails):
  emulator: state=running, retry_count=1, startup_time=75.3
  proxy: state=running, retry_count=0, startup_time=2.1
  frida: state=failed, retry_count=3, error_message="App not found"

AFTER retry_service("frida"):
  frida: state=running, retry_count=1, startup_time=8.5
```

---

## Error Codes

| Error Code | Meaning | Retry Recommended? |
|------------|---------|-------------------|
| `"emulator_timeout"` | Emulator didn't boot in 90s | Yes (might be resource contention) |
| `"port_conflict"` | Proxy port 8080 already in use | No (user must fix) |
| `"app_not_found"` | MaynDrive APK not installed | No (user must install) |
| `"frida_server_missing"` | Frida server binary missing | No (user must deploy) |
| `"adb_offline"` | ADB daemon not running | Yes (might be transient) |

---

## Thread Safety

- All methods use `self._lock` (threading.Lock) to prevent concurrent modification
- Safe to call from Qt UI thread or background worker threads

---

## Testing Contract

Tests MUST verify:
1. ✅ `start_all_services()` respects dependency order (emulator before others)
2. ✅ Retry logic triggers correctly (3 attempts, 5s delays)
3. ✅ `_detect_running_services()` correctly identifies running services
4. ✅ Manual retry resets `retry_count` to 0
5. ✅ ServiceManagerSnapshot aggregates status correctly
6. ✅ Thread-safe under concurrent calls

