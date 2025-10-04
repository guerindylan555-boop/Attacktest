# Data Model: Automation App Stabilization

## SessionState
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique identifier for a restart/replay session |
| status | Enum(`idle`,`restarting`,`ready`,`replay_running`,`error`) | Current lifecycle stage |
| started_at | datetime | Timestamp when the session began |
| updated_at | datetime | Last heartbeat received |
| app_pid | Optional[int] | Process ID reported by Appium/ADB |
| readiness_checks | List[`ReadinessCheck`] | Results for UI, hook, metrics probes |
| error | Optional[`SessionError`] | Structured failure information |

### ReadinessCheck (embedded)
| Field | Type | Description |
|-------|------|-------------|
| name | str | Check identifier (e.g., `login_ui`, `frida_hook`, `metrics_endpoint`) |
| status | Enum(`pass`,`fail`,`warn`) | Outcome of the probe |
| details | str | Additional context/log snippet |
| checked_at | datetime | Time check was performed |

### SessionError (embedded)
| Field | Type | Description |
|-------|------|-------------|
| code | str | Machine-readable error code |
| message | str | Human explanation for operators |
| remediation | str | Suggested corrective action |

### State Transitions
```
idle ──(restart requested)──▶ restarting
restarting ──(all readiness_checks pass)──▶ ready
restarting ──(timeout or failure)──▶ error
ready ──(replay started)──▶ replay_running
replay_running ──(replay complete & validated)──▶ ready
replay_running ──(drift detected)──▶ error
error ──(operator acknowledges & restart)──▶ restarting
```

## ReplayScript
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique script identifier |
| name | str | Human-friendly name (e.g., `admin-escalation-happy-path`) |
| version | str | Semantic version (major changes when steps differ) |
| steps | List[`ReplayStep`] | Ordered interactions captured from recording |
| created_at | datetime | Time script was recorded |
| updated_at | datetime | Last modification |
| golden_trace | `GoldenTrace` | Expected telemetry for validation |

### ReplayStep
| Field | Type | Description |
|-------|------|-------------|
| order | int | Step index |
| element_label | str | Reference into `UICatalogEntry.label` |
| action | Enum(`tap`,`long_press`,`text_input`,`scroll`) | Interaction type |
| value | Optional[str] | Payload (e.g., text string) |
| expected_screen | str | Screenshot hash or identifier for context |
| timestamp_offset_ms | int | Milliseconds since replay start |
| coordinate | `Coordinate` | Expected tap coordinates |

### Coordinate
| Field | Type | Description |
|-------|------|-------------|
| x | float | X coordinate normalized 0.0-1.0 |
| y | float | Y coordinate normalized 0.0-1.0 |
| tolerance_px | int | Allowed pixel deviation (default 10) |

### GoldenTrace
| Field | Type | Description |
|-------|------|-------------|
| log_digest | str | Hash of expected structured log sequence |
| metrics_snapshot | Dict[str, float] | Expected metric values post replay |
| replay_duration_ms | int | Expected total runtime |

## UICatalogEntry
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Internal identifier |
| label | str | Human-readable, stable label (e.g., `login.submit_button`) |
| selectors | Dict[str, str] | Locator map (Appium accessibility id, XPath, etc.) |
| hierarchy_path | str | Serialized widget path in view tree |
| screenshot_path | str | Relative path to stored PNG asset |
| metadata | Dict[str, Any] | Additional attributes (visibility, enabled state, etc.) |
| last_validated_at | datetime | Timestamp of last automated validation |
| sensitive | bool | Marks entries requiring redaction |

## UICatalogVersion
| Field | Type | Description |
|-------|------|-------------|
| version | str | Semantic version for catalog release |
| generated_at | datetime | Time catalog export occurred |
| json_path | str | Location of JSON catalog artifact |
| yaml_path | str | Location of YAML catalog artifact |
| device_profile | str | Emulator/device profile name |
| replay_scripts | List[`ReplayScript.id`] | Scripts validated against this catalog |
| notes | str | Operator notes or migration guidance |

## Relationships
- `SessionState` references zero or one `ReplayScript` during `replay_running`.
- `ReplayScript.steps[].element_label` must exist in the active `UICatalogEntry.label` set for validation.
- `UICatalogVersion.replay_scripts` lists scripts verified post-export, ensuring catalog and replay stay in sync.
- Catalog exports trigger session transitions (`ready` → `replay_running` → `ready`) to re-validate key flows.

## Data Storage & Lifecycle
- Catalog artifacts stored under `automation/ui_catalog/exports/{version}/` with both JSON and YAML plus screenshots; sensitive fields encrypted using repo-standard key.
- Golden traces stored in `automation/replay/traces/{replay_script.version}.json` with checksums to detect drift.
- Session logs flushed to `automation/logs/{session_id}.jsonl` for audit and observability pipelines.
- Retention policy: keep last 5 catalog versions and associated traces; archive older ones to `automation/archive/` with README annotations.
