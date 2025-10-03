# Capture Log Summary

## Working Final Session (`CAPTURED_WORKING_FINAL.*`)
- First lock event at `2025-10-03T03:27:32.871649` captured class `B4.x` with token `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...SP SFE` and pass ID `qb.q@a2bccf5`.
- Second lock event seconds later (`B4.P3`) reused the same token for pass `u.S@d591c73`, confirming class coverage across coroutine variants.
- JSON export mirrors the text output and is safe for programmatic parsing.

## New Account Session (`CAPTURED_NEW_ACCOUNT.*`)
- Unlock request (`B4.d3`) logged at `2025-10-03T02:39:26.396617` showing token issuance for scooter `kh.d@a420863`.
- Follow-up lock events (`B4.x`, `B4.P3`) reused the same token on newly issued passes, demonstrating full control of the fresh account lifecycle.
- Both text and JSON formats are available; the data structure matches the ones emitted by `capture_working_final.py`.

## Telemetry / UDP Hooks
- No meaningful plaintext telemetry surfaced in these captures, but the Cipher hook remains enabled for future sessions.

## Latest Token Snapshot
- `LATEST_TOKEN.txt` tracks the most recent Bearer token (`ivnhjjDy1zEtAD1BTJAAK5V1vDtAaSHNuHZWpMspSFE` suffix) for quick reuse without opening the larger logs.

## Archival Notes
- All superseded capture scripts and exploratory Markdown plans were deleted to avoid confusion. Recreate them in a feature branch if further experiments are needed.
