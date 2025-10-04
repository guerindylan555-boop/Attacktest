# Automation Archive

This directory tracks deprecated modules and scripts that remain in the
repository for reference while active development migrates toward the new
`automation/session`, `automation/replay`, and `automation/ui_catalog`
packages.

## Contents
- `sessions/` – stub for the previous restart/replay implementation. All new
  work must target `automation/session/` and may remove this archive once older
  branches stop importing `automation.sessions`.

Add additional subdirectories here as legacy components are relocated from the
main automation tree.
