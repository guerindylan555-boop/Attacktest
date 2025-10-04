# Attacktest Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-10-04

## Active Technologies
- Python 3.9+ (existing codebase) + PySide6 (Qt GUI), subprocess, threading, QProcess (002-i-want-the)
- Python 3.10 (Ubuntu 22.04 default interpreter) + PySide6 for UI, subprocess/adb/tmux/mitmdump tooling, project-local automation scripts (002-i-want-the)
- Local JSON/flat files under `automation/recordings/` and `automation/sessions/` (002-i-want-the)
- Python 3.10 (Ubuntu 22.04 default interpreter) + PySide6 (Qt GUI), frida-tools, mitmproxy, subprocess, threading, QProcess (003-fix-the-app)
- Local JSON files in `automation/recordings/` and `automation/sessions/`, no database required (003-fix-the-app)

## Project Structure
```
src/
tests/
```

## Commands
cd src [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] pytest [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] ruff check .

## Code Style
Python 3.9+ (existing codebase): Follow standard conventions

## Recent Changes
- 003-fix-the-app: Added Python 3.10 (Ubuntu 22.04 default interpreter) + PySide6 (Qt GUI), frida-tools, mitmproxy, subprocess, threading, QProcess
- 002-i-want-the: Added Python 3.10 (Ubuntu 22.04 default interpreter) + PySide6 for UI, subprocess/adb/tmux/mitmdump tooling, project-local automation scripts
- 002-i-want-the: Added Python 3.9+ (existing codebase) + PySide6 (Qt GUI), subprocess, threading, QProcess

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
