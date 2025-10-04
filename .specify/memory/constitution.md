<!--
Sync Impact Report:
Version change: 1.0.0 → 1.1.0
Modified principles: N/A
Added sections: Principle VI (Code & Artifact Hygiene), Cleanup Standards subsection
Removed sections: N/A
Templates requiring updates:
  ✅ plan-template.md (Constitution Check section already generic)
  ✅ spec-template.md (No changes needed - requirements-focused)
  ✅ tasks-template.md (Cleanup tasks now aligned with Principle VI)
  ✅ agent-file-template.md (No changes needed - context tracking only)
Follow-up TODOs: None
-->

# Attacktest Security Framework Constitution

## Core Principles

### I. Security-First Testing (NON-NEGOTIABLE)
Every security test MUST be designed to identify real vulnerabilities, not just validate expected behavior. Tests must simulate actual attack scenarios and produce actionable security findings. All test results must be documented with clear evidence and remediation guidance.

### II. Automation-Driven Discovery
Security testing MUST be automated wherever possible to ensure consistent, repeatable vulnerability discovery. Manual testing is reserved for complex scenarios that cannot be automated. All automated tests must be version-controlled and executable in isolated environments.

### III. Evidence-Based Reporting (NON-NEGOTIABLE)
Every security finding MUST be backed by concrete evidence: captured tokens, network traffic, code analysis results, or exploit demonstrations. Reports must include proof-of-concept code, reproduction steps, and clear impact assessment. No security claim without verifiable evidence.

### IV. Multi-Vector Analysis
Security testing MUST cover multiple attack vectors: network traffic interception, application code analysis, runtime behavior monitoring, and API endpoint testing. Single-vector testing is insufficient for comprehensive security assessment.

### V. Reproducible Test Environment
All security tests MUST be executable in controlled, reproducible environments. Test environments must be isolated, version-controlled, and documented. Tests must produce consistent results across different execution contexts.

### VI. Code & Artifact Hygiene (NON-NEGOTIABLE)
The codebase and project structure MUST remain clean, organized, and maintainable. Obsolete scripts, duplicate experiments, and temporary artifacts MUST be removed proactively. When technical debt or folder clutter accumulates, the system MUST prompt for cleanup approval before proceeding with new features. Working scripts and verified evidence take precedence over experimental code.

**Rationale**: Security testing generates extensive artifacts (captures, logs, PoCs, reports). Without disciplined hygiene, the signal-to-noise ratio degrades, making it difficult to identify working exploits, reproduce findings, or maintain automation. Clean code enables rapid iteration and reduces operational risk.

## Security Testing Framework

### Test Categories
- **Network Security**: Traffic interception, SSL/TLS analysis, API security testing
- **Application Security**: Code analysis, vulnerability scanning, runtime monitoring
- **Authentication Security**: Token capture, session management, privilege escalation
- **Data Security**: Encryption analysis, data leakage detection, storage security

### Automation Standards
- **Frida Integration**: All dynamic analysis MUST use Frida for runtime hooking and monitoring
- **Traffic Capture**: Network analysis MUST use mitmproxy or equivalent for traffic interception
- **Code Analysis**: Static analysis MUST use multiple tools (MobSF, QARK, AndroBugs) for comprehensive coverage
- **Evidence Collection**: All findings MUST be captured in structured JSON format with timestamps

## Evidence Management

### Documentation Requirements
- **Capture Logs**: All security tests MUST generate detailed logs with ISO timestamps
- **Structured Output**: Test results MUST be stored in both human-readable and machine-parseable formats
- **Version Control**: All test scripts, hooks, and evidence MUST be version-controlled
- **Artifact Preservation**: Test artifacts MUST be preserved for audit and reproduction

### Reporting Standards
- **Executive Summary**: High-level findings with business impact
- **Technical Details**: Step-by-step reproduction instructions
- **Proof of Concept**: Working exploit code or demonstration
- **Remediation Guidance**: Specific recommendations for vulnerability mitigation

### Cleanup Standards
- **Obsolete Script Removal**: Deprecated or superseded test scripts MUST be deleted, not commented out
- **Experiment Isolation**: Exploratory code MUST reside in clearly marked directories (e.g., `experiments/`, `drafts/`) separate from production automation
- **Duplicate Detection**: Redundant captures, logs, or reports MUST be consolidated or archived
- **Proactive Prompts**: When 3+ obsolete files or 2+ duplicate workflows are detected, request cleanup approval before new feature work

## Development Workflow

### Test Development Process
1. **Threat Modeling**: Identify potential attack vectors before test development
2. **Test Design**: Create automated tests that simulate real attack scenarios
3. **Evidence Collection**: Implement comprehensive logging and artifact capture
4. **Validation**: Verify tests produce consistent, actionable results
5. **Documentation**: Document findings with clear remediation guidance
6. **Cleanup Review**: Remove temporary files and obsolete experiments after validation

### Quality Gates
- **Test Coverage**: All identified attack vectors must have corresponding automated tests
- **Evidence Quality**: All security findings must include verifiable proof
- **Reproducibility**: All tests must produce consistent results across multiple runs
- **Documentation**: All findings must be documented with clear remediation steps
- **Code Hygiene**: Working directory must contain only active scripts and verified evidence

## Governance

This constitution supersedes all other testing practices. Amendments require documentation of security impact, approval from security team, and migration plan for existing tests. All security test development must verify compliance with these principles. Complexity in test design must be justified by security value. Use existing security analysis tools and frameworks as guidance for implementation.

**Version**: 1.1.0 | **Ratified**: 2025-10-04 | **Last Amended**: 2025-10-04
