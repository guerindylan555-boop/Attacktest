"""
TokenCaptureSession model for managing blhack user login automation and token extraction.
"""
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from automation.models.control_action import EvidenceArtifact


class SessionState(Enum):
    """Enumeration of possible session states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TokenCaptureSession:
    """Model for managing the blhack user login automation and token extraction process."""
    
    VALID_STATES = [state.value for state in SessionState]
    
    def __init__(self, session_id: Optional[str] = None, user_credentials: Optional[Dict[str, str]] = None):
        """Initialize a new token capture session.
        
        Args:
            session_id: Unique identifier for the capture session. 
                       If None, a new UUID will be generated.
            user_credentials: Login credentials for blhack user
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.start_time = datetime.now(timezone.utc).isoformat()
        self.end_time: Optional[str] = None
        self.status = SessionState.PENDING.value
        self.captured_tokens: List[str] = []
        self.user_credentials = user_credentials or {}
        self.capture_log: List[Dict[str, Any]] = []
        self.evidence_files: List[Dict[str, str]] = []
        self.failure_reason: Optional[str] = None
        self._process = None
    
    def start_capture(self) -> Dict[str, Any]:
        """Start the token capture session.
        
        Returns:
            Dict containing session start information.
        """
        if self.status != SessionState.PENDING.value:
            raise ValueError(f"Cannot start capture - session is {self.status}")
        
        self.status = SessionState.RUNNING.value
        self.start_time = datetime.now(timezone.utc).isoformat()

        # Add start event to log
        self.add_log_entry("session_started", "Token capture session started")
        
        return {
            "status": "success",
            "session_id": self.session_id,
            "start_time": self.start_time
        }
    
    def complete_capture(self, tokens: List[str]) -> Dict[str, Any]:
        """Complete the token capture session successfully.
        
        Args:
            tokens: List of captured authentication tokens
        
        Returns:
            Dict containing session completion information.
        """
        if self.status != SessionState.RUNNING.value:
            raise ValueError(f"Cannot complete capture - session is {self.status}")
        
        self.status = SessionState.COMPLETED.value
        self.end_time = datetime.now(timezone.utc).isoformat()
        self.captured_tokens = tokens

        # Add completion event to log
        self.add_log_entry("session_completed", f"Token capture completed with {len(tokens)} tokens")
        
        return {
            "status": "success",
            "session_id": self.session_id,
            "tokens_captured": len(tokens),
            "end_time": self.end_time
        }
    
    def fail_capture(self, error_message: str) -> Dict[str, Any]:
        """Mark the token capture session as failed.
        
        Args:
            error_message: Description of the failure
        
        Returns:
            Dict containing session failure information.
        """
        if self.status != SessionState.RUNNING.value:
            raise ValueError(f"Cannot fail capture - session is {self.status}")
        
        self.status = SessionState.FAILED.value
        self.end_time = datetime.now(timezone.utc).isoformat()
        self.failure_reason = error_message

        # Add failure event to log
        self.add_log_entry("session_failed", f"Token capture failed: {error_message}")
        
        return {
            "status": "failed",
            "session_id": self.session_id,
            "error": error_message,
            "end_time": self.end_time
        }
    
    def add_log_entry(self, event_type: str, message: str, **kwargs) -> None:
        """Add an entry to the capture log.
        
        Args:
            event_type: Type of event (session_started, token_captured, etc.)
            message: Log message
            **kwargs: Additional log data
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "message": message,
            **kwargs
        }

        self.capture_log.append(log_entry)
    
    def add_token_captured(self, token: str, source: str = "unknown") -> None:
        """Add a captured token to the session.

        Args:
            token: The captured token
            source: Source of the token (api, network, etc.)
        """
        self.captured_tokens.append(token)
        self.add_log_entry("token_captured", f"Token captured from {source}", token=token[:10] + "...")

    def register_evidence(self, path: Path, artifact_type: str, *, digest: Optional[str] = None) -> EvidenceArtifact:
        """Record an evidence file emitted during the session."""

        artifact = EvidenceArtifact(path=path, artifact_type=artifact_type, related_id=self.session_id, digest=digest)
        self.evidence_files.append(artifact.to_dict())
        self.add_log_entry("evidence_registered", f"Evidence stored: {path}", artifact_type=artifact_type)
        return artifact
    
    def add_automation_step(self, step: str, success: bool, details: str = "") -> None:
        """Add an automation step to the log.
        
        Args:
            step: Name of the automation step
            success: Whether the step was successful
            details: Additional details about the step
        """
        self.add_log_entry("automation_step", f"Step '{step}': {'SUCCESS' if success else 'FAILED'}", 
                          step=step, success=success, details=details)
    
    def is_pending(self) -> bool:
        """Check if session is pending.
        
        Returns:
            True if session status is pending, False otherwise.
        """
        return self.status == SessionState.PENDING.value
    
    def is_running(self) -> bool:
        """Check if session is running.
        
        Returns:
            True if session status is running, False otherwise.
        """
        return self.status == SessionState.RUNNING.value
    
    def is_completed(self) -> bool:
        """Check if session is completed.
        
        Returns:
            True if session status is completed, False otherwise.
        """
        return self.status == SessionState.COMPLETED.value
    
    def is_failed(self) -> bool:
        """Check if session is failed.
        
        Returns:
            True if session status is failed, False otherwise.
        """
        return self.status == SessionState.FAILED.value
    
    def get_duration(self) -> Optional[float]:
        """Get session duration in seconds.
        
        Returns:
            Duration in seconds if session has ended, None otherwise.
        """
        if not self.end_time:
            return None
        
        start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
        return (end - start).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary format.
        
        Returns:
            Dict representation of the session.
        """
        result = {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "status": self.status,
            "captured_tokens": self.captured_tokens,
            "user_credentials": self.user_credentials,
            "capture_log": self.capture_log,
            "evidence_files": self.evidence_files,
        }

        if self.end_time:
            result["end_time"] = self.end_time
        if self.failure_reason:
            result["failure_reason"] = self.failure_reason

        return result
    
    def save_to_file(self, sessions_dir: Path = None) -> Path:
        """Save session to JSON file.
        
        Args:
            sessions_dir: Directory to save the session file.
                        Defaults to automation/sessions/
        
        Returns:
            Path to the saved file.
        """
        if sessions_dir is None:
            sessions_dir = Path("automation/sessions")
        
        sessions_dir.mkdir(exist_ok=True)
        
        # Create filename: {timestamp}_token_capture_{session_id}.json
        timestamp_str = self.start_time.replace(":", "").replace("-", "").replace("T", "_").split(".")[0]
        filename = f"{timestamp_str}_token_capture_{self.session_id}.json"
        file_path = sessions_dir / filename
        
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        
        return file_path
    
    @classmethod
    def load_from_file(cls, file_path: Path) -> 'TokenCaptureSession':
        """Load session from JSON file.
        
        Args:
            file_path: Path to the session file.
        
        Returns:
            TokenCaptureSession instance loaded from file.
        """
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        session = cls(session_id=data["session_id"], user_credentials=data.get("user_credentials", {}))
        session.start_time = data.get("start_time", session.start_time)
        session.end_time = data.get("end_time")
        session.status = data.get("status", SessionState.PENDING.value)
        session.captured_tokens = data.get("captured_tokens", [])
        session.capture_log = data.get("capture_log", [])
        session.evidence_files = data.get("evidence_files", [])
        session.failure_reason = data.get("failure_reason")

        return session
    
    @classmethod
    def list_sessions(cls, sessions_dir: Path = None) -> List[Path]:
        """List all available session files.
        
        Args:
            sessions_dir: Directory to search for sessions.
                        Defaults to automation/sessions/
        
        Returns:
            List of Path objects for session files.
        """
        if sessions_dir is None:
            sessions_dir = Path("automation/sessions")
        
        if not sessions_dir.exists():
            return []
        
        # Find all files matching the pattern
        pattern = "*_token_capture_*.json"
        return list(sessions_dir.glob(pattern))
    
    def validate(self) -> bool:
        """Validate session data integrity.
        
        Returns:
            True if session is valid, False otherwise.
        """
        # Check required fields
        if not self.session_id or not self.start_time or not self.status:
            return False
        
        # Validate status
        if self.status not in self.VALID_STATES:
            return False
        
        # Validate timestamp format
        try:
            datetime.fromisoformat(self.start_time.replace('Z', '+00:00'))
        except ValueError:
            return False
        
        # Validate end_time if present
        if self.end_time:
            try:
                datetime.fromisoformat(self.end_time.replace('Z', '+00:00'))
            except ValueError:
                return False
            
            # end_time should be after start_time
            start = datetime.fromisoformat(self.start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(self.end_time.replace('Z', '+00:00'))
            if end <= start:
                return False
        
        # Validate captured_tokens
        if not isinstance(self.captured_tokens, list):
            return False
        
        # If status is completed, should have tokens
        if self.status == SessionState.COMPLETED.value and not self.captured_tokens:
            return False

        # Validate capture_log
        if not isinstance(self.capture_log, list):
            return False

        for log_entry in self.capture_log:
            if not isinstance(log_entry, dict):
                return False
            if "timestamp" not in log_entry or "event_type" not in log_entry or "message" not in log_entry:
                return False

        if not isinstance(self.evidence_files, list):
            return False

        return True
    
    def __str__(self) -> str:
        """String representation of the session."""
        return f"TokenCaptureSession(id={self.session_id}, status={self.status}, tokens={len(self.captured_tokens)})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the session."""
        return f"TokenCaptureSession(session_id='{self.session_id}', status='{self.status}', start_time='{self.start_time}')"
