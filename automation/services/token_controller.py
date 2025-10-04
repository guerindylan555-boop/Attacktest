"""
TokenCaptureController class for managing token capture automation.
"""
import subprocess
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from automation.models.control_action import ControlActionState, EvidenceArtifact
from automation.models.service_status import ServiceState
from automation.models.token_session import TokenCaptureSession
from automation.services.service_manager import ServiceManager


class TokenCaptureController:
    """Controls token capture automation using blhack user login."""
    
    def __init__(self, service_manager: Optional[ServiceManager] = None):
        """Initialize the token capture controller.
        
        Args:
            service_manager: ServiceManager instance for checking service status
        """
        self.service_manager = service_manager or ServiceManager()
        self.current_session: Optional[TokenCaptureSession] = None
        self._lock = threading.Lock()
        self._action_state = ControlActionState.ready(
            "capture_token", requires={"emulator", "frida"}
        )
        self._evidence: List[EvidenceArtifact] = []
    
    def start_token_capture(self) -> Dict[str, Any]:
        """Start token capture session.
        
        Returns:
            Dict containing session start information.
        """
        with self._lock:
            # Check if already capturing
            if self.current_session is not None:
                return {
                    "status": "error",
                    "error": "Token capture already in progress",
                    "reason": "already_capturing",
                    "ui_state": self._action_state.to_dict(),
                }

            snapshot = self.service_manager.get_service_snapshot(refresh=True)
            missing = self._missing_services(snapshot)
            if missing:
                state = self._state_for_snapshot(snapshot)
                return {
                    "status": "error",
                    "error": "Required services are not ready",
                    "reason": "services_not_ready",
                    "services": snapshot["services"],
                    "ui_state": state.to_dict(),
                }

            credentials = self._get_blhack_credentials()
            if not credentials:
                state = ControlActionState.disabled(
                    "capture_token",
                    reason="Blhack credentials missing",
                    requires=self._action_state.requires_services,
                )
                self._action_state = state
                return {
                    "status": "error",
                    "error": "Blhack user credentials not found",
                    "reason": "credentials_missing",
                    "ui_state": state.to_dict(),
                }
            
            try:
                # Create new session
                self.current_session = TokenCaptureSession(user_credentials=credentials)
                result = self.current_session.start_capture()
                self._action_state.mark_started()
                
                # Start capture in background thread
                capture_thread = threading.Thread(
                    target=self._execute_token_capture,
                    args=(self.current_session,)
                )
                capture_thread.daemon = True
                capture_thread.start()
                
                result["ui_state"] = self._action_state.to_dict()
                return result
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "reason": "capture_start_failed",
                    "ui_state": self._action_state.to_dict(),
                }
    
    def complete_token_capture(self, session_id: str, tokens: List[str]) -> Dict[str, Any]:
        """Complete token capture session.
        
        Args:
            session_id: ID of the session to complete
            tokens: List of captured tokens
        
        Returns:
            Dict containing session completion information.
        """
        with self._lock:
            if self.current_session is None or self.current_session.session_id != session_id:
                return {
                    "status": "error",
                    "error": "No matching session found",
                    "reason": "session_not_found",
                    "ui_state": self._action_state.to_dict(),
                }
            
            try:
                # Complete the session
                result = self.current_session.complete_capture(tokens)
                
                # Save session to file
                file_path = self.current_session.save_to_file()
                result["file_path"] = str(file_path)
                
                # Save evidence to project root (constitution requirement)
                evidence = self._save_evidence_files(tokens, session_id)
                result["evidence"] = [item.to_dict() for item in evidence]
                
                # Clear current session
                self.current_session = None
                self._action_state.mark_completed()
                result["ui_state"] = self._action_state.to_dict()
                
                return result
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "reason": "capture_completion_failed",
                    "ui_state": self._action_state.to_dict(),
                }
    
    def _get_blhack_credentials(self) -> Optional[Dict[str, str]]:
        """Get blhack user credentials.
        
        Returns:
            Dict containing credentials if found, None otherwise.
        """
        # In a real implementation, this would read from secure storage
        # For now, return default blhack credentials
        return {
            "username": "blhack",
            "password": "blhack_password"  # This should be stored securely
        }
    
    def _execute_token_capture(self, session: TokenCaptureSession) -> None:
        """Execute the token capture process.
        
        Args:
            session: Token capture session
        """
        try:
            # Run the existing capture script
            result = self._run_capture_script()
            
            if result["success"]:
                # Extract tokens from the result
                tokens = result.get("tokens", [])
                
                # Complete the session
                with self._lock:
                    if self.current_session and self.current_session.session_id == session.session_id:
                        self.complete_token_capture(session.session_id, tokens)
            else:
                # Mark session as failed
                with self._lock:
                    if self.current_session and self.current_session.session_id == session.session_id:
                        self.current_session.fail_capture(result["error"])
                        self.current_session = None
                        
        except Exception as e:
            # Mark session as failed
            with self._lock:
                if self.current_session and self.current_session.session_id == session.session_id:
                    self.current_session.fail_capture(str(e))
                    self._action_state.mark_completed()
                    self.current_session = None
    
    def _run_capture_script(self) -> Dict[str, Any]:
        """Run the existing capture script.
        
        Returns:
            Dict containing script execution result.
        """
        try:
            # Run the existing capture_working_final.py script
            process = subprocess.Popen([
                "python3", "capture_working_final.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if process.returncode == 0:
                # Parse the output to extract tokens
                tokens = self._parse_captured_tokens(stdout)
                
                return {
                    "success": True,
                    "tokens": tokens,
                    "output": stdout
                }
            else:
                return {
                    "success": False,
                    "error": stderr or "Script execution failed",
                    "output": stdout
                }
                
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                "success": False,
                "error": "Script execution timeout"
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "capture_working_final.py not found"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _parse_captured_tokens(self, output: str) -> List[str]:
        """Parse captured tokens from script output.
        
        Args:
            output: Script output text
        
        Returns:
            List of captured tokens.
        """
        tokens = []
        
        # Look for common token patterns in the output
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Look for JSON files with tokens
            if "CAPTURED_" in line and ".json" in line:
                try:
                    # Try to read the JSON file
                    file_path = Path(line.split()[-1])  # Assume last word is the file path
                    if file_path.exists():
                        import json
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            
                        # Extract tokens from the data
                        if isinstance(data, dict):
                            for key, value in data.items():
                                if "token" in key.lower() and isinstance(value, str):
                                    tokens.append(value)
                        elif isinstance(data, list):
                            tokens.extend([str(item) for item in data if isinstance(item, str)])
                except Exception:
                    continue
            
            # Look for token patterns in the line itself
            if "token" in line.lower() and len(line) > 20:
                # Extract potential token (basic heuristic)
                parts = line.split()
                for part in parts:
                    if len(part) > 20 and any(c.isalnum() for c in part):
                        tokens.append(part)
        
        return list(set(tokens))  # Remove duplicates
    
    def _save_evidence_files(self, tokens: List[str], session_id: str) -> List[EvidenceArtifact]:
        """Save evidence files to project root (constitution requirement).

        Args:
            tokens: List of captured tokens
            session_id: Session ID for file naming
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # Save as text file
        txt_file = Path(f"CAPTURED_TOKEN_{timestamp}_{session_id}.txt")
        with open(txt_file, 'w') as f:
            f.write(f"Token Capture Session: {session_id}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Tokens Captured: {len(tokens)}\n\n")
            for i, token in enumerate(tokens, 1):
                f.write(f"Token {i}: {token}\n")
        
        # Save as JSON file
        json_file = Path(f"CAPTURED_TOKEN_{timestamp}_{session_id}.json")
        import json
        with open(json_file, 'w') as f:
            json.dump({
                "session_id": session_id,
                "timestamp": timestamp,
                "tokens": tokens,
                "count": len(tokens)
            }, f, indent=2)

        artifacts = [
            EvidenceArtifact(path=json_file, artifact_type="token_json", related_id=session_id),
            EvidenceArtifact(path=txt_file, artifact_type="token_text", related_id=session_id),
        ]
        for artifact in artifacts:
            self._evidence.append(artifact)
            if self.current_session:
                self.current_session.register_evidence(Path(artifact.path), artifact.artifact_type)

        return artifacts

    def _state_for_snapshot(self, snapshot: Dict[str, Any]) -> ControlActionState:
        state = self._action_state
        if state.in_progress:
            return state
        missing = self._missing_services(snapshot)
        if missing:
            reason = self._disabled_reason(snapshot, missing)
            state = ControlActionState.disabled(
                "capture_token",
                reason=reason,
                requires=self._action_state.requires_services,
            )
        else:
            state = ControlActionState.ready(
                "capture_token", requires=self._action_state.requires_services
            )
        self._action_state = state
        return state

    def _missing_services(self, snapshot: Dict[str, Any]) -> List[str]:
        service_lookup = {entry["name"]: entry for entry in snapshot["services"]}
        missing: List[str] = []
        for name in self._action_state.requires_services:
            entry = service_lookup.get(name)
            if not entry or entry.get("status") != ServiceState.RUNNING.value:
                missing.append(name)
        return missing

    def _disabled_reason(self, snapshot: Dict[str, Any], missing: List[str]) -> str:
        service_lookup = {entry["name"]: entry for entry in snapshot["services"]}
        messages: List[str] = []
        for name in missing:
            entry = service_lookup.get(name, {})
            if entry.get("error_message"):
                messages.append(entry["error_message"])
            else:
                messages.append(f"{name} status: {entry.get('status', 'unknown')}")
        return "; ".join(messages) or "Services not ready"

    def get_action_state(self) -> Dict[str, Any]:
        snapshot = self.service_manager.get_service_snapshot(refresh=True)
        state = self._state_for_snapshot(snapshot)
        return {"action": state.to_dict(), "services": snapshot["services"]}

    def get_evidence_catalog(self) -> List[Dict[str, Any]]:
        return [artifact.to_dict() for artifact in self._evidence]
    
    def is_capturing(self) -> bool:
        """Check if currently capturing tokens.
        
        Returns:
            True if capture is in progress, False otherwise.
        """
        return self.current_session is not None
    
    def get_current_session_id(self) -> Optional[str]:
        """Get the ID of the current session.
        
        Returns:
            Session ID if capturing, None otherwise.
        """
        if self.current_session:
            return self.current_session.session_id
        return None
    
    def list_available_sessions(self) -> List[Dict[str, Any]]:
        """List all available token capture sessions.
        
        Returns:
            List of session information.
        """
        sessions = []
        session_files = TokenCaptureSession.list_sessions()
        
        for file_path in session_files:
            try:
                session = TokenCaptureSession.load_from_file(file_path)
                sessions.append({
                    "session_id": session.session_id,
                    "start_time": session.start_time,
                    "end_time": session.end_time,
                    "status": session.status,
                    "tokens_count": len(session.captured_tokens),
                    "file_path": str(file_path)
                })
            except Exception as e:
                print(f"Error loading session {file_path}: {e}")
        
        return sessions
