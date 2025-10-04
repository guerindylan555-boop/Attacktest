"""Automation controller orchestrating recordings and replays with retry-aware UI state."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import os
import subprocess

from automation.models.control_action import ControlActionState, EvidenceArtifact
from automation.models.recording import AutomationRecording
from automation.models.service_status import ServiceState
from automation.services.service_manager import ServiceManager


class AutomationController:
    """Controls recording and replaying of automation workflows."""

    ACTION_REQUIREMENTS: Dict[str, List[str]] = {
        "record": ["emulator", "proxy", "frida"],
        "replay": ["emulator", "proxy", "frida"],
        "capture_token": ["emulator", "frida"],
    }

    def __init__(self, service_manager: Optional[ServiceManager] = None) -> None:
        self.service_manager = service_manager or ServiceManager()
        self.recordings_dir = Path("automation/recordings")
        self.recordings_dir.mkdir(exist_ok=True)

        self.current_recording: Optional[AutomationRecording] = None
        self.current_replay: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._record_in_progress = False
        self._duration_timer: Optional[threading.Timer] = None

        self._actions: Dict[str, ControlActionState] = {
            action: ControlActionState.ready(action, requires=requirements)
            for action, requirements in self.ACTION_REQUIREMENTS.items()
        }
        self._evidence: List[EvidenceArtifact] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_action_states(self) -> Dict[str, Any]:
        snapshot = self.service_manager.get_service_snapshot(refresh=True)
        actions = [
            self._state_for_action(action, snapshot).to_dict()
            for action in self._actions
        ]
        return {"actions": actions, "services": snapshot["services"]}

    def start_recording(self) -> Dict[str, Any]:
        with self._lock:
            if self.current_recording is not None:
                state = self._actions["record"].to_dict()
                return {
                    "status": "error",
                    "error": "Recording already in progress",
                    "reason": "already_recording",
                    "ui_state": state,
                }

            snapshot = self._service_snapshot()
            blocking = self._missing_services("record", snapshot)
            if blocking:
                state = self._state_for_action("record", snapshot)
                return {
                    "status": "error",
                    "error": "Required services are not ready",
                    "reason": "services_not_ready",
                    "services": snapshot["services"],
                    "ui_state": state.to_dict(),
                }

            recording = AutomationRecording()
            result = recording.start_recording()
            self.current_recording = recording
            self._record_in_progress = True
            
            # Create incremental JSONL file for immediate persistence
            timestamp_str = recording.timestamp.replace(":", "").replace("-", "").replace("T", "_").split(".")[0]
            incremental_filename = f"{timestamp_str}_automation_recording_{recording.id}.jsonl"
            recording.incremental_file = self.recordings_dir / incremental_filename
            # Touch the file to create it
            recording.incremental_file.touch()
            
            # Start duration enforcement timer (check every 60 seconds)
            self._start_duration_timer()

            state = self._actions["record"]
            state.mark_started()
            self._actions["record"] = state

            payload = {
                "status": result["status"],
                "recording_id": result["recording_id"],
                "start_time": result["start_time"],
                "ui_state": state.to_dict(),
            }
            return payload

    def stop_recording(self, recording_id: str, *, display_name: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if (
                self.current_recording is None
                or self.current_recording.id != recording_id
            ):
                state = self._actions["record"].to_dict()
                return {
                    "status": "error",
                    "error": "No matching recording found",
                    "reason": "recording_not_found",
                    "ui_state": state,
                }

            result = self.current_recording.stop_recording()
            file_path = self.current_recording.save_to_file(self.recordings_dir, display_name=display_name)
            
            # Stop duration enforcement timer
            self._stop_duration_timer()
            self._record_in_progress = False

            artifact = EvidenceArtifact(
                path=file_path,
                artifact_type="recording",
                related_id=self.current_recording.id,
            )
            self._evidence.append(artifact)

            state = self._actions["record"]
            state.mark_completed()
            self._actions["record"] = state

            payload = {
                "status": result["status"],
                "recording_id": result["recording_id"],
                "duration": result["duration"],
                "interactions_count": result["interactions_count"],
                "file_path": str(file_path),
                "auto_stopped": self.current_recording.auto_stopped,
                "evidence": [artifact.to_dict()],
                "ui_state": state.to_dict(),
            }

            self.current_recording = None
            return payload

    def get_evidence_catalog(self) -> List[Dict[str, Any]]:
        """Return all recorded evidence artefacts for external reporting."""

        return [artifact.to_dict() for artifact in self._evidence]

    def replay_recording(self, recording_id: str) -> Dict[str, Any]:
        with self._lock:
            if self.current_replay is not None:
                return {
                    "status": "error",
                    "error": "Replay already in progress",
                    "reason": "already_replaying",
                    "ui_state": self._actions["replay"].to_dict(),
                }

            snapshot = self._service_snapshot()
            blocking = self._missing_services("replay", snapshot)
            if blocking:
                state = self._state_for_action("replay", snapshot)
                return {
                    "status": "error",
                    "error": "Required services are not ready",
                    "reason": "services_not_ready",
                    "services": snapshot["services"],
                    "ui_state": state.to_dict(),
                }

            recording_file = self._find_recording_file(recording_id)
            if not recording_file:
                state = self._state_for_action("replay", snapshot)
                return {
                    "status": "error",
                    "error": f"Recording {recording_id} not found",
                    "reason": "recording_not_found",
                    "ui_state": state.to_dict(),
                }

            recording = AutomationRecording.load_from_file(recording_file)
            replay_id = f"replay_{int(time.time())}"
            self.current_replay = {
                "replay_id": replay_id,
                "recording_id": recording_id,
                "recording": recording,
            }

            state = self._actions["replay"]
            state.mark_started()
            self._actions["replay"] = state

            thread = threading.Thread(
                target=self._execute_replay,
                args=(recording, replay_id),
                daemon=True,
            )
            thread.start()

            return {
                "status": "success",
                "replay_id": replay_id,
                "recording_id": recording_id,
                "start_time": time.time(),
                "ui_state": state.to_dict(),
            }

    def finalize_replay(self, replay_id: Optional[str] = None) -> None:
        with self._lock:
            if self.current_replay is None:
                return
            if replay_id and self.current_replay["replay_id"] != replay_id:
                return
            state = self._actions["replay"]
            state.mark_completed()
            self._actions["replay"] = state
            self.current_replay = None

    # ------------------------------------------------------------------
    # Existing helpers retained (replay execution, recordings list)
    # ------------------------------------------------------------------
    def list_available_recordings(self) -> List[Dict[str, Any]]:
        recording_files = AutomationRecording.list_recordings(self.recordings_dir)
        items: List[Dict[str, Any]] = []
        for path in recording_files:
            try:
                recording = AutomationRecording.load_from_file(path)
            except Exception:  # noqa: BLE001
                continue
            items.append(
                {
                    "id": recording.id,
                    "timestamp": recording.timestamp,
                    "duration": recording.duration,
                    "file_path": str(path),
                    "name": (recording.metadata or {}).get("name"),
                    "metadata": recording.metadata,
                }
            )
        return items

    def add_interaction(self, interaction_type: str, **kwargs) -> Dict[str, Any]:
        """Add a user interaction to the current recording.
        
        Args:
            interaction_type: Type of interaction ("click", "type", "scroll")
            **kwargs: Type-specific data (x, y for click; text for type; direction, amount for scroll)
            
        Returns:
            Dict with status and interaction_count or error
        """
        with self._lock:
            # Interaction gating: must be recording
            if not self._record_in_progress or self.current_recording is None:
                return {
                    "status": "error",
                    "reason": "recording_not_active",
                    "message": "Recording must be started first"
                }
            
            try:
                # Create interaction dict
                interaction = {
                    "type": interaction_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **kwargs
                }
                
                # Add to in-memory list
                self.current_recording.add_interaction(interaction_type, **kwargs)
                
                # Incremental persistence: append to disk immediately
                if self.current_recording.incremental_file:
                    AutomationRecording.append_interaction_to_disk(
                        interaction,
                        self.current_recording.incremental_file
                    )
                
                return {
                    "status": "success",
                    "interaction_count": len(self.current_recording.interactions)
                }
            except IOError as e:
                # Disk write failed - mark recording as failed
                self.current_recording.mark_failed(f"Failed to persist interaction: {e}")
                return {
                    "status": "error",
                    "reason": "persistence_failed",
                    "message": str(e)
                }
            except Exception as e:
                return {
                    "status": "error",
                    "reason": "interaction_failed",
                    "message": str(e)
                }
    
    def is_interaction_allowed(self) -> Dict[str, Any]:
        """Check if user interactions are currently allowed.
        
        Returns:
            Dict with allowed flag and reason
        """
        if not self._record_in_progress or self.current_recording is None:
            return {
                "allowed": False,
                "reason": "recording_not_active"
            }
        return {
            "allowed": True,
            "reason": "ok"
        }
    
    def is_recording_allowed(self) -> Dict[str, Any]:
        """Check if starting a recording is currently allowed.
        
        Returns:
            Dict with allowed flag, reason, and blocking_services if applicable
        """
        if self.current_recording is not None:
            return {
                "allowed": False,
                "reason": "recording_in_progress"
            }
        
        snapshot = self._service_snapshot()
        missing = self._missing_services("record", snapshot)
        if missing:
            return {
                "allowed": False,
                "reason": "services_not_ready",
                "blocking_services": missing
            }
        
        return {
            "allowed": True,
            "reason": "ok"
        }

    # ------------------------------------------------------------------
    # Duration enforcement
    # ------------------------------------------------------------------
    def _start_duration_timer(self) -> None:
        """Start timer to check recording duration every 60 seconds."""
        self._duration_timer = threading.Timer(60.0, self._check_duration_periodically)
        self._duration_timer.daemon = True
        self._duration_timer.start()
    
    def _stop_duration_timer(self) -> None:
        """Stop the duration enforcement timer."""
        if self._duration_timer:
            self._duration_timer.cancel()
            self._duration_timer = None
    
    def _check_duration_periodically(self) -> None:
        """Periodic callback to check recording duration."""
        self._enforce_duration_limit()
        # Reschedule for next check if still recording
        if self._record_in_progress and self.current_recording:
            self._start_duration_timer()
    
    def _enforce_duration_limit(self) -> None:
        """Check if recording has exceeded duration limit and auto-stop if needed."""
        with self._lock:
            if not self._record_in_progress or self.current_recording is None:
                return
            
            recording = self.current_recording
            if recording._start_time is None:
                return
            
            # Calculate elapsed time
            elapsed = (datetime.now(timezone.utc) - recording._start_time).total_seconds()
            
            # Check if limit reached
            if elapsed >= recording.duration_limit_seconds:
                print(f"[WARN] Recording auto-stopped: duration limit ({recording.duration_limit_seconds}s) reached")
                
                # Set auto_stopped flag
                recording.auto_stopped = True
                
                # Stop the recording
                self.stop_recording(recording.id)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _service_snapshot(self) -> Dict[str, Any]:
        return self.service_manager.get_service_snapshot(refresh=True)

    def _state_for_action(
        self, action: str, snapshot: Dict[str, Any]
    ) -> ControlActionState:
        state = self._actions[action]
        if state.in_progress:
            return state

        missing = self._missing_services(action, snapshot)
        if missing:
            reason = self._disabled_reason(snapshot, missing)
            state = ControlActionState.disabled(action, reason=reason, requires=self.ACTION_REQUIREMENTS[action])
        else:
            state = ControlActionState.ready(action, requires=self.ACTION_REQUIREMENTS[action])
        self._actions[action] = state
        return state

    def _missing_services(self, action: str, snapshot: Dict[str, Any]) -> List[str]:
        requirements = set(self.ACTION_REQUIREMENTS[action])
        service_lookup = {entry["name"]: entry for entry in snapshot["services"]}
        missing: List[str] = []
        for name in requirements:
            entry = service_lookup.get(name)
            if not entry or entry.get("status") != ServiceState.RUNNING.value:
                missing.append(name)
        return missing

    def _disabled_reason(self, snapshot: Dict[str, Any], missing: List[str]) -> str:
        service_lookup = {entry["name"]: entry for entry in snapshot["services"]}
        parts: List[str] = []
        for name in missing:
            entry = service_lookup.get(name, {})
            if entry.get("error_message"):
                parts.append(entry["error_message"])
            else:
                parts.append(f"{name} status: {entry.get('status', 'unknown')}")
        return "; ".join(parts) or "Services not ready"

    def _find_recording_file(self, recording_id: str) -> Optional[Path]:
        recordings_dir = self.recordings_dir
        # Support optional name slug after the id before .json
        pattern = f"*_automation_recording_{recording_id}*.json"
        matches = list(recordings_dir.glob(pattern))
        return matches[0] if matches else None

    def _execute_replay(self, recording: AutomationRecording, replay_id: str) -> None:
        """Execute the replay of a recording."""
        device_id = os.getenv("ANDROID_DEVICE_ID", "emulator-5554")
        try:
            for step in recording.interactions:
                itype = step.get("type")
                if itype == "click":
                    x = int(step.get("x", 0))
                    y = int(step.get("y", 0))
                    try:
                        subprocess.run(
                            ["adb", "-s", device_id, "shell", "input", "tap", str(x), str(y)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                        )
                    except Exception:
                        pass
                    time.sleep(0.1)
                elif itype == "type":
                    text = str(step.get("text", ""))
                    if text:
                        # Convert spaces to %s for adb input text
                        payload = text.replace(" ", "%s")
                        try:
                            subprocess.run(
                                ["adb", "-s", device_id, "shell", "input", "text", payload],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=5,
                            )
                        except Exception:
                            pass
                        time.sleep(0.1)
                elif itype == "scroll":
                    # Use swipe to approximate scroll
                    direction = step.get("direction", "down")
                    amount = int(step.get("amount", 300))
                    # Simple swipe from center
                    try:
                        # Get display size
                        size = subprocess.run(
                            ["adb", "-s", device_id, "shell", "wm", "size"],
                            capture_output=True,
                            text=True,
                            timeout=3,
                        ).stdout
                        import re
                        m = re.search(r"(\d+)x(\d+)", size or "")
                        if m:
                            w, h = int(m.group(1)), int(m.group(2))
                        else:
                            w, h = 1080, 1920
                        cx, cy = w // 2, h // 2
                        if direction == "down":
                            x1, y1, x2, y2 = cx, cy - amount // 2, cx, cy + amount // 2
                        elif direction == "up":
                            x1, y1, x2, y2 = cx, cy + amount // 2, cx, cy - amount // 2
                        elif direction == "left":
                            x1, y1, x2, y2 = cx + amount // 2, cy, cx - amount // 2, cy
                        else:  # right
                            x1, y1, x2, y2 = cx - amount // 2, cy, cx + amount // 2, cy
                        subprocess.run(
                            [
                                "adb",
                                "-s",
                                device_id,
                                "shell",
                                "input",
                                "swipe",
                                str(x1),
                                str(y1),
                                str(x2),
                                str(y2),
                                "150",
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=5,
                        )
                    except Exception:
                        pass
                    time.sleep(0.1)
                else:
                    # Unknown step; small delay to keep rhythm
                    time.sleep(0.05)
            self.finalize_replay(replay_id=replay_id)
        except Exception:
            self.finalize_replay(replay_id=replay_id)
