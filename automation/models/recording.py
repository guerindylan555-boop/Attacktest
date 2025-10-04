"""
AutomationRecording model for capturing and storing user interactions.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class AutomationRecording:
    """Model for capturing and storing user interactions for replay functionality."""
    
    def __init__(self, recording_id: Optional[str] = None, duration_limit_seconds: int = 1800, display_name: Optional[str] = None):
        """Initialize a new automation recording.
        
        Args:
            recording_id: Unique identifier for the recording session. 
                         If None, a new UUID will be generated.
            duration_limit_seconds: Maximum recording duration in seconds (default 30 minutes).
        """
        self.id = recording_id or str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.duration = 0.0
        self.duration_limit_seconds = duration_limit_seconds
        self.auto_stopped = False
        self.interactions: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "app_version": "1.0.0",
            "device_info": "automation_app",
            "recording_start_time": self.timestamp
        }
        if display_name:
            self.metadata["name"] = display_name
        self.state = "pending"
        self.file_path: Optional[Path] = None
        self.incremental_file: Optional[Path] = None
        self.last_error: Optional[str] = None
        self._start_time: Optional[datetime] = None
        self._is_recording = False
    
    def start_recording(self) -> Dict[str, Any]:
        """Start recording user interactions.
        
        Returns:
            Dict containing recording status and metadata.
        """
        if self._is_recording:
            raise ValueError("Recording is already in progress")
        
        self._start_time = datetime.now(timezone.utc)
        self._is_recording = True
        self.timestamp = self._start_time.isoformat()
        self.metadata["recording_start_time"] = self.timestamp
        self.metadata["last_updated"] = self.timestamp
        self.state = "recording"

        return {
            "status": "success",
            "recording_id": self.id,
            "start_time": self.timestamp
        }
    
    def stop_recording(self) -> Dict[str, Any]:
        """Stop recording and calculate duration.
        
        Returns:
            Dict containing recording completion data.
        """
        if not self._is_recording:
            raise ValueError("No recording in progress")
        
        if self._start_time:
            end_time = datetime.now(timezone.utc)
            self.duration = (end_time - self._start_time).total_seconds()
            ended_at = end_time.isoformat()
            self.metadata["recording_end_time"] = ended_at
            self.metadata["last_updated"] = ended_at

        self._is_recording = False
        self.state = "completed"

        return {
            "status": "success",
            "recording_id": self.id,
            "duration": self.duration,
            "interactions_count": len(self.interactions)
        }

    def mark_failed(self, message: str) -> Dict[str, Any]:
        """Mark the recording as failed and capture the error for diagnostics."""

        self._is_recording = False
        self.state = "failed"
        self.last_error = message
        failure_time = datetime.now(timezone.utc).isoformat()
        self.metadata["last_error"] = message
        self.metadata["last_updated"] = failure_time

        return {
            "status": "error",
            "recording_id": self.id,
            "error": message,
            "reason": "recording_failed",
        }
    
    def add_interaction(self, interaction_type: str, **kwargs) -> None:
        """Add a user interaction to the recording.
        
        Args:
            interaction_type: Type of interaction (click, type, scroll, etc.)
            **kwargs: Additional interaction data
        """
        if not self._is_recording:
            raise ValueError("Cannot add interaction - recording not in progress")
        
        interaction = {
            "type": interaction_type,
            "timestamp": datetime.now().isoformat(),
            **kwargs
        }
        
        self.interactions.append(interaction)
    
    def add_click(self, x: int, y: int) -> None:
        """Add a click interaction.
        
        Args:
            x: X coordinate of the click
            y: Y coordinate of the click
        """
        self.add_interaction("click", x=x, y=y)
    
    def add_type(self, text: str) -> None:
        """Add a text input interaction.
        
        Args:
            text: Text that was typed
        """
        self.add_interaction("type", text=text)
    
    def add_scroll(self, direction: str, amount: int) -> None:
        """Add a scroll interaction.
        
        Args:
            direction: Scroll direction (up, down, left, right)
            amount: Scroll amount in pixels
        """
        self.add_interaction("scroll", direction=direction, amount=amount)
    
    @staticmethod
    def append_interaction_to_disk(interaction: Dict[str, Any], file_path: Path) -> None:
        """Append interaction to incremental JSONL file.
        
        Args:
            interaction: Interaction dict to append
            file_path: Path to .jsonl file
            
        Raises:
            IOError: If write fails
        """
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(interaction) + '\n')
            f.flush()  # Force OS to write immediately
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert recording to dictionary format.

        Returns:
            Dict representation of the recording.
        """
        payload = {
            "id": self.id,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "duration_limit_seconds": self.duration_limit_seconds,
            "auto_stopped": self.auto_stopped,
            "interactions": self.interactions,
            "metadata": self.metadata,
            "state": self.state,
        }
        if self.file_path is not None:
            payload["file_path"] = str(self.file_path)
        if self.incremental_file is not None:
            payload["incremental_file"] = str(self.incremental_file)
        if self.last_error is not None:
            payload["last_error"] = self.last_error
        return payload
    
    def save_to_file(self, recordings_dir: Path = None, display_name: Optional[str] = None) -> Path:
        """Save recording to JSON file.
        
        Args:
            recordings_dir: Directory to save the recording file.
                          Defaults to automation/recordings/
        
        Returns:
            Path to the saved file.
        """
        if recordings_dir is None:
            recordings_dir = Path("automation/recordings")
        
        recordings_dir.mkdir(exist_ok=True)
        
        # Create filename: {timestamp}_automation_recording_{id}.json
        timestamp_str = self.timestamp.replace(":", "").replace("-", "").replace("T", "_").split(".")[0]
        # Apply optional display name (persist into metadata)
        if display_name:
            self.metadata["name"] = display_name
        name_slug = None
        if self.metadata.get("name"):
            raw = str(self.metadata.get("name"))[:64]
            name_slug = "".join(c if c.isalnum() or c in ("-", "_") else "-" for c in raw).strip("-")
            name_slug = name_slug or None
        if name_slug:
            filename = f"{timestamp_str}_automation_recording_{self.id}__{name_slug}.json"
        else:
            filename = f"{timestamp_str}_automation_recording_{self.id}.json"
        file_path = recordings_dir / filename

        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

        self.file_path = file_path
        self.metadata["file_path"] = str(file_path)
        self.metadata["last_updated"] = datetime.now(timezone.utc).isoformat()

        return file_path
    
    @classmethod
    def load_from_file(cls, file_path: Path) -> 'AutomationRecording':
        """Load recording from JSON file.
        
        Args:
            file_path: Path to the recording file.
        
        Returns:
            AutomationRecording instance loaded from file.
        """
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Load with duration_limit from file or default
        duration_limit = data.get("duration_limit_seconds", 1800)
        display_name = None
        md = data.get("metadata", {})
        if isinstance(md, dict):
            display_name = md.get("name")
        recording = cls(recording_id=data["id"], duration_limit_seconds=duration_limit, display_name=display_name)
        
        recording.timestamp = data.get("timestamp", recording.timestamp)
        recording.duration = data.get("duration", 0.0)
        recording.auto_stopped = data.get("auto_stopped", False)  # Default for old recordings
        recording.interactions = data.get("interactions", [])
        recording.metadata = data.get("metadata", {})
        recording.state = data.get("state", "completed")
        if "file_path" in data:
            recording.file_path = Path(data["file_path"])
        if "incremental_file" in data:
            recording.incremental_file = Path(data["incremental_file"])
        if "last_error" in data:
            recording.last_error = data["last_error"]

        return recording
    
    @classmethod
    def list_recordings(cls, recordings_dir: Path = None) -> List[Path]:
        """List all available recording files.
        
        Args:
            recordings_dir: Directory to search for recordings.
                          Defaults to automation/recordings/
        
        Returns:
            List of Path objects for recording files.
        """
        if recordings_dir is None:
            recordings_dir = Path("automation/recordings")
        
        if not recordings_dir.exists():
            return []
        
        # Find all files matching the pattern
        pattern = "*_automation_recording_*.json"
        return list(recordings_dir.glob(pattern))
    
    def validate(self) -> bool:
        """Validate recording data integrity.
        
        Returns:
            True if recording is valid, False otherwise.
        """
        # Check required fields
        if not self.id or not self.timestamp:
            return False
        
        # Validate timestamp format
        try:
            datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
        except ValueError:
            return False
        
        # Validate duration
        if self.duration < 0:
            return False
        
        # Validate interactions
        if not isinstance(self.interactions, list):
            return False
        
        for interaction in self.interactions:
            if not isinstance(interaction, dict):
                return False
            if "type" not in interaction or "timestamp" not in interaction:
                return False
        
        return True
    
    def __str__(self) -> str:
        """String representation of the recording."""
        return f"AutomationRecording(id={self.id}, duration={self.duration}s, interactions={len(self.interactions)})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the recording."""
        return f"AutomationRecording(id='{self.id}', timestamp='{self.timestamp}', duration={self.duration}, interactions={len(self.interactions)})"
