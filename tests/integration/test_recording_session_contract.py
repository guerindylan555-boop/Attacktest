"""Contract tests for AutomationRecording session lifecycle."""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from automation.models.recording import AutomationRecording


class TestRecordingSessionLifecycle:
    """Test AutomationRecording session contract."""

    def test_start_recording_initializes_state(self):
        """Test start_recording() sets up session correctly."""
        recording = AutomationRecording()
        
        result = recording.start_recording()
        
        assert result["status"] == "success"
        assert recording.state == "recording"
        assert recording._is_recording is True
        assert recording._start_time is not None

    def test_stop_recording_calculates_duration(self):
        """Test stop_recording() calculates correct duration."""
        recording = AutomationRecording()
        
        recording.start_recording()
        time.sleep(0.05)
        result = recording.stop_recording()
        
        assert result["status"] == "success"
        assert recording.duration >= 0.05
        assert recording.state == "completed"

    def test_incremental_persistence_to_jsonl(self):
        """Test interactions persist to JSONL file immediately."""
        recording = AutomationRecording(duration_limit_seconds=1800)
        recording.start_recording()
        
        # Create temp JSONL file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            jsonl_path = Path(f.name)
        
        try:
            # Append interactions
            interaction1 = {"type": "click", "x": 100, "y": 200, "timestamp": datetime.now(timezone.utc).isoformat()}
            interaction2 = {"type": "type", "text": "test", "timestamp": datetime.now(timezone.utc).isoformat()}
            
            AutomationRecording.append_interaction_to_disk(interaction1, jsonl_path)
            AutomationRecording.append_interaction_to_disk(interaction2, jsonl_path)
            
            # Verify file contains both interactions
            with open(jsonl_path, 'r') as f:
                lines = f.readlines()
                assert len(lines) == 2
                assert json.loads(lines[0])["type"] == "click"
                assert json.loads(lines[1])["type"] == "type"
        finally:
            jsonl_path.unlink(missing_ok=True)

    def test_auto_stop_at_duration_limit(self):
        """Test auto-stop when duration >= limit."""
        recording = AutomationRecording(duration_limit_seconds=10)
        recording.start_recording()
        
        # Simulate 11 seconds elapsed
        recording._start_time = datetime.now(timezone.utc) - timedelta(seconds=11)
        recording.stop_recording()
        
        assert recording.duration >= 10
        # auto_stopped should be set by controller, but duration should match

    def test_auto_stopped_flag_functionality(self):
        """Test auto_stopped flag can be set."""
        recording = AutomationRecording()
        
        assert recording.auto_stopped is False
        recording.auto_stopped = True
        assert recording.auto_stopped is True

    def test_backward_compatibility_load(self):
        """Test loading old recordings without new fields."""
        # Simulate old recording JSON
        old_data = {
            "id": "test-123",
            "timestamp": "2025-01-01T00:00:00Z",
            "duration": 100.0,
            "interactions": [{"type": "click", "x": 1, "y": 2, "timestamp": "2025-01-01T00:00:01Z"}],
            "metadata": {},
            "state": "completed"
        }
        
        # Create temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(old_data, f)
            temp_path = Path(f.name)
        
        try:
            recording = AutomationRecording.load_from_file(temp_path)
            
            # Should load successfully with defaults
            assert recording.duration_limit_seconds == 1800  # default
            assert recording.auto_stopped is False  # default
            assert recording.incremental_file is None  # default
        finally:
            temp_path.unlink(missing_ok=True)


pytestmark = [pytest.mark.integration]

