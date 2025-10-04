"""Unit tests for AutomationRecording auto-stop functionality."""
import time
from datetime import datetime, timedelta, timezone

import pytest

from automation.models.recording import AutomationRecording


class TestRecordingDurationCalculation:
    """Unit tests for recording duration calculation."""

    def test_stop_recording_calculates_correct_duration(self):
        """Test stop_recording() calculates correct duration."""
        recording = AutomationRecording()
        
        recording.start_recording()
        time.sleep(0.05)
        result = recording.stop_recording()
        
        assert result["status"] == "success"
        assert recording.duration >= 0.05
        assert recording.duration < 1.0  # Reasonable upper bound

    def test_duration_zero_on_immediate_stop(self):
        """Test duration is very small if stopped immediately."""
        recording = AutomationRecording()
        
        recording.start_recording()
        result = recording.stop_recording()
        
        assert recording.duration >= 0
        assert recording.duration < 0.1  # Should be very quick


class TestAutoStopFlag:
    """Unit tests for auto_stopped flag."""

    def test_auto_stopped_flag_defaults_to_false(self):
        """Test auto_stopped is False by default."""
        recording = AutomationRecording()
        assert recording.auto_stopped is False

    def test_auto_stopped_flag_can_be_set(self):
        """Test auto_stopped flag can be set to True."""
        recording = AutomationRecording()
        
        recording.auto_stopped = True
        assert recording.auto_stopped is True

    def test_auto_stopped_flag_in_to_dict(self):
        """Test auto_stopped appears in to_dict() output."""
        recording = AutomationRecording()
        recording.auto_stopped = True
        
        data = recording.to_dict()
        assert "auto_stopped" in data
        assert data["auto_stopped"] is True


class TestDurationLimitField:
    """Unit tests for duration_limit_seconds field."""

    def test_duration_limit_defaults_to_1800(self):
        """Test duration_limit_seconds defaults to 30 minutes."""
        recording = AutomationRecording()
        assert recording.duration_limit_seconds == 1800

    def test_duration_limit_can_be_customized(self):
        """Test duration_limit_seconds can be set via constructor."""
        recording = AutomationRecording(duration_limit_seconds=600)
        assert recording.duration_limit_seconds == 600

    def test_duration_limit_in_to_dict(self):
        """Test duration_limit_seconds appears in to_dict()."""
        recording = AutomationRecording(duration_limit_seconds=900)
        
        data = recording.to_dict()
        assert "duration_limit_seconds" in data
        assert data["duration_limit_seconds"] == 900


class TestRecordingValidation:
    """Unit tests for recording validation."""

    def test_validate_accepts_valid_recording(self):
        """Test validate() returns True for valid recording."""
        recording = AutomationRecording()
        recording.start_recording()
        recording.add_click(100, 200)
        recording.stop_recording()
        
        assert recording.validate() is True

    def test_validate_catches_negative_duration(self):
        """Test validate() detects invalid negative duration."""
        recording = AutomationRecording()
        recording.duration = -10.0
        
        assert recording.validate() is False

    def test_validate_catches_missing_interaction_fields(self):
        """Test validate() detects malformed interactions."""
        recording = AutomationRecording()
        recording.start_recording()
        
        # Add invalid interaction (missing required fields)
        recording.interactions.append({"invalid": "data"})
        recording.stop_recording()
        
        assert recording.validate() is False


class TestBackwardCompatibility:
    """Unit tests for backward compatibility with old recording format."""

    def test_load_old_recording_without_new_fields(self):
        """Test loading old recordings that don't have new fields."""
        import json
        import tempfile
        from pathlib import Path
        
        # Simulate old recording format
        old_data = {
            "id": "old-recording-123",
            "timestamp": "2025-01-01T00:00:00Z",
            "duration": 100.0,
            "interactions": [],
            "metadata": {},
            "state": "completed"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(old_data, f)
            temp_path = Path(f.name)
        
        try:
            recording = AutomationRecording.load_from_file(temp_path)
            
            # Should load with defaults for new fields
            assert recording.duration_limit_seconds == 1800
            assert recording.auto_stopped is False
            assert recording.incremental_file is None
        finally:
            temp_path.unlink(missing_ok=True)


pytestmark = [pytest.mark.unit]

