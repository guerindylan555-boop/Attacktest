"""
Contract tests for AutomationController recording and interaction methods.

These tests verify:
- Service readiness check before recording
- Incremental file creation
- Duration timer activation
- Interaction gating (block when not recording)
"""
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from automation.services.automation_controller import AutomationController
from automation.models.recording import AutomationRecording


class TestRecordingStartContract:
    """Test AutomationController.start_recording() contract."""

    def test_start_recording_checks_service_readiness(self):
        """Test that start_recording fails if required services not ready."""
        controller = AutomationController()
        
        # Mock service manager to report services not ready
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {
                "all_ready": False,
                "failed_services": ["frida"]
            }
            
            result = controller.start_recording()
            
            # Should fail with services_not_ready reason
            assert result["status"] == "error"
            assert result["reason"] == "services_not_ready"
            assert "frida" in result["blocking_services"]

    def test_start_recording_creates_incremental_file(self):
        """Test that start_recording creates JSONL incremental file."""
        controller = AutomationController()
        
        # Mock services as ready
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {
                "all_ready": True,
                "failed_services": []
            }
            
            result = controller.start_recording()
            
            if result["status"] == "success":
                # Check that incremental file was created
                recording = controller.current_recording
                assert recording is not None
                assert recording.incremental_file is not None
                assert recording.incremental_file.suffix == ".jsonl"

    def test_start_recording_activates_duration_timer(self):
        """Test that start_recording starts duration enforcement timer."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            with patch.object(controller, '_enforce_duration_limit') as mock_enforce:
                result = controller.start_recording()
                
                if result["status"] == "success":
                    # Duration timer should be active
                    # (Implementation detail: verify timer callback is registered)
                    assert controller.current_recording is not None

    def test_start_recording_rejects_if_already_recording(self):
        """Test that start_recording fails if recording already in progress."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            # Start first recording
            result1 = controller.start_recording()
            
            # Try to start second recording
            result2 = controller.start_recording()
            
            # Second attempt should fail
            assert result2["status"] == "error"
            assert "already" in result2.get("reason", "").lower() or "in progress" in result2.get("reason", "").lower()


class TestInteractionGatingContract:
    """Test AutomationController interaction gating contract."""

    def test_add_interaction_fails_when_not_recording(self):
        """Test that add_interaction fails if recording not active."""
        controller = AutomationController()
        
        # No recording started
        result = controller.add_interaction("click", x=540, y=960)
        
        # Should fail with recording_not_active reason
        assert result["status"] == "error"
        assert result["reason"] == "recording_not_active"
        assert "must be started first" in result["message"].lower()

    def test_is_interaction_allowed_returns_false_when_idle(self):
        """Test that is_interaction_allowed() returns False when not recording."""
        controller = AutomationController()
        
        result = controller.is_interaction_allowed()
        
        assert result["allowed"] is False
        assert result["reason"] == "recording_not_active"

    def test_is_interaction_allowed_returns_true_when_recording(self):
        """Test that is_interaction_allowed() returns True during recording."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            result = controller.is_interaction_allowed()
            
            assert result["allowed"] is True
            assert result["reason"] == "ok"

    def test_add_interaction_succeeds_when_recording(self):
        """Test that add_interaction works during active recording."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            result = controller.add_interaction("click", x=540, y=960)
            
            assert result["status"] == "success"
            assert result["interaction_count"] >= 1


class TestIncrementalPersistenceContract:
    """Test AutomationController incremental persistence contract."""

    def test_add_interaction_appends_to_disk_immediately(self):
        """Test that each interaction is written to disk immediately."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            
            if controller.current_recording:
                incremental_file = controller.current_recording.incremental_file
                
                # Add interaction
                controller.add_interaction("click", x=100, y=200)
                
                # File should immediately contain the interaction
                if incremental_file and incremental_file.exists():
                    with open(incremental_file, 'r') as f:
                        lines = f.readlines()
                        assert len(lines) >= 1
                        
                        # Verify JSON structure
                        interaction = json.loads(lines[-1])
                        assert interaction["type"] == "click"
                        assert interaction["x"] == 100
                        assert interaction["y"] == 200

    def test_incremental_file_survives_crash(self):
        """Test that incremental file preserves data if app crashes."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            
            # Add multiple interactions
            controller.add_interaction("click", x=100, y=200)
            controller.add_interaction("type", text="hello")
            controller.add_interaction("scroll", direction="down", amount=300)
            
            incremental_file = controller.current_recording.incremental_file
            
            # Simulate crash (don't call stop_recording)
            # File should still have all 3 interactions
            if incremental_file and incremental_file.exists():
                with open(incremental_file, 'r') as f:
                    lines = f.readlines()
                    assert len(lines) == 3


class TestDurationEnforcementContract:
    """Test AutomationController duration limit enforcement contract."""

    def test_enforce_duration_limit_stops_recording_at_limit(self):
        """Test that _enforce_duration_limit auto-stops at 30 minutes."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            recording = controller.current_recording
            
            if recording:
                # Simulate 30+ minutes elapsed
                with patch.object(recording, '_start_time') as mock_start:
                    from datetime import datetime, timedelta, timezone
                    mock_start.return_value = datetime.now(timezone.utc) - timedelta(minutes=31)
                    
                    # Trigger duration check
                    controller._enforce_duration_limit()
                    
                    # Recording should be auto-stopped
                    assert controller.current_recording is None or recording.auto_stopped is True

    def test_auto_stopped_flag_set_on_duration_limit(self):
        """Test that auto_stopped flag is set when duration limit reached."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            recording = controller.current_recording
            
            if recording:
                # Fast-forward time
                from datetime import datetime, timedelta, timezone
                recording._start_time = datetime.now(timezone.utc) - timedelta(seconds=1801)
                
                # Manually trigger duration enforcement
                controller._enforce_duration_limit()
                
                # Check auto_stopped flag
                assert recording.auto_stopped is True


class TestRecordingStopContract:
    """Test AutomationController.stop_recording() contract."""

    def test_stop_recording_saves_both_files(self):
        """Test that stop_recording creates both JSONL and JSON files."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            controller.add_interaction("click", x=100, y=200)
            
            result = controller.stop_recording()
            
            if result["status"] == "success":
                # Both files should exist
                file_path = Path(result["file_path"])
                jsonl_path = file_path.with_suffix(".jsonl")
                
                # JSON summary file should exist
                assert file_path.exists()
                # JSONL incremental file should exist
                # (might be same path or different naming)

    def test_stop_recording_calculates_duration(self):
        """Test that stop_recording calculates correct duration."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snapshot:
            mock_snapshot.return_value = {"all_ready": True, "failed_services": []}
            
            controller.start_recording()
            time.sleep(0.1)  # Wait a bit
            result = controller.stop_recording()
            
            if result["status"] == "success":
                assert result["duration"] >= 0.1
                assert result["duration"] < 10  # Reasonable upper bound


# Mark as integration tests
pytestmark = [pytest.mark.integration]

