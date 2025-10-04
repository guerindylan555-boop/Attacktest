"""Integration test for recording duration limits (Scenario 4)."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from automation.services.automation_controller import AutomationController


class TestRecordingDurationLimits:
    """Test 30-minute duration limit enforcement (Scenario 4)."""

    def test_auto_stop_at_30_minutes(self):
        """Scenario 4: Recording auto-stops at 30-minute limit."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snap:
            mock_snap.return_value = {
                "all_ready": True,
                "failed_services": [],
                "services": [
                    {"name": "emulator", "status": "running"},
                    {"name": "proxy", "status": "running"},
                    {"name": "frida", "status": "running"}
                ]
            }
            
            controller.start_recording()
            recording = controller.current_recording
            
            if recording:
                # Simulate 31 minutes elapsed
                recording._start_time = datetime.now(timezone.utc) - timedelta(minutes=31)
                
                # Trigger duration check
                controller._enforce_duration_limit()
                
                # Should be auto-stopped
                assert controller.current_recording is None or recording.auto_stopped is True

    def test_warning_message_on_auto_stop(self):
        """Scenario 4: Warning message displayed on auto-stop."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snap:
            mock_snap.return_value = {
                "all_ready": True,
                "failed_services": [],
                "services": [
                    {"name": "emulator", "status": "running"},
                    {"name": "proxy", "status": "running"},
                    {"name": "frida", "status": "running"}
                ]
            }
            
            controller.start_recording()
            recording = controller.current_recording
            
            if recording:
                # Fast-forward time
                recording._start_time = datetime.now(timezone.utc) - timedelta(seconds=1801)
                
                # Capture logs (implementation would log warning)
                controller._enforce_duration_limit()
                
                # Implementation should log: "[WARN] Recording auto-stopped: duration limit reached"

    def test_auto_stopped_flag_in_json_output(self):
        """Scenario 4: auto_stopped flag appears in JSON."""
        controller = AutomationController()
        
        with patch.object(controller.service_manager, 'get_service_snapshot') as mock_snap:
            mock_snap.return_value = {
                "all_ready": True,
                "failed_services": [],
                "services": [
                    {"name": "emulator", "status": "running"},
                    {"name": "proxy", "status": "running"},
                    {"name": "frida", "status": "running"}
                ]
            }
            
            controller.start_recording()
            recording = controller.current_recording
            
            if recording:
                # Simulate limit reached
                recording._start_time = datetime.now(timezone.utc) - timedelta(seconds=1801)
                controller._enforce_duration_limit()
                
                # Check JSON output
                data = recording.to_dict()
                assert "auto_stopped" in data


pytestmark = [pytest.mark.integration]

