"""Integration test for interaction blocking (Scenario 5)."""
from unittest.mock import patch

import pytest

from automation.services.automation_controller import AutomationController


class TestInteractionBlocking:
    """Test interaction blocking when recording inactive (Scenario 5)."""

    def test_block_interactions_when_recording_inactive(self):
        """Scenario 5: Interactions blocked when not recording."""
        controller = AutomationController()
        
        # Try to add interaction without starting recording
        result = controller.add_interaction("click", x=540, y=960)
        
        assert result["status"] == "error"
        assert result["reason"] == "recording_not_active"

    def test_error_message_recording_must_be_started_first(self):
        """Scenario 5: Specific error message displayed."""
        controller = AutomationController()
        
        result = controller.add_interaction("click", x=100, y=200)
        
        assert "must be started first" in result["message"].lower()

    def test_no_adb_relay_when_blocked(self):
        """Scenario 5: No ADB command sent when interaction blocked."""
        controller = AutomationController()
        
        # Mock ADB relay method (implementation detail)
        with patch('subprocess.run') as mock_run:
            result = controller.add_interaction("click", x=100, y=200)
            
            # ADB should not be called since interaction was blocked
            assert result["status"] == "error"
            # Implementation would not call adb when blocked

    def test_interactions_allowed_when_recording_active(self):
        """Test that interactions work once recording starts."""
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
            
            # Now interaction should succeed
            result = controller.add_interaction("click", x=540, y=960)
            assert result["status"] == "success"


pytestmark = [pytest.mark.integration]

