"""Integration test for service retry logic (Scenario 2)."""
import time
from unittest.mock import patch, Mock

import pytest

from automation.services.service_manager import ServiceManager


class TestServiceRetryLogic:
    """Test attach detection and retry scenarios (Scenario 2)."""

    @patch('automation.services.service_manager.subprocess.run')
    def test_attach_detection_emulator_already_running(self, mock_run):
        """Scenario 2: Detect and attach to already-running emulator."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="emulator-5554\tdevice\n"
        )
        
        manager = ServiceManager()
        running = manager._detect_running_services()
        
        assert running.get("emulator") is True

    @patch('automation.services.service_manager.ServiceManager._start_proxy')
    def test_port_conflict_retry_3_attempts(self, mock_proxy):
        """Scenario 2: Proxy retries 3 times on port conflict."""
        mock_proxy.return_value = {"success": False, "error": "port 8080 in use"}
        
        manager = ServiceManager()
        start = time.time()
        manager._start_service("proxy")
        elapsed = time.time() - start
        
        # Should have made 3 attempts with 5s delays between
        assert mock_proxy.call_count == 3
        assert elapsed >= 10  # 2 retries * 5s

    @patch('automation.services.service_manager.ServiceManager._start_frida')
    def test_manual_retry_after_failure(self, mock_frida):
        """Scenario 2: Manual retry succeeds after fixing issue."""
        # First attempts fail
        mock_frida.side_effect = [
            {"success": False, "error": "app not found"},
            {"success": False, "error": "app not found"},
            {"success": False, "error": "app not found"},
            {"success": True, "pid": 999}  # Manual retry succeeds
        ]
        
        manager = ServiceManager()
        
        # Auto-start fails after 3 attempts
        result1 = manager._start_service("frida")
        assert result1.state.value == "failed"
        
        # Manual retry succeeds
        result2 = manager.retry_service("frida")
        assert result2["status"] == "success"


pytestmark = [pytest.mark.integration, pytest.mark.slow]

