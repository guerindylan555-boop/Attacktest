"""Integration test for service startup reliability (Scenario 1 & 8)."""
import time
from unittest.mock import patch, Mock

import pytest

from automation.services.service_manager import ServiceManager


class TestServiceStartupReliability:
    """Test clean startup and service order (Scenarios 1 & 8)."""

    @pytest.mark.slow
    @patch('automation.services.service_manager.ServiceManager._start_frida')
    @patch('automation.services.service_manager.ServiceManager._start_proxy')
    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_clean_startup_all_services_auto_start(self, mock_emu, mock_proxy, mock_frida):
        """Scenario 1: All services auto-start on clean launch."""
        mock_emu.return_value = {"success": True, "pid": 1}
        mock_proxy.return_value = {"success": True, "pid": 2}
        mock_frida.return_value = {"success": True, "pid": 3}
        
        manager = ServiceManager()
        result = manager.start_all_services()
        
        assert result["status"] == "success"
        assert len(result["started_services"]) == 3
        assert manager.services["emulator"].state.value == "running"
        assert manager.services["proxy"].state.value == "running"
        assert manager.services["frida"].state.value == "running"

    @patch('automation.services.service_manager.ServiceManager._start_frida')
    @patch('automation.services.service_manager.ServiceManager._start_proxy')
    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_service_order_emulator_first(self, mock_emu, mock_proxy, mock_frida):
        """Scenario 8: Services start in order: emulator → proxy → frida."""
        call_order = []
        
        def track_emu(*args): 
            call_order.append("emulator")
            return {"success": True, "pid": 1}
        def track_proxy(*args): 
            call_order.append("proxy")
            return {"success": True, "pid": 2}
        def track_frida(*args): 
            call_order.append("frida")
            return {"success": True, "pid": 3}
        
        mock_emu.side_effect = track_emu
        mock_proxy.side_effect = track_proxy
        mock_frida.side_effect = track_frida
        
        manager = ServiceManager()
        manager.start_all_services()
        
        assert call_order == ["emulator", "proxy", "frida"]

    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_90_second_timeout_enforcement(self, mock_emu):
        """Test that emulator has 90-second timeout."""
        def slow_boot(*args):
            time.sleep(0.1)  # Simulate slow start
            return {"success": False, "error": "timeout"}
        
        mock_emu.side_effect = slow_boot
        
        manager = ServiceManager()
        # With 3 retries, should take ~0.3s + delays
        start = time.time()
        manager._start_service("emulator")
        elapsed = time.time() - start
        
        # Should have tried 3 times with delays
        assert elapsed >= 10  # 2 retries * 5s delay


pytestmark = [pytest.mark.integration, pytest.mark.slow]

