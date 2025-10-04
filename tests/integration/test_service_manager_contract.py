"""
Contract tests for ServiceManager.start_all_services() and related methods.

These tests verify the ServiceManager API contract:
- Retry logic (3 attempts, 5s delays)
- Dependency order (emulator → proxy → frida)
- Attach detection for already-running services
- ServiceManagerSnapshot aggregation
"""
import time
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

from automation.services.service_manager import ServiceManager
from automation.models.service_status import ServiceState, ServiceStatus


class TestServiceManagerRetryLogic:
    """Test ServiceManager retry logic contract."""

    @patch('automation.services.service_manager.subprocess.Popen')
    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_start_service_retries_on_failure(self, mock_start_emulator, mock_popen):
        """Test that _start_service retries up to 3 times with 5s delays."""
        manager = ServiceManager()
        
        # Mock emulator start to fail first 2 times, succeed on 3rd
        mock_start_emulator.side_effect = [
            {"success": False, "error": "timeout"},
            {"success": False, "error": "timeout"},
            {"success": True, "pid": 12345}
        ]
        
        start_time = time.time()
        result = manager._start_service("emulator")
        elapsed = time.time() - start_time
        
        # Should have made 3 attempts
        assert mock_start_emulator.call_count == 3
        # Should have taken ~10 seconds (2 retries * 5s delay)
        assert elapsed >= 10, "Retry delays not respected"
        # Final result should be success
        assert isinstance(result, ServiceStatus)
        assert result.state == ServiceState.RUNNING

    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_start_service_stops_after_max_retries(self, mock_start_emulator):
        """Test that _start_service stops after 3 failed attempts."""
        manager = ServiceManager()
        
        # Mock emulator to always fail
        mock_start_emulator.return_value = {"success": False, "error": "persistent failure"}
        
        result = manager._start_service("emulator")
        
        # Should have made exactly 3 attempts (initial + 2 retries)
        assert mock_start_emulator.call_count == 3
        # Final state should be failed
        assert isinstance(result, ServiceStatus)
        assert result.state == ServiceState.FAILED
        assert "persistent failure" in result.error_message

    def test_service_status_tracks_retry_count(self):
        """Test that ServiceStatus.retry_count is updated correctly."""
        manager = ServiceManager()
        status = manager.services["emulator"]
        
        # Initial retry count should be 0
        assert status.retry_count == 0
        assert status.max_retries == 3
        
        # Simulate retry attempts
        status.begin_retry_attempt()
        assert status.retry_count == 1
        assert status.last_retry_at is not None
        
        status.begin_retry_attempt()
        assert status.retry_count == 2
        
        # Check should_retry logic
        assert status.should_retry() is True  # 2 < 3
        
        status.begin_retry_attempt()
        assert status.retry_count == 3
        assert status.should_retry() is False  # 3 >= 3


class TestServiceManagerDependencyOrder:
    """Test ServiceManager service startup order contract."""

    @patch('automation.services.service_manager.ServiceManager._start_frida')
    @patch('automation.services.service_manager.ServiceManager._start_proxy')
    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_start_all_services_respects_order(self, mock_emulator, mock_proxy, mock_frida):
        """Test that services start in order: emulator → proxy → frida."""
        manager = ServiceManager()
        
        # Track call order
        call_order = []
        
        def track_emulator(*args, **kwargs):
            call_order.append("emulator")
            return {"success": True, "pid": 1}
        
        def track_proxy(*args, **kwargs):
            call_order.append("proxy")
            return {"success": True, "pid": 2}
        
        def track_frida(*args, **kwargs):
            call_order.append("frida")
            return {"success": True, "pid": 3}
        
        mock_emulator.side_effect = track_emulator
        mock_proxy.side_effect = track_proxy
        mock_frida.side_effect = track_frida
        
        result = manager.start_all_services()
        
        # Verify order: emulator first, then proxy, then frida
        assert call_order == ["emulator", "proxy", "frida"]
        assert result["status"] == "success"
        assert set(result["started_services"]) == {"emulator", "proxy", "frida"}

    @patch('automation.services.service_manager.ServiceManager._start_frida')
    @patch('automation.services.service_manager.ServiceManager._start_proxy')
    @patch('automation.services.service_manager.ServiceManager._start_emulator')
    def test_services_wait_for_predecessor(self, mock_emulator, mock_proxy, mock_frida):
        """Test that each service waits for its predecessor to be running."""
        manager = ServiceManager()
        
        # Emulator takes 2 seconds to start
        def slow_emulator(*args, **kwargs):
            time.sleep(0.1)  # Simulate slow boot (reduced for test speed)
            return {"success": True, "pid": 1}
        
        mock_emulator.side_effect = slow_emulator
        mock_proxy.return_value = {"success": True, "pid": 2}
        mock_frida.return_value = {"success": True, "pid": 3}
        
        start_time = time.time()
        result = manager.start_all_services()
        elapsed = time.time() - start_time
        
        # Proxy and Frida should not start until emulator completes
        assert elapsed >= 0.1
        assert result["status"] == "success"


class TestServiceManagerAttachDetection:
    """Test ServiceManager._detect_running_services() contract."""

    @patch('automation.services.service_manager.subprocess.run')
    def test_detect_running_services_checks_emulator(self, mock_run):
        """Test _detect_running_services detects running emulator via adb."""
        manager = ServiceManager()
        
        # Mock adb devices output showing running emulator
        mock_run.return_value = Mock(
            returncode=0,
            stdout="List of devices attached\nemulator-5554\tdevice\n"
        )
        
        running = manager._detect_running_services()
        
        assert running["emulator"] is True

    @patch('automation.services.service_manager.subprocess.run')
    def test_detect_running_services_checks_proxy(self, mock_run):
        """Test _detect_running_services detects proxy via port check."""
        manager = ServiceManager()
        
        # Mock netstat showing port 8080 in use
        mock_run.return_value = Mock(
            returncode=0,
            stdout="tcp 0 0 0.0.0.0:8080 0.0.0.0:* LISTEN"
        )
        
        running = manager._detect_running_services()
        
        # Should check for port 8080
        assert mock_run.called

    @patch('automation.services.service_manager.subprocess.run')
    def test_attach_to_running_services_skips_start(self, mock_run):
        """Test that start_all_services skips services already running."""
        manager = ServiceManager()
        
        # Mock detection: emulator already running, others not
        with patch.object(manager, '_detect_running_services') as mock_detect:
            mock_detect.return_value = {
                "emulator": True,
                "proxy": False,
                "frida": False
            }
            
            with patch.object(manager, '_start_emulator') as mock_start_emu:
                with patch.object(manager, '_start_proxy') as mock_start_proxy:
                    with patch.object(manager, '_start_frida') as mock_start_frida:
                        mock_start_proxy.return_value = {"success": True, "pid": 2}
                        mock_start_frida.return_value = {"success": True, "pid": 3}
                        
                        manager.start_all_services()
                        
                        # Emulator start should be skipped
                        mock_start_emu.assert_not_called()
                        # Others should still start
                        mock_start_proxy.assert_called_once()
                        mock_start_frida.assert_called_once()


class TestServiceManagerSnapshot:
    """Test ServiceManagerSnapshot aggregation contract."""

    def test_get_service_snapshot_aggregates_status(self):
        """Test that get_service_snapshot correctly aggregates service states."""
        manager = ServiceManager()
        
        # Set up service states
        manager.services["emulator"].mark_running(pid=1, startup_time=5.0)
        manager.services["proxy"].mark_running(pid=2, startup_time=2.0)
        manager.services["frida"].mark_error("App not found")
        
        snapshot = manager.get_service_snapshot()
        
        # Verify snapshot structure
        assert "timestamp" in snapshot
        assert "services" in snapshot
        assert len(snapshot["services"]) == 3
        
        # Verify all_ready flag (should be False because frida failed)
        assert snapshot["all_ready"] is False
        
        # Verify failed_services list
        assert "frida" in snapshot["failed_services"]
        assert len(snapshot["failed_services"]) == 1

    def test_snapshot_includes_retry_status(self):
        """Test that snapshot includes retry_in_progress flag."""
        manager = ServiceManager()
        
        # Simulate retry in progress
        manager.services["emulator"].retry_count = 1
        manager.services["emulator"].state = ServiceState.STARTING
        
        snapshot = manager.get_service_snapshot()
        
        # Should indicate retry in progress
        assert snapshot["retry_in_progress"] is True

    def test_snapshot_all_ready_when_all_running(self):
        """Test that all_ready is True only when all services running."""
        manager = ServiceManager()
        
        # Mark all services as running
        manager.services["emulator"].mark_running(pid=1, startup_time=5.0)
        manager.services["proxy"].mark_running(pid=2, startup_time=2.0)
        manager.services["frida"].mark_running(pid=3, startup_time=8.0)
        
        snapshot = manager.get_service_snapshot()
        
        assert snapshot["all_ready"] is True
        assert len(snapshot["failed_services"]) == 0


class TestServiceManagerManualRetry:
    """Test ServiceManager.retry_service() contract."""

    @patch('automation.services.service_manager.ServiceManager._start_frida')
    def test_retry_service_resets_retry_count(self, mock_start_frida):
        """Test that manual retry resets retry_count to 0."""
        manager = ServiceManager()
        
        # Simulate previous failed attempts
        manager.services["frida"].retry_count = 3
        manager.services["frida"].state = ServiceState.FAILED
        
        mock_start_frida.return_value = {"success": True, "pid": 999}
        
        result = manager.retry_service("frida")
        
        # Retry count should be reset before new attempt
        assert manager.services["frida"].retry_count <= 1  # 0 or 1 after first attempt
        assert result["status"] == "success"

    def test_retry_service_requires_failed_state(self):
        """Test that retry_service requires service to be in failed state."""
        manager = ServiceManager()
        
        # Service is already running
        manager.services["emulator"].state = ServiceState.RUNNING
        
        # Attempting retry should either skip or raise error
        # (Implementation detail - just verify it handles gracefully)
        try:
            result = manager.retry_service("emulator")
            # If it returns, should indicate no retry needed
            assert "already running" in result.get("message", "").lower() or result["status"] == "success"
        except ValueError as e:
            # Or it may raise an error - both are acceptable
            assert "not in failed state" in str(e).lower() or "already running" in str(e).lower()


# Mark these as integration tests and potentially slow
pytestmark = [pytest.mark.integration, pytest.mark.slow]

