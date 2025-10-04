"""Unit tests for ServiceStatus retry logic."""
from datetime import datetime

import pytest

from automation.models.service_status import ServiceStatus, ServiceState


class TestServiceStatusRetryLogic:
    """Unit tests for ServiceStatus retry tracking."""

    def test_should_retry_returns_true_when_under_limit(self):
        """Test should_retry() returns True when retry_count < max_retries."""
        status = ServiceStatus(service_name="emulator")
        
        assert status.retry_count == 0
        assert status.max_retries == 3
        assert status.should_retry() is True
        
        status.retry_count = 1
        assert status.should_retry() is True
        
        status.retry_count = 2
        assert status.should_retry() is True

    def test_should_retry_returns_false_when_at_limit(self):
        """Test should_retry() returns False when retry_count >= max_retries."""
        status = ServiceStatus(service_name="proxy")
        
        status.retry_count = 3
        assert status.should_retry() is False
        
        status.retry_count = 4  # Even beyond limit
        assert status.should_retry() is False

    def test_begin_retry_attempt_increments_count(self):
        """Test begin_retry_attempt() increments retry_count."""
        status = ServiceStatus(service_name="frida")
        
        assert status.retry_count == 0
        
        status.begin_retry_attempt()
        assert status.retry_count == 1
        assert status.last_retry_at is not None
        assert isinstance(status.last_retry_at, datetime)
        
        status.begin_retry_attempt()
        assert status.retry_count == 2

    def test_last_retry_at_timestamp_updates(self):
        """Test last_retry_at timestamp is updated on retry."""
        status = ServiceStatus(service_name="emulator")
        
        assert status.last_retry_at is None
        
        status.begin_retry_attempt()
        first_retry = status.last_retry_at
        assert first_retry is not None
        
        import time
        time.sleep(0.01)
        
        status.begin_retry_attempt()
        second_retry = status.last_retry_at
        assert second_retry > first_retry

    def test_mark_running_resets_retry_count(self):
        """Test mark_running() resets retry_count to 0."""
        status = ServiceStatus(service_name="proxy")
        
        status.retry_count = 2
        status.mark_running(pid=123, startup_time=5.0)
        
        assert status.retry_count == 0
        assert status.state == ServiceState.RUNNING

    def test_retry_delay_field_exists(self):
        """Test retry_delay field has correct default."""
        status = ServiceStatus(service_name="emulator")
        
        assert status.retry_delay == 5.0
        assert isinstance(status.retry_delay, float)

    def test_max_retries_field_exists(self):
        """Test max_retries field has correct default."""
        status = ServiceStatus(service_name="frida")
        
        assert status.max_retries == 3
        assert isinstance(status.max_retries, int)


pytestmark = [pytest.mark.unit]

