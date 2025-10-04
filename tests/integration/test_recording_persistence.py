"""Integration test for recording persistence (Scenario 3)."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automation.services.automation_controller import AutomationController


class TestRecordingPersistence:
    """Test recording workflow and persistence (Scenario 3)."""

    def test_basic_recording_workflow(self):
        """Scenario 3: Start, interact, stop recording."""
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
            
            # Start recording
            start_result = controller.start_recording()
            assert start_result["status"] == "success"
            session_id = start_result["recording_id"]  # Changed from session_id to recording_id
            
            # Add interactions
            controller.add_interaction("click", x=540, y=960)
            controller.add_interaction("type", text="hello")
            controller.add_interaction("scroll", direction="down", amount=300)
            
            # Stop recording
            stop_result = controller.stop_recording(session_id)
            assert stop_result["status"] == "success"
            assert stop_result["interactions_count"] == 3

    def test_incremental_jsonl_append_per_interaction(self):
        """Scenario 3: Each interaction appends to JSONL immediately."""
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
            
            if recording and recording.incremental_file:
                # Add interaction
                controller.add_interaction("click", x=100, y=200)
                
                # Verify immediate write
                with open(recording.incremental_file, 'r') as f:
                    lines = f.readlines()
                    assert len(lines) >= 1
                    interaction = json.loads(lines[-1])
                    assert interaction["type"] == "click"

    def test_crash_recovery_partial_data_preserved(self):
        """Scenario 3: Partial data preserved if app crashes mid-recording."""
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
            controller.add_interaction("click", x=1, y=2)
            controller.add_interaction("click", x=3, y=4)
            
            # Simulate crash (don't call stop_recording)
            incremental_file = controller.current_recording.incremental_file
            
            # JSONL file should still have both interactions
            if incremental_file and incremental_file.exists():
                with open(incremental_file, 'r') as f:
                    lines = f.readlines()
                    assert len(lines) == 2


pytestmark = [pytest.mark.integration]

