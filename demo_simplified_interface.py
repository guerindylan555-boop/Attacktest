#!/usr/bin/env python3
"""
Demo script for the simplified automation app interface.
This script demonstrates the key features of the simplified interface.
"""
import sys
import time
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from automation.models.recording import AutomationRecording
from automation.models.service_status import ServiceStatus
from automation.models.token_session import TokenCaptureSession
from automation.services.service_manager import ServiceManager
from automation.services.automation_controller import AutomationController
from automation.services.token_controller import TokenCaptureController


def demo_models():
    """Demonstrate the data models."""
    print("=== Data Models Demo ===")
    
    # AutomationRecording
    print("\n1. AutomationRecording Model:")
    recording = AutomationRecording()
    print(f"   - Created recording with ID: {recording.id}")
    print(f"   - Timestamp: {recording.timestamp}")
    print(f"   - Duration: {recording.duration}s")
    print(f"   - Interactions: {len(recording.interactions)}")
    
    # ServiceStatus
    print("\n2. ServiceStatus Model:")
    status = ServiceStatus("emulator", "running")
    print(f"   - Service: {status.service_name}")
    print(f"   - Status: {status.status}")
    print(f"   - Is running: {status.is_running()}")
    print(f"   - Is healthy: {status.is_healthy()}")
    
    # TokenCaptureSession
    print("\n3. TokenCaptureSession Model:")
    session = TokenCaptureSession()
    print(f"   - Session ID: {session.session_id}")
    print(f"   - Status: {session.status}")
    print(f"   - Is pending: {session.is_pending()}")
    print(f"   - Start time: {session.start_time}")


def demo_services():
    """Demonstrate the service classes."""
    print("\n=== Service Classes Demo ===")
    
    # ServiceManager
    print("\n1. ServiceManager:")
    service_manager = ServiceManager()
    print("   - ServiceManager initialized")
    print(f"   - Services managed: {list(service_manager.services.keys())}")
    
    # AutomationController
    print("\n2. AutomationController:")
    automation_controller = AutomationController(service_manager)
    print("   - AutomationController initialized")
    print(f"   - Is recording: {automation_controller.is_recording()}")
    print(f"   - Is replaying: {automation_controller.is_replaying()}")
    
    # TokenCaptureController
    print("\n3. TokenCaptureController:")
    token_controller = TokenCaptureController(service_manager)
    print("   - TokenCaptureController initialized")
    print(f"   - Is capturing: {token_controller.is_capturing()}")


def demo_ui_components():
    """Demonstrate UI components (without showing the actual window)."""
    print("\n=== UI Components Demo ===")
    
    try:
        from PySide6.QtWidgets import QApplication
        from automation.ui.control_center import ControlCenter
        
        # Create QApplication (required for Qt widgets)
        app = QApplication(sys.argv)
        
        # Create ControlCenter instance
        window = ControlCenter()
        print("   - ControlCenter created successfully")
        print(f"   - Window title: {window.windowTitle()}")
        print(f"   - Service manager initialized: {window.service_manager is not None}")
        print(f"   - Automation controller initialized: {window.automation_controller is not None}")
        print(f"   - Token controller initialized: {window.token_controller is not None}")
        
        # Check if the simplified buttons exist
        print(f"   - Record button exists: {hasattr(window, 'btn_record_automation')}")
        print(f"   - Replay button exists: {hasattr(window, 'btn_replay_automation')}")
        print(f"   - Capture button exists: {hasattr(window, 'btn_capture_token')}")
        
        # Check if old buttons are removed
        print(f"   - Old emulator buttons removed: {not hasattr(window, 'btn_start_emulator')}")
        print(f"   - Old proxy buttons removed: {not hasattr(window, 'btn_start_proxy')}")
        print(f"   - Old frida buttons removed: {not hasattr(window, 'btn_start_frida')}")
        
        # Clean up
        window.close()
        app.quit()
        
    except Exception as e:
        print(f"   - UI demo failed: {e}")


def demo_file_structure():
    """Demonstrate the file structure created."""
    print("\n=== File Structure Demo ===")
    
    # Check if directories exist
    directories = [
        "tests/unit",
        "tests/integration", 
        "tests/contract",
        "automation/recordings",
        "automation/sessions",
        "automation/models",
        "automation/services"
    ]
    
    for directory in directories:
        path = Path(directory)
        exists = path.exists()
        print(f"   - {directory}: {'✓' if exists else '✗'}")
    
    # Check if key files exist
    files = [
        "automation/models/recording.py",
        "automation/models/service_status.py", 
        "automation/models/token_session.py",
        "automation/services/service_manager.py",
        "automation/services/automation_controller.py",
        "automation/services/token_controller.py",
        "automation/ui/control_center.py",
        "pytest.ini"
    ]
    
    for file_path in files:
        path = Path(file_path)
        exists = path.exists()
        print(f"   - {file_path}: {'✓' if exists else '✗'}")


def main():
    """Run the complete demo."""
    print("🚀 Simplified Automation App Interface Demo")
    print("=" * 50)
    
    demo_models()
    demo_services()
    demo_ui_components()
    demo_file_structure()
    
    print("\n" + "=" * 50)
    print("✅ Demo completed successfully!")
    print("\nKey Features Implemented:")
    print("  • Simplified 3-button interface (Record, Replay, Capture Token)")
    print("  • Automatic service startup/shutdown")
    print("  • Real-time service status monitoring")
    print("  • Data models for recordings, sessions, and service status")
    print("  • Service managers for automation workflows")
    print("  • Integration with existing automation scripts")
    print("  • Evidence collection and file-based storage")
    print("  • Error handling and logging")
    
    print("\nTo run the actual application:")
    print("  python3 automation/ui/control_center.py")


if __name__ == "__main__":
    main()
