#!/usr/bin/env python3
"""Comprehensive Frida server setup and management for Android devices."""

import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRIDA_VERSION = "17.3.2"
DEVICE_ID = os.getenv("MAYNDRIVE_DEVICE_ID", "emulator-5554")
PACKAGE = os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app")

class FridaSetup:
    def __init__(self):
        self.device_id = DEVICE_ID
        self.package = PACKAGE
        self.frida_version = FRIDA_VERSION
        self.frida_server_path = None
        self.device_arch = None
        
    def run_adb_command(self, args: list, capture_output: bool = True, timeout: int = 10) -> subprocess.CompletedProcess:
        """Run an ADB command with proper error handling."""
        cmd = ["adb", "-s", self.device_id] + args
        try:
            return subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                check=False
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"ADB command timed out: {' '.join(cmd)}")
        except FileNotFoundError:
            raise RuntimeError("ADB not found in PATH. Please install Android SDK platform-tools.")
    
    def check_device_connection(self, retries: int = 3) -> bool:
        """Check if device is connected and accessible."""
        for attempt in range(retries):
            try:
                result = self.run_adb_command(["get-state"])
                if result.returncode == 0 and result.stdout.strip() == "device":
                    return True
                if attempt < retries - 1:
                    print(f"[INFO] Device not ready, retrying in 2 seconds... (attempt {attempt + 1}/{retries})")
                    time.sleep(2)
            except Exception:
                if attempt < retries - 1:
                    print(f"[INFO] Device connection error, retrying in 2 seconds... (attempt {attempt + 1}/{retries})")
                    time.sleep(2)
        return False
    
    def get_device_architecture(self) -> Optional[str]:
        """Get the device's CPU architecture."""
        try:
            result = self.run_adb_command(["shell", "getprop", "ro.product.cpu.abi"])
            if result.returncode == 0:
                arch = result.stdout.strip()
                # Map Android architectures to Frida architectures
                arch_map = {
                    "armeabi-v7a": "arm",
                    "armeabi": "arm", 
                    "arm64-v8a": "arm64",
                    "x86": "x86",
                    "x86_64": "x86_64"
                }
                return arch_map.get(arch, arch)
        except Exception:
            pass
        return None
    
    def download_frida_server(self, arch: str) -> Optional[Path]:
        """Download the appropriate Frida server binary."""
        filename = f"frida-server-{self.frida_version}-android-{arch}"
        filename_xz = f"{filename}.xz"
        local_path = PROJECT_ROOT / "frida_servers" / filename
        local_path_xz = PROJECT_ROOT / "frida_servers" / filename_xz
        
        # Create directory if it doesn't exist
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if already downloaded and extracted
        if local_path.exists():
            print(f"[INFO] Frida server already exists: {local_path}")
            return local_path
        
        # Download compressed file from GitHub releases
        url = f"https://github.com/frida/frida/releases/download/{self.frida_version}/{filename_xz}"
        print(f"[INFO] Downloading Frida server from: {url}")
        
        try:
            import urllib.request
            import lzma
            
            # Download compressed file
            urllib.request.urlretrieve(url, local_path_xz)
            print(f"[INFO] Downloaded compressed file: {local_path_xz}")
            
            # Extract the .xz file
            with lzma.open(local_path_xz, 'rb') as compressed:
                with open(local_path, 'wb') as extracted:
                    extracted.write(compressed.read())
            
            # Remove compressed file
            local_path_xz.unlink()
            
            # Make executable
            local_path.chmod(0o755)
            print(f"[SUCCESS] Downloaded and extracted Frida server: {local_path}")
            return local_path
            
        except Exception as e:
            print(f"[ERROR] Failed to download Frida server: {e}")
            # Clean up partial files
            for path in [local_path, local_path_xz]:
                if path.exists():
                    path.unlink()
            return None
    
    def push_frida_server(self, local_path: Path) -> bool:
        """Push Frida server to device."""
        remote_path = "/data/local/tmp/frida-server"
        
        print(f"[INFO] Pushing Frida server to device...")
        result = self.run_adb_command(["push", str(local_path), remote_path])
        
        if result.returncode != 0:
            print(f"[ERROR] Failed to push Frida server: {result.stderr}")
            return False
        
        # Make executable
        result = self.run_adb_command(["shell", "chmod", "755", remote_path])
        if result.returncode != 0:
            print(f"[ERROR] Failed to make Frida server executable: {result.stderr}")
            return False
        
        print(f"[SUCCESS] Frida server pushed and made executable")
        return True
    
    def is_frida_server_running(self) -> bool:
        """Check if Frida server is already running on device."""
        try:
            result = self.run_adb_command(["shell", "ps", "-A"])
            return "frida-server" in result.stdout
        except Exception:
            return False
    
    def start_frida_server(self) -> bool:
        """Start Frida server on device."""
        if self.is_frida_server_running():
            print("[INFO] Frida server is already running")
            return True
        
        print("[INFO] Starting Frida server...")
        
        # Use Python-based approach for better error handling
        script_path = PROJECT_ROOT / "automation" / "scripts" / "start_frida_python.py"
        try:
            result = subprocess.run(
                [sys.executable, str(script_path), self.device_id],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("[SUCCESS] Frida server started successfully")
                return True
            else:
                print(f"[ERROR] Failed to start Frida server: {result.stderr}")
                print(f"[DEBUG] Output: {result.stdout}")
                return False
                
        except subprocess.TimeoutExpired:
            print("[ERROR] Frida server startup timed out")
            return False
        except Exception as e:
            print(f"[ERROR] Exception starting Frida server: {e}")
            return False
    
    def stop_frida_server(self) -> bool:
        """Stop Frida server on device."""
        print("[INFO] Stopping Frida server...")
        result = self.run_adb_command(["shell", "su", "-c", "pkill -f frida-server"])
        
        if result.returncode == 0:
            print("[SUCCESS] Frida server stopped")
            return True
        else:
            print("[INFO] Frida server was not running")
            return True
    
    def verify_frida_connection(self) -> bool:
        """Verify that Frida can connect to the device."""
        try:
            result = subprocess.run(
                ["frida-ps", "-U"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def setup_frida_server(self) -> bool:
        """Complete Frida server setup process."""
        print("=" * 60)
        print("FRIDA SERVER SETUP")
        print("=" * 60)
        
        # Check device connection
        if not self.check_device_connection():
            print(f"[ERROR] Device {self.device_id} is not connected or not accessible")
            return False
        
        print(f"[SUCCESS] Device {self.device_id} is connected")
        
        # Get device architecture
        self.device_arch = self.get_device_architecture()
        if not self.device_arch:
            print("[ERROR] Could not determine device architecture")
            return False
        
        print(f"[SUCCESS] Device architecture: {self.device_arch}")
        
        # Download Frida server
        local_path = self.download_frida_server(self.device_arch)
        if not local_path:
            return False
        
        # Push to device
        if not self.push_frida_server(local_path):
            return False
        
        # Start Frida server
        if not self.start_frida_server():
            return False
        
        # Verify connection
        if not self.verify_frida_connection():
            print("[ERROR] Frida connection verification failed")
            return False
        
        print("[SUCCESS] Frida server setup completed successfully")
        return True
    
    def ensure_frida_ready(self) -> bool:
        """Ensure Frida server is ready for use."""
        if not self.check_device_connection():
            print(f"[ERROR] Device {self.device_id} is not connected")
            return False
        
        if not self.is_frida_server_running():
            print("[INFO] Frida server not running, starting...")
            if not self.start_frida_server():
                return False
        
        if not self.verify_frida_connection():
            print("[ERROR] Frida connection not working")
            return False
        
        return True


def main():
    """Main function for standalone execution."""
    setup = FridaSetup()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "setup":
            success = setup.setup_frida_server()
            sys.exit(0 if success else 1)
        
        elif command == "start":
            success = setup.start_frida_server()
            sys.exit(0 if success else 1)
        
        elif command == "stop":
            success = setup.stop_frida_server()
            sys.exit(0 if success else 1)
        
        elif command == "status":
            connected = setup.check_device_connection()
            running = setup.is_frida_server_running() if connected else False
            print(f"Device connected: {connected}")
            print(f"Frida server running: {running}")
            sys.exit(0)
        
        elif command == "ensure":
            success = setup.ensure_frida_ready()
            sys.exit(0 if success else 1)
        
        else:
            print(f"Unknown command: {command}")
            print("Available commands: setup, start, stop, status, ensure")
            sys.exit(1)
    
    else:
        # Default: run full setup
        success = setup.setup_frida_server()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
