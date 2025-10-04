"""ServiceManager handles background service lifecycle with retry awareness."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import threading
import zipfile
import os
from pathlib import Path
import socket
from typing import Any, Dict, Iterable, List, Optional

from automation.models.service_status import (
    ServiceManagerSnapshot,
    ServiceState,
    ServiceStatus,
)
from automation.scripts import run_hooks


class ServiceManager:
    """Manage emulator, proxy, and Frida services for the automation UI."""

    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    MANAGED_SERVICES: Dict[str, Path] = {
        "emulator": Path.home() / "android-tools" / "restart_mayndrive_emulator.sh",
        "proxy": Path("mitmdump"),
        "frida": PROJECT_ROOT / "automation" / "scripts" / "run_hooks.py",
        "appium": Path("appium"),
    }
    FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"
    FRIDA_SERVER_LOCAL_CANDIDATES = (
        PROJECT_ROOT / "frida-server",
        Path.home() / "android-tools" / "frida-server",
        Path.home() / "android-tools" / "vendor" / "frida" / "frida-server",
    )
    MAYNDRIVE_PACKAGE_NAME = "fr.mayndrive.app"
    MAYNDRIVE_PACKAGE_CANDIDATES = (
        PROJECT_ROOT / "Mayn Drive_1.1.34.xapk",
        PROJECT_ROOT / "mayndrive.apk",
        PROJECT_ROOT / "apk" / "mayndrive.apk",
        Path.home() / "android-tools" / "mayndrive.apk",
        Path.home() / "Downloads" / "mayndrive.apk",
    )
    MAYNDRIVE_APK_ENV = os.getenv("MAYNDRIVE_APK")
    MAYNDRIVE_XAPK_ENV = os.getenv("MAYNDRIVE_XAPK")
    MAYNDRIVE_APK_URL = os.getenv("MAYNDRIVE_APK_URL")

    def __init__(self) -> None:
        self.services: Dict[str, ServiceStatus] = {
            name: ServiceStatus(name) for name in self.MANAGED_SERVICES
        }
        self._processes: Dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start_all_services(self) -> Dict[str, Any]:
        """Attempt to start all managed services and return a snapshot payload."""

        with self._lock:
            # Detect already-running services to avoid duplicates
            running = self._detect_running_services()
            started_services = []
            failed_services = []
            
            for name in self.services:
                if running.get(name, False):
                    print(f"[INFO] {name} already running, attaching to existing instance")
                    # Mark as running without starting
                    self.services[name].mark_running()
                    started_services.append(name)
                else:
                    result = self._start_service(name)
                    self._apply_service_result(name, result)
                    if self.services[name].status == "running":
                        started_services.append(name)
                    else:
                        failed_services.append(name)

            snapshot = self._snapshot()
            status = "success" if snapshot.all_ready else ("partial" if started_services else "failed")
            return {
                "status": status,
                "snapshot": snapshot.to_dict(),
                "started_services": started_services,
                "failed_services": failed_services
            }

    def stop_all_services(self) -> Dict[str, Any]:
        with self._lock:
            stopped: List[str] = []
            for name in list(self.services):
                try:
                    self._stop_service(name)
                    stopped.append(name)
                    self.services[name].mark_stopped()
                except Exception as exc:  # noqa: BLE001
                    print(f"Error stopping {name}: {exc}")
            return {"status": "success", "stopped_services": stopped}

    def get_service_status(self) -> Dict[str, Any]:
        """Refresh health checks and return the latest snapshot."""

        with self._lock:
            self._refresh_statuses()
            return self._snapshot().to_dict()

    def get_service_snapshot(self, *, refresh: bool = False) -> Dict[str, Any]:
        with self._lock:
            if refresh:
                self._refresh_statuses()
            return self._snapshot().to_dict()

    def retry_services(self, services: Iterable[str]) -> Dict[str, Any]:
        with self._lock:
            for name in services:
                if name not in self.services:
                    continue
                # Reset retry attempt so another attempt is permitted
                status = self.services[name]
                if status.retry_attempt >= status.max_retries:
                    status.retry_attempt = status.max_retries - 1
                result = self._start_service(name)
                self._apply_service_result(name, result)
            return self._snapshot().to_dict()

    def retry_service(self, service_name: str) -> Dict[str, Any]:
        """Manually retry a single failed service.
        
        Args:
            service_name: Name of service to retry
            
        Returns:
            Dict with status and service_status
        """
        with self._lock:
            if service_name not in self.services:
                return {"status": "error", "error": f"Unknown service: {service_name}"}
            
            status = self.services[service_name]
            
            # Reset retry count for manual retry
            status.retry_count = 0
            status.retry_attempt = 0
            
            result = self._start_service(service_name)
            
            if isinstance(result, ServiceStatus):
                return {
                    "status": "success" if result.status == "running" else "failed",
                    "service_status": result
                }
            return {"status": "error", "error": "Unknown result type"}

    def is_service_ready(self, service_name: str) -> bool:
        return self.services[service_name].is_running

    def are_all_services_ready(self) -> bool:
        return all(status.is_running for status in self.services.values())

    def get_service_startup_time(self, service_name: str) -> float:
        return self.services[service_name].startup_time

    def cleanup(self) -> Dict[str, Any]:
        result = self.stop_all_services()
        for process in self._processes.values():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        self._processes.clear()
        self._kill_emulator_device()
        self._stop_frida_server()
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _detect_running_services(self) -> Dict[str, bool]:
        """Detect which services are already running.
        
        Returns:
            Dict mapping service names to True/False (running/not running)
        """
        running = {}
        
        # Check emulator via adb devices
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Look for emulator-* in output
            running["emulator"] = "emulator-" in result.stdout and "device" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            running["emulator"] = False
        
        # Check proxy via port 8080
        try:
            result = subprocess.run(
                ["netstat", "-tnlp"],
                capture_output=True,
                text=True,
                timeout=5
            )
            running["proxy"] = ":8080" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # Try alternate method with lsof
            try:
                result = subprocess.run(
                    ["lsof", "-i", ":8080"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                running["proxy"] = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                running["proxy"] = False
        
        # Check Frida via frida-ps -U
        try:
            result = subprocess.run(
                ["frida-ps", "-U"],
                capture_output=True,
                text=True,
                timeout=5
            )
            running["frida"] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            running["frida"] = False
        
        # Check Appium by probing port 4723
        try:
            with socket.create_connection(("127.0.0.1", 4723), timeout=1):
                running["appium"] = True
        except Exception:
            running["appium"] = False
        
        return running

    def _snapshot(self) -> ServiceManagerSnapshot:
        return ServiceManagerSnapshot.from_services(self.services.values())

    def _refresh_statuses(self) -> None:
        for name in self.services:
            result = self._check_service_health(name)
            if result is not None:
                self.services[name] = result

    def _apply_service_result(self, service_name: str, result: Any) -> None:
        status = self.services[service_name]
        if isinstance(result, ServiceStatus):
            self.services[service_name] = result
            return
        if not isinstance(result, dict):
            return

        status.retry_attempt = result.get("retry_attempt", status.retry_attempt)
        status.max_retries = result.get("max_retries", status.max_retries)
        status.startup_time = result.get("startup_time", status.startup_time)

        payload_status = result.get("status", status.status)
        if payload_status == ServiceState.RUNNING.value or payload_status == "running":
            status.mark_running(pid=result.get("pid"), startup_time=result.get("startup_time"))
        elif payload_status == ServiceState.ERROR.value or payload_status == "error":
            message = result.get("error_message") or result.get("error") or "Unknown error"
            status.mark_error(message, error_code=result.get("last_error_code"))
        elif payload_status == ServiceState.STARTING.value or payload_status == "starting":
            status.begin_start_attempt()
        else:
            status.record_health_check()

        self.services[service_name] = status

    def _start_service(self, service_name: str) -> Any:
        status = self.services[service_name]
        
        # Retry loop: attempt up to max_retries times
        for attempt in range(status.max_retries):
            if attempt > 0:
                # This is a retry - log it and wait
                print(f"[INFO] Retry {attempt}/{status.max_retries} for {service_name}")
                status.begin_retry_attempt()
                time.sleep(status.retry_delay)
            else:
                # First attempt
                status.begin_start_attempt()
            
            start_time = time.time()

            try:
                if service_name == "emulator":
                    result = self._start_emulator()
                elif service_name == "proxy":
                    result = self._start_proxy()
                elif service_name == "frida":
                    result = self._start_frida()
                elif service_name == "appium":
                    result = self._start_appium()
                else:
                    raise ValueError(f"Unknown service: {service_name}")

                elapsed = time.time() - start_time
                if isinstance(result, ServiceStatus):
                    self.services[service_name] = result
                    return result

                if result.get("success"):
                    status.mark_running(pid=result.get("pid"), startup_time=elapsed)
                    print(f"[INFO] {service_name} started successfully on attempt {attempt + 1}")
                    return status
                else:
                    error_msg = result.get("error", "Unknown error")
                    print(f"[WARN] {service_name} failed on attempt {attempt + 1}: {error_msg}")
                    status.mark_error(error_msg)
                    # Continue to next retry if available
            except Exception as exc:  # noqa: BLE001
                print(f"[ERROR] {service_name} exception on attempt {attempt + 1}: {exc}")
                status.mark_error(str(exc))
                # Continue to next retry if available
        
        # All retries exhausted
        print(f"[ERROR] {service_name} failed after {status.max_retries} attempts")
        return status

    def _stop_service(self, service_name: str) -> None:
        process = self._processes.get(service_name)
        if not process:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self._processes.pop(service_name, None)

    def _check_service_health(self, service_name: str) -> Optional[ServiceStatus]:
        if service_name == "emulator":
            return ServiceStatus.check_emulator_status()
        if service_name == "proxy":
            return ServiceStatus.check_proxy_status()
        if service_name == "frida":
            return ServiceStatus.check_frida_status()
        if service_name == "appium":
            return ServiceStatus.check_appium_status()
        return None

    def _kill_emulator_device(self) -> None:
        try:
            subprocess.run(
                ["adb", "-s", "emulator-5554", "emu", "kill"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except Exception:  # noqa: BLE001
            pass

    def _stop_frida_server(self) -> None:
        try:
            subprocess.run(
                ["adb", "shell", "pkill -f frida-server"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Service-specific starters
    # ------------------------------------------------------------------
    def _start_emulator(self) -> Dict[str, Any]:
        script = self.MANAGED_SERVICES["emulator"]
        print("[EMULATOR] Starting ADB server...")
        try:
            subprocess.run(
                ["adb", "start-server"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except Exception:  # noqa: BLE001
            pass

        # Check if device is already ready
        print("[EMULATOR] Checking if device is already running...")
        if self._ensure_device_ready(timeout=15):
            print("[EMULATOR] Device is already ready!")
            print("[EMULATOR] Waiting for boot to complete...")
            if self._wait_for_boot_complete(timeout=30):
                print("[EMULATOR] Boot completed!")
                ensure_app = self._ensure_mayndrive_installed()
                if ensure_app.get("status") == "error":
                    return {
                        "success": False,
                        "error": ensure_app.get("error", "MaynDrive not installed"),
                        "error_message": ensure_app.get("details"),
                    }
                print("[EMULATOR] MaynDrive app is installed and ready!")
                return {"success": True, "pid": None}
            else:
                print("[EMULATOR] Boot not complete, continuing anyway...")

        # Device not ready, try to start emulator
        print(f"[EMULATOR] Device not ready, looking for emulator script: {script}")
        if script.exists() and script.is_file():
            print(f"[EMULATOR] Starting emulator via {script}...")
            proc = subprocess.Popen(
                ["bash", str(script)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._processes["emulator"] = proc
            print("[EMULATOR] Waiting for device to be ready (up to 90 seconds)...")
            if self._ensure_device_ready(timeout=90):
                print("[EMULATOR] Device is ready!")
                print("[EMULATOR] Waiting for boot to complete...")
                self._wait_for_boot_complete(timeout=60)
                print("[EMULATOR] Ensuring MaynDrive app is installed...")
                ensure_app = self._ensure_mayndrive_installed()
                if ensure_app.get("status") == "error":
                    return {
                        "success": False,
                        "error": ensure_app.get("error", "MaynDrive not installed"),
                        "error_message": ensure_app.get("details"),
                    }
                print("[EMULATOR] All ready!")
                return {"success": True, "pid": proc.pid}
            return {"success": False, "error": "Timed out waiting for emulator"}
        
        print(f"[EMULATOR] Emulator script not found at {script}")
        return {"success": False, "error": "Emulator restart script not found"}

    def _start_proxy(self) -> Dict[str, Any]:
        print("[PROXY] Checking if mitmproxy is already running...")
        try:
            result = subprocess.run(
                ["tmux", "has-session", "-t", "mitmproxy_session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            if result.returncode == 0:
                print("[PROXY] Mitmproxy session already exists!")
                return {"success": True, "pid": None}

            print("[PROXY] Starting mitmproxy in tmux session...")
            process = subprocess.Popen(
                [
                    "tmux",
                    "new-session",
                    "-d",
                    "-s",
                    "mitmproxy_session",
                    "mitmdump",
                    "--listen-port",
                    "8080",
                ]
            )
            time.sleep(3)
            check = subprocess.run(
                ["tmux", "has-session", "-t", "mitmproxy_session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            if check.returncode == 0:
                self._processes["proxy"] = process
                print("[PROXY] Mitmproxy started successfully on port 8080!")
                return {"success": True, "pid": process.pid}
            print("[PROXY] Failed to verify mitmproxy session")
            return {"success": False, "error": "Failed to start mitmproxy"}
        except subprocess.TimeoutExpired:
            print("[PROXY] Timeout while starting mitmproxy")
            return {"success": False, "error": "tmux command timeout"}
        except FileNotFoundError:
            print("[PROXY] tmux or mitmdump command not found")
            return {"success": False, "error": "tmux or mitmproxy not found"}
        except Exception as exc:  # noqa: BLE001
            print(f"[PROXY] Error: {exc}")
            return {"success": False, "error": str(exc)}

    def _start_frida(self) -> Dict[str, Any]:
        print("[FRIDA] Starting Frida service...")
        print("[FRIDA] Checking device connection...")
        if not self._ensure_device_ready(timeout=30):
            print("[FRIDA] Device is not ready!")
            return {"success": False, "error": "Device offline while launching Frida"}

        print("[FRIDA] Ensuring frida-server is running on device...")
        ensure_result = self._start_frida_server()
        if ensure_result.get("status") == "error":
            print(f"[FRIDA] Failed to start frida-server: {ensure_result.get('error')}")
            return {
                "success": False,
                "error": ensure_result.get("error", "Unable to start frida-server"),
                "error_message": ensure_result.get("details"),
            }
        print("[FRIDA] frida-server is running!")

        script = self.MANAGED_SERVICES["frida"]
        if not script.exists():
            print(f"[FRIDA] Hook script not found: {script}")
            return {"success": False, "error": f"Frida hook script missing: {script}"}

        try:
            # Use attach mode (default) with auto-launch enabled
            # This will attach to running app or launch it if needed
            print("[FRIDA] Launching Frida with auto-attach mode...")
            print("[FRIDA] This will automatically launch MaynDrive app if not running...")
            proc, log_file = run_hooks.run_frida(attach_mode=True, auto_launch=True)
            self._processes["frida_hook"] = proc
            print("[FRIDA] Verifying Frida process is stable...")
            time.sleep(5)
            if proc.poll() is None:
                print(f"[FRIDA] Success! Frida is running (PID: {proc.pid})")
                print(f"[FRIDA] Logs: {log_file}")
                return {"success": True, "pid": proc.pid, "log_file": str(log_file)}
            snippet = self._read_tail(log_file)
            print("[FRIDA] Frida exited unexpectedly!")
            print(f"[FRIDA] Log snippet: {snippet}")
            # Fall back to spawn mode if attach exited early
            print("[FRIDA] Falling back to spawn mode...")
            proc2, log_file2 = run_hooks.run_frida(attach_mode=False, auto_launch=False)
            self._processes["frida_hook"] = proc2
            time.sleep(5)
            if proc2.poll() is None:
                print(f"[FRIDA] Spawn mode success (PID: {proc2.pid})")
                print(f"[FRIDA] Logs: {log_file2}")
                return {"success": True, "pid": proc2.pid, "log_file": str(log_file2)}
            snippet2 = self._read_tail(log_file2)
            return {
                "success": False,
                "error": "Frida hook exited (attach and spawn failed)",
                "error_message": snippet2 or f"See log: {log_file2}",
            }
        except FileNotFoundError:
            print("[FRIDA] frida command not found in PATH")
            return {"success": False, "error": "frida CLI not found in PATH"}
        except RuntimeError as exc:
            # Handle app not running or failed to launch
            print(f"[FRIDA] Runtime error: {exc}")
            # Attempt spawn as a fallback when auto-attach launch failed
            try:
                print("[FRIDA] Falling back to spawn mode after launch error...")
                proc2, log_file2 = run_hooks.run_frida(attach_mode=False, auto_launch=False)
                self._processes["frida_hook"] = proc2
                time.sleep(5)
                if proc2.poll() is None:
                    print(f"[FRIDA] Spawn mode success (PID: {proc2.pid})")
                    print(f"[FRIDA] Logs: {log_file2}")
                    return {"success": True, "pid": proc2.pid, "log_file": str(log_file2)}
                snippet2 = self._read_tail(log_file2)
                return {
                    "success": False,
                    "error": "App launch failed (spawn fallback exited)",
                    "error_message": snippet2 or str(exc),
                }
            except Exception as exc2:  # noqa: BLE001
                return {
                    "success": False,
                    "error": "App launch failed (spawn fallback error)",
                    "error_message": f"{exc}; fallback: {exc2}",
                }
        except Exception as exc:  # noqa: BLE001
            print(f"[FRIDA] Unexpected error: {exc}")
            return {"success": False, "error": str(exc)}

    def _start_appium(self) -> Dict[str, Any]:
        print("[APPIUM] Checking if Appium server is already running...")
        try:
            with socket.create_connection(("127.0.0.1", 4723), timeout=1):
                print("[APPIUM] Appium already running on 127.0.0.1:4723")
                return {"success": True, "pid": None}
        except Exception:
            pass

        # Try tmux session reuse
        try:
            result = subprocess.run(
                ["tmux", "has-session", "-t", "appium_session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            if result.returncode == 0:
                print("[APPIUM] tmux appium_session exists; waiting for server...")
                time.sleep(2)
                try:
                    with socket.create_connection(("127.0.0.1", 4723), timeout=2):
                        return {"success": True, "pid": None}
                except Exception:
                    pass
        except Exception:
            pass

        # Start appium in tmux, try v2 `appium server` first, then legacy `appium`
        cmd_variants = [
            ["appium", "server", "--address", "127.0.0.1", "--port", "4723", "--base-path", "/wd/hub"],
            ["appium", "--address", "127.0.0.1", "--port", "4723", "--base-path", "/wd/hub"],
        ]
        last_error: Optional[str] = None
        for args in cmd_variants:
            try:
                print(f"[APPIUM] Starting Appium via: {' '.join(args)}")
                process = subprocess.Popen([
                    "tmux",
                    "new-session",
                    "-d",
                    "-s",
                    "appium_session",
                    *args,
                ])
                self._processes["appium"] = process
                # Wait for server to become responsive
                for _ in range(10):
                    try:
                        with socket.create_connection(("127.0.0.1", 4723), timeout=1):
                            print("[APPIUM] Appium started successfully on 4723")
                            return {"success": True, "pid": process.pid}
                    except Exception:
                        time.sleep(1)
                last_error = "timeout waiting for port 4723"
            except FileNotFoundError as e:
                last_error = str(e)
                continue
            except Exception as exc:
                last_error = str(exc)
                continue
        return {"success": False, "error": f"Failed to start Appium: {last_error or 'unknown error'}"}

    def _start_frida_server(self) -> Dict[str, Any]:
        if not self._ensure_device_ready(timeout=30):
            return {"status": "error", "error": "Device not ready"}

        try:
            check = subprocess.run(
                [
                    "adb",
                    "-s",
                    "emulator-5554",
                    "shell",
                    f"ls {self.FRIDA_SERVER_REMOTE_PATH}"
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if check.returncode != 0:
                ensure_binary = self._push_frida_binary()
                if ensure_binary.get("status") == "error":
                    return ensure_binary

            subprocess.run(
                [
                    "adb",
                    "-s",
                    "emulator-5554",
                    "shell",
                    f"chmod 755 {self.FRIDA_SERVER_REMOTE_PATH}"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )

            subprocess.run(
                [
                    "adb",
                    "-s",
                    "emulator-5554",
                    "shell",
                    f"{self.FRIDA_SERVER_REMOTE_PATH} &"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            # also attempt via su for rooted emulator
            subprocess.run(
                [
                    "adb",
                    "-s",
                    "emulator-5554",
                    "shell",
                    f"su -c '{self.FRIDA_SERVER_REMOTE_PATH} &'"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )

            time.sleep(2)
            verify = subprocess.run(
                ["adb", "-s", "emulator-5554", "shell", "ps -A | grep frida-server"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "frida-server" in verify.stdout:
                return {"status": "ok"}
            return {
                "status": "error",
                "error": "frida-server failed to start",
                "details": verify.stdout.strip() or verify.stderr.strip(),
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Timeout starting frida-server"}
        except FileNotFoundError:
            return {"status": "error", "error": "adb command not found"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc)}

    def _push_frida_binary(self) -> Dict[str, Any]:
        for candidate in self.FRIDA_SERVER_LOCAL_CANDIDATES:
            if not candidate.exists():
                continue
            try:
                result = subprocess.run(
                    ["adb", "-s", "emulator-5554", "push", str(candidate), self.FRIDA_SERVER_REMOTE_PATH],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    continue
                subprocess.run(
                    [
                        "adb",
                        "-s",
                        "emulator-5554",
                        "shell",
                        f"chmod 755 {self.FRIDA_SERVER_REMOTE_PATH}"
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                return {"status": "ok"}
            except subprocess.TimeoutExpired:
                continue
            except FileNotFoundError:
                break
        return {
            "status": "error",
            "error": "frida-server binary not found locally",
            "details": "Place frida-server under project root or ~/android-tools/",
        }

    def _ensure_mayndrive_installed(self) -> Dict[str, Any]:
        if not self._ensure_device_ready(timeout=30):
            return {"status": "error", "error": "Device not ready"}

        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    "emulator-5554",
                    "shell",
                    "pm",
                    "list",
                    "packages",
                    self.MAYNDRIVE_PACKAGE_NAME,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if self.MAYNDRIVE_PACKAGE_NAME in result.stdout:
                return {"status": "ok"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Timeout checking packages"}
        except FileNotFoundError:
            return {"status": "error", "error": "adb command not found"}

        install_result = self._install_mayndrive_from_local_sources()
        if install_result.get("status") == "error":
            return install_result
        return {"status": "ok"}

    def _install_mayndrive_from_local_sources(self) -> Dict[str, Any]:
        # Build candidate list (env vars take precedence)
        env_candidates: List[Path] = []
        if self.MAYNDRIVE_APK_ENV:
            env_candidates.append(Path(self.MAYNDRIVE_APK_ENV))
        if self.MAYNDRIVE_XAPK_ENV:
            env_candidates.append(Path(self.MAYNDRIVE_XAPK_ENV))

        candidates = [*env_candidates, *self.MAYNDRIVE_PACKAGE_CANDIDATES]

        for candidate in candidates:
            if not candidate.exists():
                continue
            if candidate.is_dir():
                result = self._install_from_directory(candidate)
                if result.get("status") == "ok":
                    return result
                # fallthrough on error to try other candidates
                continue
            suffix = candidate.suffix.lower()
            if suffix == ".apk":
                return self._adb_install_apk(candidate)
            if suffix == ".xapk" or zipfile.is_zipfile(candidate):
                result = self._install_from_xapk(candidate)
                if result.get("status") == "ok":
                    return result

        # If a URL is provided, attempt to download and install
        if self.MAYNDRIVE_APK_URL:
            dl_result = self._download_and_install_apk(self.MAYNDRIVE_APK_URL)
            if dl_result.get("status") == "ok":
                return dl_result
            return dl_result
        return {
            "status": "error",
            "error": "MaynDrive package not found",
            "details": (
                "Place MaynDrive APK/XAPK in one of: "
                f"{self.PROJECT_ROOT}, {self.PROJECT_ROOT/'apk'}, "
                f"{Path.home()/'android-tools'}, {Path.home()/'Downloads'} "
                "or set MAYNDRIVE_APK/MAYNDRIVE_XAPK env vars. "
                "You can also set MAYNDRIVE_APK_URL to download automatically."
            ),
        }

    def _download_and_install_apk(self, url: str) -> Dict[str, Any]:
        try:
            import requests  # lazy import; present in requirements
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir) / "mayndrive.apk"
                resp = requests.get(url, timeout=60)
                if resp.status_code != 200:
                    return {
                        "status": "error",
                        "error": f"Failed to download APK (HTTP {resp.status_code})",
                    }
                tmp_path.write_bytes(resp.content)
                return self._adb_install_apk(tmp_path)
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc)}

    def _install_from_xapk(self, xapk_path: Path) -> Dict[str, Any]:
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                with zipfile.ZipFile(xapk_path) as archive:
                    apk_infos = [
                        info for info in archive.infolist() if info.filename.endswith(".apk")
                    ]
                    if not apk_infos:
                        return {
                            "status": "error",
                            "error": "No APK found inside XAPK",
                            "details": str(xapk_path),
                        }
                    # Extract all APK splits and install-multiple with base first
                    # Prefer base.apk first if present
                    apk_infos.sort(key=lambda info: (0 if info.filename.endswith("base.apk") else 1, -info.file_size))
                    extracted: List[Path] = []
                    for info in apk_infos:
                        archive.extract(info, tmp_dir)
                        extracted.append(Path(tmp_dir) / info.filename)
                    if len(extracted) == 1:
                        return self._adb_install_apk(extracted[0])
                    return self._adb_install_multi_apk(extracted)
        except zipfile.BadZipFile:
            return {
                "status": "error",
                "error": "Invalid XAPK archive",
                "details": str(xapk_path),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc)}

    def _install_from_directory(self, dir_path: Path) -> Dict[str, Any]:
        try:
            apks = sorted(dir_path.glob("**/*.apk"))
            if not apks:
                return {"status": "error", "error": "No APKs in directory", "details": str(dir_path)}
            # If there is only one, install single; else multi with base first
            if len(apks) == 1:
                return self._adb_install_apk(apks[0])
            apks.sort(key=lambda p: (0 if p.name.endswith("base.apk") else 1, -p.stat().st_size))
            return self._adb_install_multi_apk(apks)
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc)}

    def _adb_install_multi_apk(self, apk_paths: List[Path]) -> Dict[str, Any]:
        try:
            cmd = ["adb", "-s", "emulator-5554", "install-multiple", "-r", *[str(p) for p in apk_paths]]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode == 0:
                return {"status": "ok"}
            return {
                "status": "error",
                "error": "adb install-multiple failed",
                "details": result.stderr.strip() or result.stdout.strip(),
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Timeout installing split APKs"}
        except FileNotFoundError:
            return {"status": "error", "error": "adb command not found"}

    def _adb_install_apk(self, apk_path: Path) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                ["adb", "-s", "emulator-5554", "install", "-r", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                return {"status": "ok"}
            return {
                "status": "error",
                "error": "adb install failed",
                "details": result.stderr.strip() or result.stdout.strip(),
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Timeout installing APK"}
        except FileNotFoundError:
            return {"status": "error", "error": "adb command not found"}

    def _ensure_device_ready(self, timeout: int = 60) -> bool:
        start = time.time()
        try:
            subprocess.run(
                ["adb", "start-server"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except Exception:  # noqa: BLE001
            pass

        while time.time() - start < timeout:
            try:
                result = subprocess.run(
                    ["adb", "-s", "emulator-5554", "get-state"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip() == "device":
                    return True
            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                return False
            time.sleep(2)
        return False

    def _wait_for_boot_complete(self, timeout: int = 60) -> bool:
        """Wait for Android boot to complete (sys.boot_completed = 1)."""
        start = time.time()
        print("[EMULATOR] Waiting for Android boot completion...")
        
        while time.time() - start < timeout:
            try:
                result = subprocess.run(
                    ["adb", "-s", "emulator-5554", "shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip() == "1":
                    print("[EMULATOR] Boot completed!")
                    return True
            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                return False
            time.sleep(3)
        
        print("[EMULATOR] Boot completion check timed out")
        return False

    def _read_tail(self, path: Path, max_bytes: int = 400) -> str:
        try:
            data = path.read_bytes()
        except Exception:  # noqa: BLE001
            return ""
        return data[-max_bytes:].decode("utf-8", errors="ignore").strip()
