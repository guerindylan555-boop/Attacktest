#!/bin/bash
# Simple script to start Frida server on Android device

DEVICE_ID=${1:-"emulator-5554"}

echo "[INFO] Starting Frida server on device $DEVICE_ID"

# Wait for device to be ready
for i in {1..10}; do
    if adb -s "$DEVICE_ID" get-state 2>/dev/null | grep -q "device"; then
        echo "[INFO] Device is ready"
        break
    fi
    echo "[INFO] Waiting for device to be ready... ($i/10)"
    sleep 2
done

# Check if device is ready
if ! adb -s "$DEVICE_ID" get-state 2>/dev/null | grep -q "device"; then
    echo "[ERROR] Device $DEVICE_ID is not ready"
    exit 1
fi

# Kill any existing Frida server
echo "[INFO] Killing existing Frida server processes..."
adb -s "$DEVICE_ID" shell "su -c 'pkill -f frida-server'" 2>/dev/null
sleep 1

# Start Frida server in background
echo "[INFO] Starting Frida server..."
adb -s "$DEVICE_ID" shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"

# Wait a moment
sleep 3

# Check if it's running
echo "[INFO] Checking if Frida server is running..."
if adb -s "$DEVICE_ID" shell "ps -A | grep frida-server" 2>/dev/null | grep -q frida-server; then
    echo "[SUCCESS] Frida server is running"
    exit 0
else
    echo "[ERROR] Frida server failed to start"
    # Try to get more info
    echo "[DEBUG] Checking Frida server file..."
    adb -s "$DEVICE_ID" shell "ls -la /data/local/tmp/frida-server" 2>/dev/null
    echo "[DEBUG] Checking processes..."
    adb -s "$DEVICE_ID" shell "ps -A | grep frida" 2>/dev/null
    exit 1
fi
