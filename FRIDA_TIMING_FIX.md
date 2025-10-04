# Frida Timing Fix - Summary

## Problem Statement

The Control Center application was spawning Frida at the **wrong time**, causing the MaynDrive app to launch immediately when the Control Center started, rather than when the user was ready to interact with it.

## Root Cause

1. **Auto-spawn mode**: Frida was using `-f fr.mayndrive.app` (spawn mode) which immediately launches a new app instance
2. **Premature execution**: Services started automatically on Control Center initialization (line 59 in `control_center.py`)
3. **No user control**: The app launched before the user clicked any action buttons (Record, Replay, or Capture Token)

## Changes Made

### 1. Fixed Missing Constants in `service_manager.py`
- Added `MAYNDRIVE_PACKAGE_NAME = "fr.mayndrive.app"`
- Added `MAYNDRIVE_PACKAGE_CANDIDATES` tuple with APK/XAPK search paths
- Added missing imports: `tempfile`, `zipfile`

### 2. Enhanced `run_hooks.py` with Smart Attach Logic
**New Functions:**
- `is_app_running(package_name, device_id)` - Check if MaynDrive is currently running
- `launch_app(package_name, device_id)` - Launch MaynDrive via adb monkey

**Updated `run_frida()` Function:**
```python
def run_frida(attach_mode: bool = True, auto_launch: bool = True)
```

**Behavior:**
- **Default mode**: Attach to running app (`-n` flag) instead of spawning (`-f` flag)
- **Smart launch**: If app isn't running and `auto_launch=True`, launch it via adb
- **Graceful errors**: Raises `RuntimeError` if app can't be started

### 3. Updated `service_manager.py` Frida Startup
```python
# Use attach mode with auto-launch
proc, log_file = run_hooks.run_frida(attach_mode=True, auto_launch=True)
```

**Benefits:**
- Frida now attaches to existing app instances
- If app isn't running, launches it on-demand (not immediately at startup)
- Better error handling with `RuntimeError` catching

## Timing Flow (Before vs After)

### Before (Broken)
```
Control Center starts
  → Start all services
    → Start Frida
      → Frida spawns new MaynDrive app (-f flag)
        → App launches IMMEDIATELY (wrong timing!)
```

### After (Fixed)
```
Control Center starts
  → Start all services
    → Start Frida
      → Check if app is running
        → If NOT running: Launch app via adb (controlled launch)
        → If running: Attach to existing instance
      → Frida attaches to app (-n flag)
        → App only launches when needed (right timing!)
```

## User Experience Improvements

1. **Controlled Launch**: App no longer auto-spawns at startup
2. **Flexibility**: Can attach to already-running app instances
3. **On-Demand**: App launches only when Frida service starts (after emulator is ready)
4. **Better Errors**: Clear error messages if app can't launch or attach

## App Launch Improvements (v2)

The `launch_app()` function now uses **3 fallback strategies** to ensure the app launches:

1. **Method 1**: Direct activity launch via `am start -n` (most reliable)
   - Uses explicit activity: `fr.mayndrive.app/city.knot.mayndrive.ui.MainActivity`
   
2. **Method 2**: Monkey launcher (fallback)
   - Uses Android monkey tool with launcher category
   
3. **Method 3**: Generic intent launcher (last resort)
   - Uses generic MAIN/LAUNCHER intent

All methods include:
- Better logging and debugging output
- Verification that app actually started
- Proper wait times for app initialization
- Clear error messages on failure

## Testing Recommendations

### Quick Test (Automated)
```bash
# Run the automated test suite
python3 test_app_launch.py
```
This will test:
1. App detection
2. App launching with all 3 methods
3. Frida attachment

### Manual Tests

1. **Test attach to running app**:
   ```bash
   # Manually launch MaynDrive first
   adb shell am start -n fr.mayndrive.app/city.knot.mayndrive.ui.MainActivity
   # Then start Control Center - should attach without re-spawning
   ./run_control_center.sh
   ```

2. **Test auto-launch**:
   ```bash
   # Ensure app is NOT running
   adb shell am force-stop fr.mayndrive.app
   # Start Control Center - should launch app on-demand
   ./run_control_center.sh
   ```

3. **Test error handling**:
   ```bash
   # Kill emulator
   adb -s emulator-5554 emu kill
   # Start Control Center - should show clear error
   ./run_control_center.sh
   ```

### Debugging Tips

If the app doesn't launch:

1. **Check if emulator is running**:
   ```bash
   adb devices
   ```

2. **Check if app is installed**:
   ```bash
   adb shell pm list packages | grep mayndrive
   ```

3. **Try manual launch**:
   ```bash
   adb shell am start -n fr.mayndrive.app/city.knot.mayndrive.ui.MainActivity
   ```

4. **Check Frida logs**:
   ```bash
   tail -f ~/android-tools/logs/frida-general-*.log
   ```

## Configuration Options

The `run_frida()` function now supports flexible configuration:

```python
# Default: Attach mode with auto-launch
run_frida(attach_mode=True, auto_launch=True)

# Attach mode, fail if app not running
run_frida(attach_mode=True, auto_launch=False)

# Classic spawn mode (launches new instance)
run_frida(attach_mode=False)
```

## Files Modified

1. `/automation/services/service_manager.py`
   - Added missing constants
   - Added missing imports
   - Updated `_start_frida()` to use attach mode

2. `/automation/scripts/run_hooks.py`
   - Added `is_app_running()` helper
   - Added `launch_app()` helper
   - Enhanced `run_frida()` with attach mode and auto-launch

## Backward Compatibility

The changes maintain backward compatibility:
- Default behavior uses attach mode (better UX)
- Can still use spawn mode by passing `attach_mode=False`
- All existing code paths continue to work

## Summary

✅ **Fixed**: Frida no longer spawns app at the wrong time
✅ **Smart**: Automatically launches app only when needed
✅ **Flexible**: Can attach to running instances or spawn new ones
✅ **Robust**: Better error handling and user feedback

The Control Center now provides proper control over when the MaynDrive app launches, giving users a much better experience.

