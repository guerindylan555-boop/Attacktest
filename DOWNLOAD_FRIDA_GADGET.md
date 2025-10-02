# Download Frida Gadget

## Quick Download

**For Redmi 13C 4G (ARM64):**

1. Visit: https://github.com/frida/frida/releases/tag/16.5.9

2. Download: **frida-gadget-16.5.9-android-arm64.so.xz**

3. Extract the .xz file (use 7-Zip on Windows)

4. Rename to: **frida-gadget-android-arm64.so**

5. Place in: `C:\Users\abesn\OneDrive\Bureau\analyse\`

## Alternative: Latest Version

Visit: https://github.com/frida/frida/releases/latest

Download the latest `frida-gadget-*-android-arm64.so.xz`

## Verify Architecture

Your device uses: **ARM64-v8a** (Helio G85 chipset)

To confirm on your phone:
```bash
adb shell getprop ro.product.cpu.abi
# Should output: arm64-v8a
```

## After Download

Run:
```bash
python auto_inject_frida.py
```

This will automatically inject Frida Gadget into the APK!

