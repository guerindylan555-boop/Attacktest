#!/bin/bash
################################################################################
# MaynDrive APK Repackaging Script with Frida Gadget (Non-Root)
# For Linux/Mac - Automates the Frida Gadget injection process
################################################################################

set -e  # Exit on error

# Configuration
APK_NAME="mayndrive_original.apk"
DECOMPILED_DIR="mayndrive_decompiled"
GADGET_FILE="frida-gadget-android-arm64.so"
OUTPUT_APK="mayndrive_signed.apk"
KEYSTORE="my-release-key.keystore"
KEYSTORE_ALIAS="my-key-alias"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MaynDrive APK Frida Gadget Injector                    ║"
echo "║   Non-Root SSL Unpinning for Redmi 13C 4G                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if original APK exists
if [ ! -f "$APK_NAME" ]; then
    echo "❌ Error: $APK_NAME not found!"
    echo ""
    echo "Please extract the APK first:"
    echo "  adb shell pm path city.knot.mayndrive"
    echo "  adb pull /data/app/city.knot.mayndrive-xxx/base.apk $APK_NAME"
    echo ""
    exit 1
fi

# Check if Frida Gadget exists
if [ ! -f "$GADGET_FILE" ]; then
    echo "❌ Error: $GADGET_FILE not found!"
    echo ""
    echo "Please download Frida Gadget from:"
    echo "  https://github.com/frida/frida/releases"
    echo ""
    echo "Download: frida-gadget-*-android-arm64.so"
    echo "Rename it to: $GADGET_FILE"
    echo ""
    exit 1
fi

echo "✓ Found: $APK_NAME"
echo "✓ Found: $GADGET_FILE"
echo ""

################################################################################
echo "[1/7] Decompiling APK..."
################################################################################
if [ -d "$DECOMPILED_DIR" ]; then
    echo "  Removing old decompiled directory..."
    rm -rf "$DECOMPILED_DIR"
fi

apktool d "$APK_NAME" -o "$DECOMPILED_DIR"
echo "  ✓ APK decompiled to $DECOMPILED_DIR"
echo ""

################################################################################
echo "[2/7] Adding Frida Gadget library..."
################################################################################
LIB_DIR="$DECOMPILED_DIR/lib/arm64-v8a"
mkdir -p "$LIB_DIR"

cp "$GADGET_FILE" "$LIB_DIR/libfrida-gadget.so"
echo "  ✓ Gadget library added to $LIB_DIR"
echo ""

################################################################################
echo "[3/7] Finding MainActivity..."
################################################################################
if grep -q "android.intent.action.MAIN" "$DECOMPILED_DIR/AndroidManifest.xml"; then
    echo "  ✓ Found MainActivity in AndroidManifest.xml"
else
    echo "  ⚠️  Could not find MainActivity automatically"
fi
echo ""

echo "  ⚠️  MANUAL STEP REQUIRED:"
echo "  1. Open: $DECOMPILED_DIR/smali/city/knot/mayndrive/MainActivity.smali"
echo "  2. Find the <init> method (constructor)"
echo "  3. Add these lines after invoke-direct:"
echo ""
echo "     const-string v0, \"frida-gadget\""
echo "     invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
echo ""
echo "  4. Increment .locals count by 1"
echo ""
read -p "Press Enter after editing the smali file..."
echo ""

################################################################################
echo "[4/7] Rebuilding APK..."
################################################################################
apktool b "$DECOMPILED_DIR" -o "$DECOMPILED_DIR.apk"
echo "  ✓ APK rebuilt: $DECOMPILED_DIR.apk"
echo ""

################################################################################
echo "[5/7] Aligning APK..."
################################################################################
zipalign -v -p 4 "$DECOMPILED_DIR.apk" "${DECOMPILED_DIR}_aligned.apk"
echo "  ✓ APK aligned"
echo ""

################################################################################
echo "[6/7] Signing APK..."
################################################################################
if [ ! -f "$KEYSTORE" ]; then
    echo "  Creating new keystore..."
    keytool -genkey -v -keystore "$KEYSTORE" \
            -keyalg RSA -keysize 2048 -validity 10000 \
            -alias "$KEYSTORE_ALIAS"
fi

apksigner sign --ks "$KEYSTORE" --out "$OUTPUT_APK" "${DECOMPILED_DIR}_aligned.apk"
apksigner verify "$OUTPUT_APK"
echo "  ✓ APK signed: $OUTPUT_APK"
echo ""

################################################################################
echo "[7/7] Installing modified APK..."
################################################################################
echo "  Uninstalling original app..."
adb uninstall city.knot.mayndrive 2>/dev/null || true
echo ""

echo "  Installing modified app..."
adb install "$OUTPUT_APK"
echo "  ✓ Modified APK installed"
echo ""

################################################################################
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   SUCCESS! Modified APK Ready                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo ""
echo "1. Launch MaynDrive app on your phone"
echo ""
echo "2. Run Frida unpinning script from PC:"
echo "   frida -U Gadget -l ssl-unpinning.js"
echo ""
echo "3. Configure proxy on phone (WiFi settings):"
echo "   - Hostname: [Your PC IP]"
echo "   - Port: 8080"
echo ""
echo "4. Launch HTTP Toolkit or mitmproxy:"
echo "   mitmweb -p 8080"
echo ""
echo "5. Use the app and capture traffic!"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

