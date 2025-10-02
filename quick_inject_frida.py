"""
Quick Frida Gadget injection using existing decompiled APK
"""

import os
import shutil
from pathlib import Path
import subprocess
import re

print("""
╔═══════════════════════════════════════════════════════════╗
║   Quick Frida Gadget Injection                           ║
║   Using existing decompiled APK                          ║
╚═══════════════════════════════════════════════════════════╝
""")

# Use existing decoded directory
DECOMPILED_DIR = "MaynDrive/base_decoded"
GADGET_FILE = "frida-gadget-android-arm64.so"
OUTPUT_APK = "mayndrive_frida_injected.apk"
KEYSTORE = "my-release-key.keystore"
KEYSTORE_PASSWORD = "fridatest123"

# Step 1: Add Frida Gadget
print("\n[1/4] Adding Frida Gadget library...")
lib_dir = Path(DECOMPILED_DIR) / "lib" / "arm64-v8a"
lib_dir.mkdir(parents=True, exist_ok=True)
dest = lib_dir / "libfrida-gadget.so"
shutil.copy(GADGET_FILE, dest)
print(f"✓ Copied to {dest}")

# Step 2: Inject load call
print("\n[2/4] Injecting Gadget load call...")
smali_path = Path(DECOMPILED_DIR) / "smali" / "city" / "knot" / "knotapp" / "ui" / "MainActivity.smali"

if not smali_path.exists():
    print(f"❌ MainActivity not found at {smali_path}")
    exit(1)

with open(smali_path, 'r', encoding='utf-8') as f:
    content = f.read()

if 'libfrida-gadget' in content:
    print("✓ Gadget already injected!")
else:
    # Find <init> method and inject
    pattern = r'(\.method\s+public\s+constructor\s+<init>\(\)V\s*\n\s*\.locals\s+)(\d+)'
    match = re.search(pattern, content)
    
    if match:
        locals_count = int(match.group(2))
        new_locals = locals_count + 1
        
        # Update locals
        content = re.sub(pattern, f'\\g<1>{new_locals}', content, count=1)
        
        # Find injection point
        inject_pattern = r'(\.method\s+public\s+constructor\s+<init>\(\)V\s*\n\s*\.locals\s+\d+\s*\n(?:.*\n)*?\s*invoke-direct[^\n]+\n)'
        
        injection = f'''
    # Frida Gadget
    const-string v{locals_count}, "frida-gadget"
    invoke-static {{v{locals_count}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

'''
        
        content = re.sub(inject_pattern, f'\\g<1>{injection}', content, count=1)
        
        with open(smali_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✓ Injected! Updated locals from {locals_count} to {new_locals}")
    else:
        print("❌ Could not find injection point")
        exit(1)

# Step 3: Rebuild
print("\n[3/4] Rebuilding APK...")
cmd = f'java -jar apktool.jar b "{DECOMPILED_DIR}" -o "{DECOMPILED_DIR}.apk"'
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

if result.returncode != 0:
    print(f"❌ Rebuild failed:")
    print(result.stderr)
    exit(1)

print(f"✓ Rebuilt: {DECOMPILED_DIR}.apk")

# Step 4: Sign
print("\n[4/4] Signing APK...")

# Create keystore if needed
if not os.path.exists(KEYSTORE):
    print("  Creating keystore...")
    cmd_keystore = (
        f'keytool -genkey -v -keystore {KEYSTORE} '
        f'-keyalg RSA -keysize 2048 -validity 10000 '
        f'-alias my-key -storepass {KEYSTORE_PASSWORD} '
        f'-keypass {KEYSTORE_PASSWORD} '
        f'-dname "CN=Frida, OU=Test, O=Test, L=Test, S=Test, C=US"'
    )
    subprocess.run(cmd_keystore, shell=True, check=False, capture_output=True)

# Try zipalign
aligned_apk = f"{DECOMPILED_DIR}_aligned.apk"
cmd_align = f'zipalign -v -p 4 "{DECOMPILED_DIR}.apk" "{aligned_apk}"'
result = subprocess.run(cmd_align, shell=True, capture_output=True)

if result.returncode != 0:
    print("  Zipalign not found, skipping...")
    aligned_apk = f"{DECOMPILED_DIR}.apk"

# Sign
cmd_sign = (
    f'apksigner sign --ks {KEYSTORE} '
    f'--ks-pass pass:{KEYSTORE_PASSWORD} '
    f'--key-pass pass:{KEYSTORE_PASSWORD} '
    f'--out {OUTPUT_APK} "{aligned_apk}"'
)
result = subprocess.run(cmd_sign, shell=True, capture_output=True, text=True)

if result.returncode != 0:
    print(f"❌ Signing failed:")
    print(result.stderr)
    print("\n⚠️  APK built but not signed. Manual signing required.")
    print(f"   Built APK: {DECOMPILED_DIR}.apk")
    exit(1)

print(f"✓ Signed: {OUTPUT_APK}")

# Verify
print("\nVerifying signature...")
cmd_verify = f'apksigner verify "{OUTPUT_APK}"'
result = subprocess.run(cmd_verify, shell=True, capture_output=True)

if result.returncode == 0:
    print("✓ Signature verified!")
else:
    print("⚠️  Could not verify (apksigner may not be in PATH)")

print(f"""
╔═══════════════════════════════════════════════════════════╗
║   SUCCESS! Modified APK Ready                            ║
╚═══════════════════════════════════════════════════════════╝

✅ Output: {OUTPUT_APK}
✅ Location: {os.path.abspath(OUTPUT_APK)}

Next steps:
1. Install: adb install {OUTPUT_APK}
2. Push script: adb push ssl-unpinning.js /data/local/tmp/
3. Run Frida: frida -U Gadget -l ssl-unpinning.js
4. Configure proxy on phone
5. Start mitmweb: mitmweb -p 8080
6. Capture traffic!
""")

