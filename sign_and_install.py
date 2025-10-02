"""
Sign APK and install on device
"""

import subprocess
import os
import sys

print("""
╔═══════════════════════════════════════════════════════════╗
║   Sign APK and Install                                    ║
╚═══════════════════════════════════════════════════════════╝
""")

APK_FILE = "MaynDrive/base_decoded.apk"
SIGNED_APK = "mayndrive_frida_signed.apk"
KEYSTORE = "my-release-key.keystore"
KEYSTORE_PASSWORD = "fridatest123"

# Find Java home
result = subprocess.run("java -XshowSettings:properties -version", 
                       shell=True, capture_output=True, text=True)

java_home = None
for line in result.stderr.split('\n'):
    if 'java.home' in line:
        java_home = line.split('=')[1].strip()
        break

if java_home:
    print(f"✓ Found Java: {java_home}")
    jarsigner = os.path.join(java_home, 'bin', 'jarsigner.exe')
    
    if not os.path.exists(jarsigner):
        jarsigner = os.path.join(java_home, 'bin', 'jarsigner')
    
    if os.path.exists(jarsigner):
        print(f"✓ Found jarsigner: {jarsigner}")
        
        # Sign the APK
        print(f"\nSigning APK...")
        cmd = f'"{jarsigner}" -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {KEYSTORE} -storepass {KEYSTORE_PASSWORD} "{APK_FILE}" my-key'
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 or "jar signed" in result.stdout.lower():
            print("✓ APK signed successfully!")
            
            # Copy to final location
            import shutil
            shutil.copy(APK_FILE, SIGNED_APK)
            print(f"✓ Signed APK: {SIGNED_APK}")
            
            # Install
            print(f"\nInstalling on device...")
            adb = "platform-tools\\adb.exe"
            
            # Uninstall old
            subprocess.run(f'{adb} uninstall fr.mayndrive.app', shell=True)
            
            # Install new
            result = subprocess.run(f'{adb} install "{SIGNED_APK}"', 
                                  shell=True, capture_output=True, text=True)
            
            if "Success" in result.stdout:
                print("✓ APK installed successfully!")
                
                # Push script
                print(f"\nPushing SSL unpinning script...")
                subprocess.run(f'{adb} push ssl-unpinning.js /data/local/tmp/', shell=True)
                subprocess.run(f'{adb} shell chmod 644 /data/local/tmp/ssl-unpinning.js', shell=True)
                print("✓ Script pushed!")
                
                print(f"""
╔═══════════════════════════════════════════════════════════╗
║   ✅ Installation Complete!                               ║
╚═══════════════════════════════════════════════════════════╝

Next steps:

1. Launch MaynDrive app on your phone

2. Run Frida:
   pip install frida-tools
   frida -U Gadget -l ssl-unpinning.js

3. Start mitmproxy:
   pip install mitmproxy
   mitmweb -p 8080

4. Configure WiFi proxy on phone

5. Capture traffic!
                """)
            else:
                print(f"❌ Installation failed:")
                print(result.stdout)
                print(result.stderr)
        else:
            print(f"❌ Signing failed:")
            print(result.stdout)
            print(result.stderr)
    else:
        print(f"❌ jarsigner not found at {jarsigner}")
else:
    print(f"❌ Could not find Java home")


