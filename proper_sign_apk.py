"""
Properly sign the APK using uber-apk-signer
"""

import subprocess
import os
import urllib.request
import sys

print("""
╔═══════════════════════════════════════════════════════════╗
║   Proper APK Signing and Installation                    ║
╚═══════════════════════════════════════════════════════════╝
""")

APK_FILE = "MaynDrive/base_decoded.apk"
SIGNED_APK = "mayndrive_frida_SIGNED.apk"
SIGNER_URL = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
SIGNER_JAR = "uber-apk-signer.jar"

# Download uber-apk-signer if not present
if not os.path.exists(SIGNER_JAR):
    print(f"📥 Downloading APK signer...")
    try:
        urllib.request.urlretrieve(SIGNER_URL, SIGNER_JAR)
        print(f"✓ Downloaded uber-apk-signer")
    except Exception as e:
        print(f"❌ Download failed: {e}")
        print("\nFallback: Trying with jarsigner...")
        
        # Try to find and use jarsigner
        result = subprocess.run("where java", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            java_path = result.stdout.strip().split('\n')[0]
            java_home = os.path.dirname(os.path.dirname(java_path))
            jarsigner = os.path.join(java_home, 'bin', 'jarsigner.exe')
            
            if os.path.exists(jarsigner):
                print(f"✓ Found jarsigner: {jarsigner}")
                
                # Create keystore
                keystore = "release.keystore"
                if not os.path.exists(keystore):
                    print("Creating keystore...")
                    cmd_key = f'keytool -genkey -v -keystore {keystore} -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android -dname "CN=Android Debug,O=Android,C=US"'
                    subprocess.run(cmd_key, shell=True)
                
                # Sign with jarsigner
                print(f"\nSigning APK with jarsigner...")
                cmd_sign = f'"{jarsigner}" -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore {keystore} -storepass android -keypass android "{APK_FILE}" androiddebugkey'
                
                result = subprocess.run(cmd_sign, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0 or "jar signed" in result.stdout.lower():
                    print("✓ APK signed with jarsigner!")
                    
                    # Copy to final name
                    import shutil
                    shutil.copy(APK_FILE, SIGNED_APK)
                    
                    # Zipalign if available
                    print("\nTrying to zipalign...")
                    result_align = subprocess.run(f'zipalign -v -p 4 "{SIGNED_APK}" "{SIGNED_APK}.aligned"', 
                                                 shell=True, capture_output=True)
                    if result_align.returncode == 0:
                        os.replace(f"{SIGNED_APK}.aligned", SIGNED_APK)
                        print("✓ APK aligned")
                    
                    print(f"\n✓ Signed APK ready: {SIGNED_APK}")
                    
                    # Install
                    print(f"\nInstalling on device...")
                    adb = "platform-tools\\adb.exe"
                    
                    print("Uninstalling old version...")
                    subprocess.run(f'{adb} uninstall fr.mayndrive.app', shell=True)
                    
                    print("Installing signed APK...")
                    result = subprocess.run(f'{adb} install -r "{SIGNED_APK}"', 
                                          shell=True, capture_output=True, text=True)
                    
                    print(result.stdout)
                    if "Success" in result.stdout:
                        print("\n✅ Installation réussie!")
                        print("\nPushing SSL script...")
                        subprocess.run(f'{adb} push ssl-unpinning.js /data/local/tmp/', shell=True)
                        
                        print("""
╔═══════════════════════════════════════════════════════════╗
║   ✅ APK Installé!                                        ║
╚═══════════════════════════════════════════════════════════╝

Prochaines étapes:

1. Ouvrez l'app MaynDrive sur votre téléphone
2. Sur PC: frida -U Gadget -l ssl-unpinning.js
3. Configurez le proxy WiFi
4. Capturez le trafic!
                        """)
                    else:
                        print(f"\n❌ Installation échouée:")
                        print(result.stderr)
                else:
                    print(f"❌ Signing failed:")
                    print(result.stderr)
            else:
                print(f"❌ jarsigner not found")
        sys.exit(1)
else:
    print(f"✓ Signer already downloaded")

# Sign with uber-apk-signer
print(f"\nSigning APK with uber-apk-signer...")
cmd = f'java -jar {SIGNER_JAR} --apks "{APK_FILE}" --allowResign --overwrite'

result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

if result.returncode == 0:
    # Find the signed APK
    signed_files = [f for f in os.listdir("MaynDrive") if f.endswith("-aligned-debugSigned.apk")]
    
    if signed_files:
        signed_apk_path = os.path.join("MaynDrive", signed_files[0])
        
        # Copy to root with clear name
        import shutil
        shutil.copy(signed_apk_path, SIGNED_APK)
        
        print(f"✓ APK signed successfully: {SIGNED_APK}")
        
        # Install
        print(f"\nInstalling on device...")
        adb = "platform-tools\\adb.exe"
        
        print("Uninstalling old version...")
        subprocess.run(f'{adb} uninstall fr.mayndrive.app', shell=True)
        
        print("Installing signed APK...")
        result = subprocess.run(f'{adb} install -r "{SIGNED_APK}"', 
                              shell=True, capture_output=True, text=True)
        
        print(result.stdout)
        if "Success" in result.stdout:
            print("\n✅ Installation réussie!")
            
            print("\nPushing SSL script...")
            subprocess.run(f'{adb} push ssl-unpinning.js /data/local/tmp/', shell=True)
            
            print("""
╔═══════════════════════════════════════════════════════════╗
║   ✅ APK Installé!                                        ║
╚═══════════════════════════════════════════════════════════╝

Prochaines étapes:

1. Ouvrez l'app MaynDrive sur votre téléphone
2. Sur PC: py -m pip install frida-tools
3. Puis: frida -U Gadget -l ssl-unpinning.js
4. Configurez le proxy WiFi
5. Capturez le trafic!
            """)
        else:
            print(f"\n❌ Installation échouée:")
            print(result.stderr)
    else:
        print(f"❌ Could not find signed APK")
else:
    print(f"❌ Signing failed:")
    print(result.stdout)
    print(result.stderr)

