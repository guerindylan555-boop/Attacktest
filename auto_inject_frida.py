"""
Fully Automated Frida Gadget Injection for MaynDrive APK
Handles decompilation, injection, smali editing, rebuilding, signing, and installation
"""

import os
import sys
import subprocess
import shutil
import re
from pathlib import Path
import urllib.request
import zipfile

class FridaInjector:
    def __init__(self):
        self.apk_name = "mayndrive_original.apk"
        self.decompiled_dir = "mayndrive_decompiled"
        self.gadget_file = "frida-gadget-android-arm64.so"
        self.gadget_url = "https://github.com/frida/frida/releases/download/16.5.9/frida-gadget-16.5.9-android-arm64.so.xz"
        self.output_apk = "mayndrive_frida_injected.apk"
        self.keystore = "my-release-key.keystore"
        self.keystore_alias = "my-key-alias"
        self.keystore_password = "fridatest123"
        
    def print_step(self, step_num, total, message):
        """Print a formatted step message"""
        print(f"\n{'='*70}")
        print(f"[{step_num}/{total}] {message}")
        print(f"{'='*70}")
        
    def run_command(self, command, shell=True, check=True):
        """Run a shell command and return result"""
        try:
            result = subprocess.run(
                command,
                shell=shell,
                check=check,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            return False, e.stdout, e.stderr
        except Exception as e:
            return False, "", str(e)
    
    def check_prerequisites(self):
        """Check if all required tools are available"""
        self.print_step(1, 9, "Checking Prerequisites")
        
        # Check if APK exists
        if not os.path.exists(self.apk_name):
            print(f"❌ APK not found: {self.apk_name}")
            return False
        print(f"✓ Found APK: {self.apk_name}")
        
        # Check for apktool
        if not os.path.exists("apktool.jar"):
            print(f"❌ apktool.jar not found")
            return False
        print(f"✓ Found apktool.jar")
        
        # Check for Java
        success, stdout, stderr = self.run_command("java -version")
        if success or "version" in stderr.lower():
            print(f"✓ Java is installed")
        else:
            print(f"❌ Java not found - please install JDK")
            return False
        
        # Check for zipalign (part of Android SDK build-tools)
        success, _, _ = self.run_command("zipalign --help")
        if success:
            print(f"✓ zipalign found")
        else:
            print(f"⚠️  zipalign not found - will try to continue")
        
        # Check for apksigner
        success, _, _ = self.run_command("apksigner --help")
        if success:
            print(f"✓ apksigner found")
        else:
            print(f"⚠️  apksigner not found - will try to continue")
        
        return True
    
    def download_frida_gadget(self):
        """Download Frida Gadget if not present"""
        self.print_step(2, 9, "Getting Frida Gadget")
        
        if os.path.exists(self.gadget_file):
            print(f"✓ Frida Gadget already downloaded: {self.gadget_file}")
            return True
        
        print(f"📥 Frida Gadget not found locally")
        print(f"⚠️  Please download manually from:")
        print(f"   https://github.com/frida/frida/releases")
        print(f"   Download: frida-gadget-*-android-arm64.so")
        print(f"   Rename to: {self.gadget_file}")
        print(f"   Place in: {os.getcwd()}")
        
        return os.path.exists(self.gadget_file)
    
    def decompile_apk(self):
        """Decompile the APK using apktool"""
        self.print_step(3, 9, "Decompiling APK")
        
        # Remove old decompiled directory if exists
        if os.path.exists(self.decompiled_dir):
            print(f"  Removing old decompiled directory...")
            shutil.rmtree(self.decompiled_dir)
        
        # Decompile
        cmd = f"java -jar apktool.jar d {self.apk_name} -o {self.decompiled_dir}"
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists(self.decompiled_dir):
            print(f"✓ APK decompiled successfully")
            return True
        else:
            print(f"❌ Failed to decompile APK")
            print(f"Error: {stderr}")
            return False
    
    def add_gadget_library(self):
        """Add Frida Gadget library to the APK"""
        self.print_step(4, 9, "Adding Frida Gadget Library")
        
        lib_dir = Path(self.decompiled_dir) / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True, exist_ok=True)
        
        dest = lib_dir / "libfrida-gadget.so"
        shutil.copy(self.gadget_file, dest)
        
        if dest.exists():
            print(f"✓ Gadget library copied to {dest}")
            return True
        else:
            print(f"❌ Failed to copy Gadget library")
            return False
    
    def find_main_activity(self):
        """Find the main activity from AndroidManifest.xml"""
        manifest_path = Path(self.decompiled_dir) / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            return None
        
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find activity with MAIN action
        # Look for pattern: <activity android:name=".Something" ...> with MAIN intent
        activity_pattern = r'<activity[^>]*android:name="([^"]+)"[^>]*>(?:(?!</activity>).)*android\.intent\.action\.MAIN'
        match = re.search(activity_pattern, content, re.DOTALL)
        
        if match:
            activity_name = match.group(1)
            # Convert from .MainActivity to full path
            if activity_name.startswith('.'):
                # Get package name
                package_match = re.search(r'package="([^"]+)"', content)
                if package_match:
                    package_name = package_match.group(1)
                    activity_name = package_name + activity_name
            
            return activity_name
        
        return None
    
    def inject_gadget_load(self):
        """Inject Frida Gadget load call into MainActivity"""
        self.print_step(5, 9, "Injecting Gadget Load Call")
        
        # Find main activity
        activity_name = self.find_main_activity()
        if not activity_name:
            print(f"❌ Could not find main activity")
            return False
        
        print(f"  Found main activity: {activity_name}")
        
        # Convert to file path
        smali_relative = activity_name.replace('.', '/') + ".smali"
        smali_path = Path(self.decompiled_dir) / "smali" / smali_relative
        
        # Also check smali_classes2, smali_classes3, etc.
        if not smali_path.exists():
            for i in range(2, 10):
                smali_relative = activity_name.replace('.', '/') + ".smali"
                alt_path = Path(self.decompiled_dir) / f"smali_classes{i}" / smali_relative
                if alt_path.exists():
                    smali_path = alt_path
                    break
        
        if not smali_path.exists():
            print(f"❌ Could not find smali file: {smali_path}")
            return False
        
        print(f"  Found smali file: {smali_path}")
        
        # Read smali file
        with open(smali_path, 'r', encoding='utf-8') as f:
            smali_content = f.read()
        
        # Check if already injected
        if 'libfrida-gadget' in smali_content:
            print(f"✓ Gadget load already injected")
            return True
        
        # Find the <init> method
        init_pattern = r'(\.method\s+(?:public\s+)?constructor\s+<init>\([^\)]*\)V\s*\n\s*\.locals\s+)(\d+)'
        init_match = re.search(init_pattern, smali_content)
        
        if not init_match:
            print(f"❌ Could not find <init> method in smali file")
            return False
        
        # Get current locals count and increment
        current_locals = int(init_match.group(2))
        new_locals = current_locals + 1
        
        # Find where to inject (after invoke-direct in <init>)
        inject_pattern = r'(\.method\s+(?:public\s+)?constructor\s+<init>\([^\)]*\)V\s*\n\s*\.locals\s+\d+\s*\n(?:.*\n)*?\s*invoke-direct[^\n]+\n)'
        inject_match = re.search(inject_pattern, smali_content)
        
        if not inject_match:
            print(f"❌ Could not find injection point in <init> method")
            return False
        
        # Prepare injection code
        injection_code = f'''
    # Frida Gadget injection
    const-string v{current_locals}, "frida-gadget"
    invoke-static {{v{current_locals}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
'''
        
        # Update locals count
        smali_content = re.sub(
            r'(\.method\s+(?:public\s+)?constructor\s+<init>\([^\)]*\)V\s*\n\s*\.locals\s+)\d+',
            f'\\g<1>{new_locals}',
            smali_content,
            count=1
        )
        
        # Inject the gadget load code
        smali_content = re.sub(
            inject_pattern,
            f'\\g<1>{injection_code}\n',
            smali_content,
            count=1
        )
        
        # Write modified smali back
        with open(smali_path, 'w', encoding='utf-8') as f:
            f.write(smali_content)
        
        print(f"✓ Gadget load call injected successfully")
        print(f"  Updated .locals from {current_locals} to {new_locals}")
        return True
    
    def rebuild_apk(self):
        """Rebuild the modified APK"""
        self.print_step(6, 9, "Rebuilding APK")
        
        cmd = f"java -jar apktool.jar b {self.decompiled_dir} -o {self.decompiled_dir}.apk"
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists(f"{self.decompiled_dir}.apk"):
            print(f"✓ APK rebuilt successfully")
            return True
        else:
            print(f"❌ Failed to rebuild APK")
            print(f"Error: {stderr}")
            return False
    
    def align_apk(self):
        """Align the APK"""
        self.print_step(7, 9, "Aligning APK")
        
        input_apk = f"{self.decompiled_dir}.apk"
        aligned_apk = f"{self.decompiled_dir}_aligned.apk"
        
        cmd = f"zipalign -v -p 4 {input_apk} {aligned_apk}"
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists(aligned_apk):
            print(f"✓ APK aligned successfully")
            return True
        else:
            print(f"⚠️  zipalign failed, continuing anyway...")
            # Copy unaligned APK as aligned for signing
            shutil.copy(input_apk, aligned_apk)
            return True
    
    def create_keystore(self):
        """Create signing keystore if it doesn't exist"""
        if os.path.exists(self.keystore):
            return True
        
        print(f"  Creating new keystore...")
        cmd = (
            f'keytool -genkey -v -keystore {self.keystore} '
            f'-keyalg RSA -keysize 2048 -validity 10000 '
            f'-alias {self.keystore_alias} '
            f'-storepass {self.keystore_password} '
            f'-keypass {self.keystore_password} '
            f'-dname "CN=Frida, OU=Test, O=Test, L=Test, S=Test, C=US"'
        )
        
        success, stdout, stderr = self.run_command(cmd)
        return success and os.path.exists(self.keystore)
    
    def sign_apk(self):
        """Sign the APK"""
        self.print_step(8, 9, "Signing APK")
        
        # Create keystore if needed
        if not self.create_keystore():
            print(f"❌ Failed to create keystore")
            return False
        
        aligned_apk = f"{self.decompiled_dir}_aligned.apk"
        
        cmd = (
            f'apksigner sign --ks {self.keystore} '
            f'--ks-pass pass:{self.keystore_password} '
            f'--key-pass pass:{self.keystore_password} '
            f'--out {self.output_apk} {aligned_apk}'
        )
        
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists(self.output_apk):
            # Verify signature
            cmd_verify = f'apksigner verify {self.output_apk}'
            verify_success, _, _ = self.run_command(cmd_verify)
            
            if verify_success:
                print(f"✓ APK signed and verified successfully")
                print(f"✓ Output: {self.output_apk}")
                return True
            else:
                print(f"⚠️  APK signed but verification failed")
                return True
        else:
            print(f"❌ Failed to sign APK")
            print(f"Error: {stderr}")
            return False
    
    def install_apk(self):
        """Install the modified APK to connected device"""
        self.print_step(9, 9, "Installing APK")
        
        # Check if device is connected
        success, stdout, _ = self.run_command("adb devices")
        if "device" not in stdout:
            print(f"⚠️  No Android device connected via ADB")
            print(f"   Skipping installation")
            return True
        
        print(f"  Uninstalling original app...")
        self.run_command("adb uninstall city.knot.mayndrive", check=False)
        
        print(f"  Installing modified APK...")
        cmd = f"adb install {self.output_apk}"
        success, stdout, stderr = self.run_command(cmd)
        
        if success:
            print(f"✓ APK installed successfully")
            return True
        else:
            print(f"⚠️  Installation failed: {stderr}")
            print(f"   You can install manually: adb install {self.output_apk}")
            return True
    
    def run(self):
        """Run the complete injection process"""
        print("""
╔═══════════════════════════════════════════════════════════╗
║   Automated Frida Gadget Injection for MaynDrive         ║
║   Non-Root SSL Unpinning - Fully Automated               ║
╚═══════════════════════════════════════════════════════════╝
        """)
        
        steps = [
            ("Check Prerequisites", self.check_prerequisites),
            ("Download Frida Gadget", self.download_frida_gadget),
            ("Decompile APK", self.decompile_apk),
            ("Add Gadget Library", self.add_gadget_library),
            ("Inject Gadget Load", self.inject_gadget_load),
            ("Rebuild APK", self.rebuild_apk),
            ("Align APK", self.align_apk),
            ("Sign APK", self.sign_apk),
            ("Install APK", self.install_apk),
        ]
        
        for i, (name, func) in enumerate(steps, 1):
            if not func():
                print(f"\n❌ Process failed at step {i}: {name}")
                return False
        
        print(f"\n{'='*70}")
        print(f"╔═══════════════════════════════════════════════════════════╗")
        print(f"║   SUCCESS! Modified APK Created                          ║")
        print(f"╚═══════════════════════════════════════════════════════════╝")
        print(f"\n✅ Modified APK: {self.output_apk}")
        print(f"✅ Location: {os.path.abspath(self.output_apk)}")
        print(f"\nNext steps:")
        print(f"1. Push SSL unpinning script to device:")
        print(f"   adb push ssl-unpinning.js /data/local/tmp/")
        print(f"\n2. Launch the app on your phone")
        print(f"\n3. Run Frida from your PC:")
        print(f"   frida -U Gadget -l ssl-unpinning.js")
        print(f"\n4. Configure proxy on phone (WiFi settings):")
        print(f"   - Hostname: <Your PC IP>")
        print(f"   - Port: 8080")
        print(f"\n5. Start mitmproxy or HTTP Toolkit:")
        print(f"   mitmweb -p 8080")
        print(f"\n6. Use MaynDrive app and capture traffic!")
        print(f"{'='*70}\n")
        
        return True


if __name__ == "__main__":
    injector = FridaInjector()
    success = injector.run()
    sys.exit(0 if success else 1)

