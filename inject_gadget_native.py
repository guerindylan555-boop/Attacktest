"""
LIEF-based Frida Gadget Injection for Native Android Libraries
Injects libfrida-gadget.so dependency into native libraries without modifying smali code
"""

import lief
import sys
import os
from pathlib import Path

def inject_gadget(lib_path: str, verify: bool = True):
    """
    Inject Frida Gadget dependency into a native library
    
    Args:
        lib_path: Path to the native .so file
        verify: Whether to verify injection with readelf
    """
    if not os.path.exists(lib_path):
        print(f"❌ Library not found: {lib_path}")
        return False
    
    print(f"🔍 Parsing native library: {lib_path}")
    
    try:
        # Parse the ELF library
        lib = lief.parse(lib_path)
        
        if not lib:
            print(f"❌ Failed to parse library")
            return False
        
        print(f"✓ Library parsed successfully")
        print(f"  Architecture: {lib.header.machine_type}")
        print(f"  Type: {lib.header.file_type}")
        
        # Check if gadget is already added
        existing_libs = [l.name for l in lib.libraries]
        print(f"\n📚 Existing dependencies: {', '.join(existing_libs)}")
        
        if "libfrida-gadget.so" in existing_libs:
            print(f"\n⚠️  libfrida-gadget.so already present in dependencies")
            return True
        
        # Add Frida Gadget as a dependency
        print(f"\n🔧 Adding libfrida-gadget.so dependency...")
        lib.add_library("libfrida-gadget.so")
        
        # Write modified library
        backup_path = lib_path + ".bak"
        print(f"💾 Creating backup: {backup_path}")
        os.rename(lib_path, backup_path)
        
        print(f"💾 Writing modified library...")
        lib.write(lib_path)
        
        print(f"\n✅ Gadget dependency successfully added to {lib_path}")
        
        # Verify with readelf if requested
        if verify:
            print(f"\n🔍 Verifying injection with readelf...")
            try:
                import subprocess
                result = subprocess.run(
                    ['readelf', '-d', lib_path], 
                    capture_output=True, 
                    text=True,
                    timeout=5
                )
                
                if "libfrida-gadget.so" in result.stdout:
                    print(f"✅ Verification successful! libfrida-gadget.so is in NEEDED list")
                    print(f"\nRelevant section:")
                    for line in result.stdout.split('\n'):
                        if 'NEEDED' in line and 'libfrida' in line:
                            print(f"  {line}")
                else:
                    print(f"⚠️  Warning: libfrida-gadget.so not found in readelf output")
                    
            except FileNotFoundError:
                print(f"⚠️  readelf not found, skipping verification")
            except Exception as e:
                print(f"⚠️  Verification failed: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error injecting gadget: {e}")
        return False


def find_native_libs(decompiled_dir: str) -> list:
    """Find all native libraries in decompiled APK"""
    lib_dirs = [
        "lib/arm64-v8a",
        "lib/armeabi-v7a", 
        "lib/x86_64",
        "lib/x86"
    ]
    
    libs = []
    for lib_dir in lib_dirs:
        full_path = Path(decompiled_dir) / lib_dir
        if full_path.exists():
            for lib_file in full_path.glob("*.so"):
                # Skip Frida Gadget itself
                if "frida-gadget" not in lib_file.name:
                    libs.append(str(lib_file))
    
    return libs


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("""
╔═══════════════════════════════════════════════════════════╗
║   LIEF Frida Gadget Injector for Android Native Libs     ║
╚═══════════════════════════════════════════════════════════╝

Usage:
  python inject_gadget_native.py <path_to_library.so>
  python inject_gadget_native.py <decompiled_apk_directory>

Examples:
  # Inject into specific library
  python inject_gadget_native.py mayndrive_decompiled/lib/arm64-v8a/libnative.so

  # Auto-detect and inject into all libs in decompiled APK
  python inject_gadget_native.py mayndrive_decompiled/

Requirements:
  pip install lief

Note: This adds libfrida-gadget.so as a dependency without modifying smali code.
Ensure libfrida-gadget.so exists in the same lib directory before rebuilding APK!
        """)
        return
    
    target = sys.argv[1]
    
    # Check if target is directory or file
    if os.path.isdir(target):
        print(f"🔍 Scanning directory for native libraries: {target}\n")
        libs = find_native_libs(target)
        
        if not libs:
            print(f"❌ No native libraries found in {target}")
            print(f"   Make sure you provide the decompiled APK root directory")
            return
        
        print(f"📦 Found {len(libs)} native libraries:\n")
        for lib in libs:
            print(f"  - {lib}")
        
        print(f"\n⚠️  This will inject Frida Gadget into ALL libraries")
        choice = input("Proceed? (y/N): ")
        
        if choice.lower() != 'y':
            print("Cancelled.")
            return
        
        success_count = 0
        for lib in libs:
            print(f"\n{'='*70}")
            if inject_gadget(lib, verify=False):
                success_count += 1
            print(f"{'='*70}")
        
        print(f"\n✅ Successfully injected {success_count}/{len(libs)} libraries")
        
    elif os.path.isfile(target):
        # Single file
        inject_gadget(target, verify=True)
        
    else:
        print(f"❌ Target not found: {target}")
        return
    
    print(f"\n📋 Next steps:")
    print(f"1. Ensure libfrida-gadget.so is in the same lib directory")
    print(f"2. Rebuild APK: apktool b <decompiled_dir> -o modified.apk")
    print(f"3. Align and sign the APK")
    print(f"4. Install and test")


if __name__ == "__main__":
    main()

