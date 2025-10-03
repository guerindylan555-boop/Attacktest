#!/usr/bin/env python3
"""
MaynDrive Unsigned APK Vulnerability Analysis
Tests the CRITICAL vulnerability: APK_UNSIGNED
"""

import subprocess
import json
import os
from pathlib import Path
from datetime import datetime

def check_apk_signature(apk_path):
    """Check if APK is signed and analyze signature details"""
    print("🔍 Checking APK signature status...")
    
    try:
        # Check if apksigner is available
        result = subprocess.run(['apksigner', 'verify', '--print-certs', apk_path], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ APK is SIGNED")
            print("📋 Signature details:")
            print(result.stdout)
            return {
                "signed": True,
                "signature_details": result.stdout,
                "error": None
            }
        else:
            print("❌ APK is UNSIGNED or signature verification failed")
            print(f"Error: {result.stderr}")
            return {
                "signed": False,
                "signature_details": None,
                "error": result.stderr
            }
            
    except subprocess.TimeoutExpired:
        print("⏰ Signature check timed out")
        return {"signed": False, "error": "Timeout", "signature_details": None}
    except FileNotFoundError:
        print("❌ apksigner not found - trying alternative method")
        return check_apk_signature_alternative(apk_path)
    except Exception as e:
        print(f"❌ Error checking signature: {e}")
        return {"signed": False, "error": str(e), "signature_details": None}

def check_apk_signature_alternative(apk_path):
    """Alternative method to check APK signature using jarsigner"""
    print("🔍 Trying alternative signature check with jarsigner...")
    
    try:
        result = subprocess.run(['jarsigner', '-verify', '-verbose', '-certs', apk_path], 
                              capture_output=True, text=True, timeout=30)
        
        if "jar verified" in result.stdout.lower():
            print("✅ APK is SIGNED (verified with jarsigner)")
            return {
                "signed": True,
                "signature_details": result.stdout,
                "error": None
            }
        else:
            print("❌ APK is UNSIGNED (jarsigner verification failed)")
            return {
                "signed": False,
                "signature_details": result.stdout,
                "error": result.stderr
            }
            
    except FileNotFoundError:
        print("❌ jarsigner not found - trying basic file analysis")
        return check_apk_signature_basic(apk_path)
    except Exception as e:
        print(f"❌ Error with jarsigner: {e}")
        return {"signed": False, "error": str(e), "signature_details": None}

def check_apk_signature_basic(apk_path):
    """Basic file analysis to check for signature files"""
    print("🔍 Performing basic APK signature analysis...")
    
    try:
        # Check for META-INF directory and signature files
        result = subprocess.run(['unzip', '-l', apk_path], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            
            # Look for signature-related files
            signature_files = []
            if 'meta-inf/manifest.mf' in output:
                signature_files.append('MANIFEST.MF')
            if 'meta-inf/cert.sf' in output:
                signature_files.append('CERT.SF')
            if 'meta-inf/cert.rsa' in output or 'meta-inf/cert.dsa' in output:
                signature_files.append('CERT.RSA/DSA')
            
            if signature_files:
                print(f"✅ Found signature files: {', '.join(signature_files)}")
                return {
                    "signed": True,
                    "signature_details": f"Found signature files: {', '.join(signature_files)}",
                    "error": None
                }
            else:
                print("❌ No signature files found in META-INF")
                return {
                    "signed": False,
                    "signature_details": "No signature files found",
                    "error": "No META-INF signature files"
                }
        else:
            print(f"❌ Error listing APK contents: {result.stderr}")
            return {"signed": False, "error": result.stderr, "signature_details": None}
            
    except Exception as e:
        print(f"❌ Error in basic analysis: {e}")
        return {"signed": False, "error": str(e), "signature_details": None}

def analyze_apk_modification_risk(apk_path):
    """Analyze the risk of APK modification due to unsigned status"""
    print("\n🔍 Analyzing APK modification risks...")
    
    risks = []
    
    # Check file permissions
    apk_stat = os.stat(apk_path)
    risks.append(f"APK file size: {apk_stat.st_size:,} bytes")
    risks.append(f"APK modification time: {datetime.fromtimestamp(apk_stat.st_mtime)}")
    
    # Check if APK can be extracted
    try:
        extract_dir = Path("/tmp/mayndrive_extract_test")
        extract_dir.mkdir(exist_ok=True)
        
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            risks.append("✅ APK can be easily extracted and modified")
            
            # Check for sensitive files that could be modified
            sensitive_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if any(sensitive in file.lower() for sensitive in ['manifest', 'config', 'api', 'key', 'token']):
                        sensitive_files.append(os.path.join(root, file))
            
            if sensitive_files:
                risks.append(f"⚠️  Found {len(sensitive_files)} potentially sensitive files that could be modified")
                for file in sensitive_files[:5]:  # Show first 5
                    risks.append(f"   - {file}")
            
            # Cleanup
            subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        else:
            risks.append("❌ APK extraction failed")
            
    except Exception as e:
        risks.append(f"❌ Error analyzing extraction: {e}")
    
    return risks

def test_apk_repackaging():
    """Test if APK can be repackaged (demonstration only)"""
    print("\n🧪 Testing APK repackaging capability...")
    
    apk_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk"
    
    try:
        # Create test directory
        test_dir = Path("/tmp/mayndrive_repack_test")
        test_dir.mkdir(exist_ok=True)
        
        # Extract APK
        print("   📦 Extracting APK...")
        extract_result = subprocess.run(['unzip', '-q', apk_path, '-d', str(test_dir)], 
                                      capture_output=True, text=True, timeout=30)
        
        if extract_result.returncode != 0:
            print("   ❌ APK extraction failed")
            return False
        
        # Modify a harmless file (add a comment to AndroidManifest.xml)
        manifest_path = test_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            print("   ✏️  Modifying AndroidManifest.xml...")
            with open(manifest_path, 'rb') as f:
                content = f.read()
            
            # Add a comment (this is just for demonstration)
            modified_content = content + b'\n<!-- Modified by security test -->'
            
            with open(manifest_path, 'wb') as f:
                f.write(modified_content)
            
            print("   ✅ Successfully modified AndroidManifest.xml")
        
        # Test repackaging (without actually creating the APK)
        print("   📦 Testing repackaging capability...")
        
        # Check if we can create a new APK structure
        repack_test = subprocess.run(['zip', '-r', str(test_dir / "test_repack.apk"), '.'], 
                                   cwd=test_dir, capture_output=True, text=True, timeout=30)
        
        if repack_test.returncode == 0:
            print("   ✅ APK can be repackaged (unsigned)")
            repack_success = True
        else:
            print("   ❌ Repackaging failed")
            repack_success = False
        
        # Cleanup
        subprocess.run(['rm', '-rf', str(test_dir)], capture_output=True)
        
        return repack_success
        
    except Exception as e:
        print(f"   ❌ Error in repackaging test: {e}")
        return False

def generate_vulnerability_report(signature_result, modification_risks, repack_success):
    """Generate comprehensive vulnerability report"""
    print("\n" + "="*60)
    print("📊 UNSIGNED APK VULNERABILITY REPORT")
    print("="*60)
    
    # Determine vulnerability status
    if not signature_result.get("signed", False):
        vulnerability_status = "🚨 CRITICAL VULNERABILITY CONFIRMED"
        risk_level = "CRITICAL"
    else:
        vulnerability_status = "✅ NO VULNERABILITY"
        risk_level = "LOW"
    
    print(f"Status: {vulnerability_status}")
    print(f"Risk Level: {risk_level}")
    print(f"APK Signed: {signature_result.get('signed', False)}")
    print(f"Repackaging Possible: {repack_success}")
    
    print("\n📋 Detailed Analysis:")
    for risk in modification_risks:
        print(f"   {risk}")
    
    if signature_result.get("error"):
        print(f"\n❌ Signature Check Error: {signature_result['error']}")
    
    # Generate JSON report
    report_data = {
        "vulnerability_id": "APK_UNSIGNED",
        "severity": risk_level,
        "timestamp": datetime.now().isoformat(),
        "apk_signed": signature_result.get("signed", False),
        "signature_details": signature_result.get("signature_details"),
        "signature_error": signature_result.get("error"),
        "modification_risks": modification_risks,
        "repackaging_possible": repack_success,
        "vulnerability_confirmed": not signature_result.get("signed", False)
    }
    
    # Save report
    report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/unsigned_apk_report.json"
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📁 Report saved to: {report_path}")
    
    return report_data

def main():
    """Main analysis function"""
    print("🔍 MaynDrive Unsigned APK Vulnerability Analysis")
    print("="*60)
    print("🎯 Testing CRITICAL vulnerability: APK_UNSIGNED")
    print("="*60)
    
    apk_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk"
    
    if not os.path.exists(apk_path):
        print(f"❌ APK not found: {apk_path}")
        return
    
    print(f"📱 Analyzing APK: {apk_path}")
    
    # Step 1: Check APK signature
    signature_result = check_apk_signature(apk_path)
    
    # Step 2: Analyze modification risks
    modification_risks = analyze_apk_modification_risk(apk_path)
    
    # Step 3: Test repackaging capability
    repack_success = test_apk_repackaging()
    
    # Step 4: Generate report
    report = generate_vulnerability_report(signature_result, modification_risks, repack_success)
    
    print("\n" + "="*60)
    print("🎯 ANALYSIS COMPLETE")
    print("="*60)
    
    if report["vulnerability_confirmed"]:
        print("🚨 CRITICAL VULNERABILITY: Unsigned APK allows easy modification")
        print("💡 Recommendation: Sign the APK with a valid certificate")
    else:
        print("✅ NO VULNERABILITY: APK is properly signed")
    
    return report

if __name__ == "__main__":
    main()
