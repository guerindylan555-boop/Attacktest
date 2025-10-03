#!/usr/bin/env python3
"""
MaynDrive Dangerous Permissions Vulnerability Analysis
Tests HIGH severity vulnerabilities: Dangerous Permissions
"""

import subprocess
import json
import re
from pathlib import Path
from datetime import datetime

def extract_permissions_from_manifest(apk_path):
    """Extract permissions from AndroidManifest.xml"""
    print("🔍 Extracting permissions from AndroidManifest.xml...")
    
    try:
        # Use aapt to dump the manifest
        result = subprocess.run(['aapt', 'dump', 'permissions', apk_path], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            permissions = []
            for line in result.stdout.split('\n'):
                if 'uses-permission:' in line:
                    # Extract permission name
                    match = re.search(r"name='([^']+)'", line)
                    if match:
                        permissions.append(match.group(1))
            
            print(f"✅ Found {len(permissions)} permissions")
            return permissions
        else:
            print(f"❌ Error extracting permissions: {result.stderr}")
            return []
            
    except FileNotFoundError:
        print("❌ aapt not found - trying alternative method")
        return extract_permissions_alternative(apk_path)
    except Exception as e:
        print(f"❌ Error extracting permissions: {e}")
        return []

def extract_permissions_alternative(apk_path):
    """Alternative method to extract permissions"""
    print("🔍 Trying alternative permission extraction...")
    
    try:
        # Extract APK and read AndroidManifest.xml
        extract_dir = Path("/tmp/mayndrive_permissions_test")
        extract_dir.mkdir(exist_ok=True)
        
        # Extract APK
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print("❌ APK extraction failed")
            return []
        
        # Read AndroidManifest.xml
        manifest_path = extract_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            print("❌ AndroidManifest.xml not found")
            return []
        
        # Use aapt to dump the binary manifest
        dump_result = subprocess.run(['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'], 
                                   capture_output=True, text=True, timeout=30)
        
        if dump_result.returncode == 0:
            permissions = []
            for line in dump_result.stdout.split('\n'):
                if 'uses-permission' in line and 'android:name' in line:
                    # Extract permission name
                    match = re.search(r'android:name="([^"]+)"', line)
                    if match:
                        permissions.append(match.group(1))
            
            print(f"✅ Found {len(permissions)} permissions (alternative method)")
            return permissions
        else:
            print("❌ Error dumping manifest")
            return []
            
    except Exception as e:
        print(f"❌ Error in alternative extraction: {e}")
        return []
    finally:
        # Cleanup
        try:
            subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        except:
            pass

def analyze_dangerous_permissions(permissions):
    """Analyze dangerous permissions and their risks"""
    print("\n🔍 Analyzing dangerous permissions...")
    
    # Define dangerous permissions and their risk levels
    dangerous_permissions = {
        "android.permission.ACCESS_FINE_LOCATION": {
            "risk_level": "HIGH",
            "description": "Precise location access",
            "impact": "Can track exact user location",
            "legitimate_use": "Scooter location services"
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            "risk_level": "HIGH", 
            "description": "Approximate location access",
            "impact": "Can track general user location",
            "legitimate_use": "Scooter location services"
        },
        "android.permission.CAMERA": {
            "risk_level": "HIGH",
            "description": "Camera access",
            "impact": "Can take photos and videos",
            "legitimate_use": "Document scanning, QR codes"
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "risk_level": "HIGH",
            "description": "Read external storage",
            "impact": "Can access user files and photos",
            "legitimate_use": "Document upload, profile pictures"
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "risk_level": "HIGH",
            "description": "Write external storage", 
            "impact": "Can modify user files",
            "legitimate_use": "Save documents, cache data"
        },
        "android.permission.RECORD_AUDIO": {
            "risk_level": "HIGH",
            "description": "Record audio",
            "impact": "Can record conversations",
            "legitimate_use": "Voice notes, support calls"
        },
        "android.permission.READ_CONTACTS": {
            "risk_level": "HIGH",
            "description": "Read contacts",
            "impact": "Can access user's contact list",
            "legitimate_use": "Invite friends, emergency contacts"
        },
        "android.permission.READ_SMS": {
            "risk_level": "CRITICAL",
            "description": "Read SMS messages",
            "impact": "Can read all SMS messages",
            "legitimate_use": "SMS verification"
        },
        "android.permission.SEND_SMS": {
            "risk_level": "CRITICAL",
            "description": "Send SMS messages",
            "impact": "Can send SMS without user knowledge",
            "legitimate_use": "SMS notifications"
        }
    }
    
    found_dangerous = []
    analysis_results = []
    
    for permission in permissions:
        if permission in dangerous_permissions:
            perm_info = dangerous_permissions[permission]
            found_dangerous.append({
                "permission": permission,
                "risk_level": perm_info["risk_level"],
                "description": perm_info["description"],
                "impact": perm_info["impact"],
                "legitimate_use": perm_info["legitimate_use"]
            })
            
            analysis_results.append(f"🚨 {perm_info['risk_level']}: {permission}")
            analysis_results.append(f"   Description: {perm_info['description']}")
            analysis_results.append(f"   Impact: {perm_info['impact']}")
            analysis_results.append(f"   Legitimate Use: {perm_info['legitimate_use']}")
    
    return found_dangerous, analysis_results

def check_runtime_permissions(apk_path):
    """Check if the app requests permissions at runtime (Android 6.0+)"""
    print("\n🔍 Checking for runtime permission requests...")
    
    try:
        # Extract and analyze the APK for runtime permission code
        extract_dir = Path("/tmp/mayndrive_runtime_perms")
        extract_dir.mkdir(exist_ok=True)
        
        # Extract APK
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print("❌ APK extraction failed")
            return False
        
        # Look for runtime permission patterns in the code
        runtime_patterns = [
            "requestPermissions",
            "checkSelfPermission", 
            "shouldShowRequestPermissionRationale",
            "onRequestPermissionsResult",
            "Permission.requestPermissions"
        ]
        
        found_patterns = []
        
        # Search through all files for runtime permission patterns
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.java')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern in runtime_patterns:
                                if pattern in content:
                                    found_patterns.append(f"{pattern} in {file}")
                    except:
                        continue
        
        # Cleanup
        subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        
        if found_patterns:
            print(f"✅ Found {len(found_patterns)} runtime permission patterns:")
            for pattern in found_patterns[:10]:  # Show first 10
                print(f"   - {pattern}")
            return True
        else:
            print("❌ No runtime permission patterns found")
            return False
            
    except Exception as e:
        print(f"❌ Error checking runtime permissions: {e}")
        return False

def analyze_permission_risks(dangerous_permissions):
    """Analyze the overall risk of dangerous permissions"""
    print("\n🔍 Analyzing overall permission risks...")
    
    risk_analysis = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "total_dangerous": len(dangerous_permissions),
        "risk_factors": []
    }
    
    for perm in dangerous_permissions:
        risk_level = perm["risk_level"]
        if risk_level == "CRITICAL":
            risk_analysis["critical_count"] += 1
        elif risk_level == "HIGH":
            risk_analysis["high_count"] += 1
        elif risk_level == "MEDIUM":
            risk_analysis["medium_count"] += 1
        else:
            risk_analysis["low_count"] += 1
    
    # Determine overall risk
    if risk_analysis["critical_count"] > 0:
        overall_risk = "CRITICAL"
    elif risk_analysis["high_count"] >= 3:
        overall_risk = "HIGH"
    elif risk_analysis["high_count"] > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"
    
    # Add risk factors
    if risk_analysis["critical_count"] > 0:
        risk_analysis["risk_factors"].append("Critical permissions present")
    if risk_analysis["high_count"] >= 3:
        risk_analysis["risk_factors"].append("Multiple high-risk permissions")
    if risk_analysis["total_dangerous"] > 5:
        risk_analysis["risk_factors"].append("Excessive dangerous permissions")
    
    risk_analysis["overall_risk"] = overall_risk
    
    return risk_analysis

def generate_permission_report(permissions, dangerous_permissions, runtime_perms, risk_analysis):
    """Generate comprehensive permission vulnerability report"""
    print("\n" + "="*60)
    print("📊 DANGEROUS PERMISSIONS VULNERABILITY REPORT")
    print("="*60)
    
    print(f"Total Permissions: {len(permissions)}")
    print(f"Dangerous Permissions: {len(dangerous_permissions)}")
    print(f"Runtime Permissions: {'Yes' if runtime_perms else 'No'}")
    print(f"Overall Risk: {risk_analysis['overall_risk']}")
    
    print(f"\nRisk Breakdown:")
    print(f"   Critical: {risk_analysis['critical_count']}")
    print(f"   High: {risk_analysis['high_count']}")
    print(f"   Medium: {risk_analysis['medium_count']}")
    print(f"   Low: {risk_analysis['low_count']}")
    
    if risk_analysis['risk_factors']:
        print(f"\nRisk Factors:")
        for factor in risk_analysis['risk_factors']:
            print(f"   - {factor}")
    
    # Generate JSON report
    report_data = {
        "vulnerability_id": "DANGEROUS_PERMISSIONS",
        "severity": risk_analysis['overall_risk'],
        "timestamp": datetime.now().isoformat(),
        "total_permissions": len(permissions),
        "dangerous_permissions": dangerous_permissions,
        "runtime_permissions_implemented": runtime_perms,
        "risk_analysis": risk_analysis,
        "all_permissions": permissions,
        "vulnerability_confirmed": risk_analysis['overall_risk'] in ['CRITICAL', 'HIGH']
    }
    
    # Save report
    report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/dangerous_permissions_report.json"
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📁 Report saved to: {report_path}")
    
    return report_data

def main():
    """Main analysis function"""
    print("🔍 MaynDrive Dangerous Permissions Vulnerability Analysis")
    print("="*60)
    print("🎯 Testing HIGH severity vulnerabilities: Dangerous Permissions")
    print("="*60)
    
    apk_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk"
    
    if not os.path.exists(apk_path):
        print(f"❌ APK not found: {apk_path}")
        return
    
    print(f"📱 Analyzing APK: {apk_path}")
    
    # Step 1: Extract permissions
    permissions = extract_permissions_from_manifest(apk_path)
    
    if not permissions:
        print("❌ No permissions found")
        return
    
    # Step 2: Analyze dangerous permissions
    dangerous_permissions, analysis_results = analyze_dangerous_permissions(permissions)
    
    # Step 3: Check runtime permissions
    runtime_perms = check_runtime_permissions(apk_path)
    
    # Step 4: Analyze overall risk
    risk_analysis = analyze_permission_risks(dangerous_permissions)
    
    # Step 5: Generate report
    report = generate_permission_report(permissions, dangerous_permissions, runtime_perms, risk_analysis)
    
    print("\n" + "="*60)
    print("🎯 ANALYSIS COMPLETE")
    print("="*60)
    
    if report["vulnerability_confirmed"]:
        print(f"🚨 {risk_analysis['overall_risk']} VULNERABILITY: Dangerous permissions present")
        print("💡 Recommendation: Implement runtime permission requests and review necessity")
    else:
        print("✅ LOW RISK: Permissions appear appropriate for scooter app")
    
    return report

if __name__ == "__main__":
    import os
    main()
