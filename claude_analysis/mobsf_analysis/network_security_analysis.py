#!/usr/bin/env python3
"""
MaynDrive Network Security Vulnerability Analysis
Tests MEDIUM severity vulnerabilities: Certificate Pinning, Network Security
"""

import subprocess
import json
import re
import os
from pathlib import Path
from datetime import datetime

def extract_network_security_config(apk_path):
    """Extract network security configuration from APK"""
    print("🔍 Extracting network security configuration...")
    
    try:
        # Extract APK to analyze network security files
        extract_dir = Path("/tmp/mayndrive_network_security")
        extract_dir.mkdir(exist_ok=True)
        
        # Extract APK
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print("❌ APK extraction failed")
            return None
        
        # Look for network security configuration files
        network_security_files = []
        
        # Check for network_security_config.xml
        ns_config_path = extract_dir / "res" / "xml" / "network_security_config.xml"
        if ns_config_path.exists():
            network_security_files.append(str(ns_config_path))
        
        # Check for other network security related files
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if 'network' in file.lower() and 'security' in file.lower():
                    network_security_files.append(os.path.join(root, file))
                elif file.endswith('.xml') and ('ssl' in file.lower() or 'cert' in file.lower()):
                    network_security_files.append(os.path.join(root, file))
        
        print(f"✅ Found {len(network_security_files)} network security files")
        
        # Analyze the files
        analysis_results = []
        for file_path in network_security_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    analysis_results.append({
                        "file": file_path,
                        "content": content,
                        "size": len(content)
                    })
            except Exception as e:
                print(f"❌ Error reading {file_path}: {e}")
        
        # Cleanup
        subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        
        return analysis_results
        
    except Exception as e:
        print(f"❌ Error extracting network security config: {e}")
        return None

def analyze_certificate_pinning(apk_path):
    """Analyze certificate pinning implementation"""
    print("\n🔍 Analyzing certificate pinning...")
    
    try:
        # Extract APK to search for certificate pinning code
        extract_dir = Path("/tmp/mayndrive_cert_pinning")
        extract_dir.mkdir(exist_ok=True)
        
        # Extract APK
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print("❌ APK extraction failed")
            return False
        
        # Search for certificate pinning patterns
        pinning_patterns = [
            "CertificatePinner",
            "certificatePinner",
            "pin-sha256",
            "pin-sha1",
            "TrustManager",
            "X509TrustManager",
            "SSLContext",
            "HttpsURLConnection",
            "OkHttp",
            "certificate",
            "pinning",
            "trust",
            "ssl"
        ]
        
        found_patterns = []
        pinning_files = []
        
        # Search through all files for certificate pinning patterns
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.java', '.kt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            file_patterns = []
                            for pattern in pinning_patterns:
                                if pattern in content:
                                    file_patterns.append(pattern)
                            
                            if file_patterns:
                                found_patterns.extend(file_patterns)
                                pinning_files.append({
                                    "file": file_path,
                                    "patterns": file_patterns
                                })
                    except:
                        continue
        
        # Cleanup
        subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        
        if found_patterns:
            print(f"✅ Found {len(found_patterns)} certificate pinning patterns")
            print(f"   Patterns found: {', '.join(set(found_patterns))}")
            print(f"   Files with pinning code: {len(pinning_files)}")
            return True
        else:
            print("❌ No certificate pinning patterns found")
            return False
            
    except Exception as e:
        print(f"❌ Error analyzing certificate pinning: {e}")
        return False

def check_http_traffic_allowed(apk_path):
    """Check if HTTP traffic is allowed (cleartext traffic)"""
    print("\n🔍 Checking for cleartext HTTP traffic...")
    
    try:
        # Use aapt to dump the manifest and look for cleartext traffic settings
        result = subprocess.run(['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            manifest_content = result.stdout
            
            # Look for cleartext traffic settings
            cleartext_patterns = [
                "android:usesCleartextTraffic",
                "android:networkSecurityConfig",
                "cleartext",
                "http://"
            ]
            
            found_cleartext = []
            for pattern in cleartext_patterns:
                if pattern in manifest_content:
                    found_cleartext.append(pattern)
            
            if found_cleartext:
                print(f"⚠️  Found cleartext traffic patterns: {', '.join(found_cleartext)}")
                return True
            else:
                print("✅ No cleartext traffic patterns found")
                return False
        else:
            print(f"❌ Error dumping manifest: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking cleartext traffic: {e}")
        return False

def analyze_network_libraries(apk_path):
    """Analyze network libraries used in the app"""
    print("\n🔍 Analyzing network libraries...")
    
    try:
        # Extract APK to analyze network libraries
        extract_dir = Path("/tmp/mayndrive_network_libs")
        extract_dir.mkdir(exist_ok=True)
        
        # Extract APK
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print("❌ APK extraction failed")
            return []
        
        # Look for network library files
        network_libraries = []
        
        # Check for common network libraries
        library_patterns = [
            "okhttp",
            "retrofit", 
            "volley",
            "httpclient",
            "urlconnection",
            "gson",
            "moshi",
            "jackson"
        ]
        
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                file_lower = file.lower()
                for pattern in library_patterns:
                    if pattern in file_lower:
                        network_libraries.append({
                            "library": pattern,
                            "file": os.path.join(root, file)
                        })
        
        # Cleanup
        subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        
        if network_libraries:
            print(f"✅ Found {len(network_libraries)} network libraries:")
            for lib in network_libraries[:10]:  # Show first 10
                print(f"   - {lib['library']}: {lib['file']}")
        else:
            print("❌ No network libraries found")
        
        return network_libraries
        
    except Exception as e:
        print(f"❌ Error analyzing network libraries: {e}")
        return []

def check_api_endpoints(apk_path):
    """Check for hardcoded API endpoints"""
    print("\n🔍 Checking for hardcoded API endpoints...")
    
    try:
        # Extract APK to search for API endpoints
        extract_dir = Path("/tmp/mayndrive_api_endpoints")
        extract_dir.mkdir(exist_ok=True)
        
        # Extract APK
        result = subprocess.run(['unzip', '-q', apk_path, '-d', str(extract_dir)], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print("❌ APK extraction failed")
            return []
        
        # Search for API endpoint patterns
        endpoint_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?:/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]*)?',
            r'api\.[a-zA-Z0-9.-]+',
            r'[a-zA-Z0-9.-]+\.com',
            r'[a-zA-Z0-9.-]+\.io',
            r'[a-zA-Z0-9.-]+\.net'
        ]
        
        found_endpoints = []
        
        # Search through all files for API endpoints
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith(('.smali', '.xml', '.java', '.kt', '.properties')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern in endpoint_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    if match not in found_endpoints:
                                        found_endpoints.append(match)
                    except:
                        continue
        
        # Cleanup
        subprocess.run(['rm', '-rf', str(extract_dir)], capture_output=True)
        
        if found_endpoints:
            print(f"✅ Found {len(found_endpoints)} API endpoints:")
            for endpoint in found_endpoints[:10]:  # Show first 10
                print(f"   - {endpoint}")
        else:
            print("❌ No API endpoints found")
        
        return found_endpoints
        
    except Exception as e:
        print(f"❌ Error checking API endpoints: {e}")
        return []

def analyze_network_security_risks(cert_pinning, cleartext_allowed, network_libs, api_endpoints):
    """Analyze overall network security risks"""
    print("\n🔍 Analyzing network security risks...")
    
    risk_factors = []
    risk_level = "LOW"
    
    # Certificate pinning analysis
    if not cert_pinning:
        risk_factors.append("No certificate pinning implemented")
        risk_level = "MEDIUM"
    
    # Cleartext traffic analysis
    if cleartext_allowed:
        risk_factors.append("Cleartext HTTP traffic allowed")
        if risk_level == "LOW":
            risk_level = "MEDIUM"
    
    # Network libraries analysis
    if not network_libs:
        risk_factors.append("No modern network libraries detected")
    
    # API endpoints analysis
    if api_endpoints:
        risk_factors.append(f"Found {len(api_endpoints)} hardcoded API endpoints")
        if len(api_endpoints) > 5:
            risk_level = "HIGH"
    
    # Determine overall risk
    if len(risk_factors) >= 3:
        risk_level = "HIGH"
    elif len(risk_factors) >= 2:
        risk_level = "MEDIUM"
    
    return {
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "certificate_pinning": cert_pinning,
        "cleartext_allowed": cleartext_allowed,
        "network_libraries_count": len(network_libs),
        "api_endpoints_count": len(api_endpoints)
    }

def generate_network_security_report(risk_analysis, network_libs, api_endpoints):
    """Generate comprehensive network security report"""
    print("\n" + "="*60)
    print("📊 NETWORK SECURITY VULNERABILITY REPORT")
    print("="*60)
    
    print(f"Overall Risk: {risk_analysis['risk_level']}")
    print(f"Certificate Pinning: {'Yes' if risk_analysis['certificate_pinning'] else 'No'}")
    print(f"Cleartext Traffic: {'Allowed' if risk_analysis['cleartext_allowed'] else 'Blocked'}")
    print(f"Network Libraries: {risk_analysis['network_libraries_count']}")
    print(f"API Endpoints: {risk_analysis['api_endpoints_count']}")
    
    if risk_analysis['risk_factors']:
        print(f"\nRisk Factors:")
        for factor in risk_analysis['risk_factors']:
            print(f"   - {factor}")
    
    # Generate JSON report
    report_data = {
        "vulnerability_id": "NETWORK_SECURITY",
        "severity": risk_analysis['risk_level'],
        "timestamp": datetime.now().isoformat(),
        "certificate_pinning_implemented": risk_analysis['certificate_pinning'],
        "cleartext_traffic_allowed": risk_analysis['cleartext_allowed'],
        "network_libraries": network_libs,
        "api_endpoints": api_endpoints,
        "risk_analysis": risk_analysis,
        "vulnerability_confirmed": risk_analysis['risk_level'] in ['HIGH', 'MEDIUM']
    }
    
    # Save report
    report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/network_security_report.json"
    with open(report_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📁 Report saved to: {report_path}")
    
    return report_data

def main():
    """Main analysis function"""
    print("🔍 MaynDrive Network Security Vulnerability Analysis")
    print("="*60)
    print("🎯 Testing MEDIUM severity vulnerabilities: Network Security")
    print("="*60)
    
    apk_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk"
    
    if not os.path.exists(apk_path):
        print(f"❌ APK not found: {apk_path}")
        return
    
    print(f"📱 Analyzing APK: {apk_path}")
    
    # Step 1: Extract network security configuration
    network_config = extract_network_security_config(apk_path)
    
    # Step 2: Analyze certificate pinning
    cert_pinning = analyze_certificate_pinning(apk_path)
    
    # Step 3: Check cleartext traffic
    cleartext_allowed = check_http_traffic_allowed(apk_path)
    
    # Step 4: Analyze network libraries
    network_libs = analyze_network_libraries(apk_path)
    
    # Step 5: Check API endpoints
    api_endpoints = check_api_endpoints(apk_path)
    
    # Step 6: Analyze overall risks
    risk_analysis = analyze_network_security_risks(cert_pinning, cleartext_allowed, network_libs, api_endpoints)
    
    # Step 7: Generate report
    report = generate_network_security_report(risk_analysis, network_libs, api_endpoints)
    
    print("\n" + "="*60)
    print("🎯 ANALYSIS COMPLETE")
    print("="*60)
    
    if report["vulnerability_confirmed"]:
        print(f"🚨 {risk_analysis['risk_level']} VULNERABILITY: Network security issues found")
        print("💡 Recommendation: Implement certificate pinning and disable cleartext traffic")
    else:
        print("✅ LOW RISK: Network security appears adequate")
    
    return report

if __name__ == "__main__":
    main()
