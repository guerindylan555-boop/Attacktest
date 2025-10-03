#!/usr/bin/env python3
"""
MaynDrive MobSF Analysis Runner
Simplified approach using MobSF CLI and direct analysis
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

def run_mobsf_static_analysis(apk_path, output_dir):
    """Run MobSF static analysis using command line"""
    print(f"🔍 Analyzing APK: {apk_path}")
    
    try:
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Run MobSF static analysis
        cmd = [
            'python3', '-m', 'mobsf.MobSF',
            '--scan', str(apk_path),
            '--output', str(output_dir)
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ MobSF static analysis completed")
            return True
        else:
            print(f"❌ MobSF analysis failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Analysis timed out")
        return False
    except Exception as e:
        print(f"❌ Error running analysis: {e}")
        return False

def analyze_apk_with_tools(apk_path, output_dir):
    """Analyze APK using various tools"""
    print("🔧 Running comprehensive APK analysis...")
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'apk_path': str(apk_path),
        'apk_size': apk_path.stat().st_size,
        'analysis_results': {}
    }
    
    # 1. Basic APK info
    try:
        print("📱 Extracting APK information...")
        cmd = ['aapt', 'dump', 'badging', str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            results['analysis_results']['apk_info'] = {
                'aapt_output': result.stdout,
                'raw_info': result.stdout.split('\n')
            }
            print("✅ APK information extracted")
        else:
            print("⚠️  aapt not available, skipping APK info extraction")
    except Exception as e:
        print(f"⚠️  Error extracting APK info: {e}")
    
    # 2. Check for common security issues
    print("🔒 Checking for security issues...")
    security_issues = []
    
    # Check if APK is signed
    try:
        cmd = ['jarsigner', '-verify', '-verbose', '-certs', str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if 'jar verified' in result.stdout:
            security_issues.append({
                'type': 'APK_SIGNING',
                'status': 'SIGNED',
                'description': 'APK is properly signed'
            })
        else:
            security_issues.append({
                'type': 'APK_SIGNING',
                'status': 'UNSIGNED',
                'description': 'APK is not signed - security risk'
            })
    except Exception as e:
        print(f"⚠️  Could not verify APK signature: {e}")
    
    # 3. Extract and analyze manifest
    try:
        print("📋 Analyzing AndroidManifest.xml...")
        cmd = ['aapt', 'dump', 'xmltree', str(apk_path), 'AndroidManifest.xml']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            manifest_analysis = analyze_manifest(result.stdout)
            results['analysis_results']['manifest'] = manifest_analysis
            security_issues.extend(manifest_analysis.get('security_issues', []))
            print("✅ Manifest analysis completed")
    except Exception as e:
        print(f"⚠️  Error analyzing manifest: {e}")
    
    # 4. Check for hardcoded secrets
    print("🔐 Checking for hardcoded secrets...")
    try:
        cmd = ['strings', str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            secrets = find_potential_secrets(result.stdout)
            if secrets:
                security_issues.append({
                    'type': 'HARDCODED_SECRETS',
                    'status': 'FOUND',
                    'description': f'Found {len(secrets)} potential hardcoded secrets',
                    'secrets': secrets[:10]  # Limit to first 10
                })
            else:
                security_issues.append({
                    'type': 'HARDCODED_SECRETS',
                    'status': 'NONE_FOUND',
                    'description': 'No obvious hardcoded secrets detected'
                })
    except Exception as e:
        print(f"⚠️  Error checking for secrets: {e}")
    
    results['analysis_results']['security_issues'] = security_issues
    
    # Create output directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Save results
    with open(Path(output_dir) / 'analysis_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

def analyze_manifest(manifest_xml):
    """Analyze AndroidManifest.xml for security issues"""
    analysis = {
        'permissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
        'security_issues': []
    }
    
    lines = manifest_xml.split('\n')
    current_element = None
    
    for line in lines:
        line = line.strip()
        
        # Extract permissions
        if 'uses-permission' in line and 'android:name=' in line:
            perm = extract_quoted_value(line, 'android:name=')
            if perm:
                analysis['permissions'].append(perm)
                
                # Check for dangerous permissions
                dangerous_perms = [
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'android.permission.READ_EXTERNAL_STORAGE',
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.ACCESS_COARSE_LOCATION',
                    'android.permission.READ_PHONE_STATE',
                    'android.permission.READ_SMS',
                    'android.permission.SEND_SMS'
                ]
                
                if perm in dangerous_perms:
                    analysis['security_issues'].append({
                        'type': 'DANGEROUS_PERMISSION',
                        'permission': perm,
                        'severity': 'HIGH',
                        'description': f'Dangerous permission: {perm}'
                    })
        
        # Extract activities
        elif 'activity' in line and 'android:name=' in line:
            activity = extract_quoted_value(line, 'android:name=')
            if activity:
                analysis['activities'].append(activity)
        
        # Check for debuggable
        elif 'android:debuggable=' in line:
            debuggable = extract_quoted_value(line, 'android:debuggable=')
            if debuggable == 'true':
                analysis['security_issues'].append({
                    'type': 'DEBUGGABLE',
                    'severity': 'HIGH',
                    'description': 'App is debuggable - security risk'
                })
        
        # Check for allowBackup
        elif 'android:allowBackup=' in line:
            allow_backup = extract_quoted_value(line, 'android:allowBackup=')
            if allow_backup == 'true':
                analysis['security_issues'].append({
                    'type': 'ALLOW_BACKUP',
                    'severity': 'MEDIUM',
                    'description': 'allowBackup is enabled - data extraction risk'
                })
    
    return analysis

def extract_quoted_value(line, key):
    """Extract quoted value from XML line"""
    try:
        start = line.find(key)
        if start == -1:
            return None
        
        start += len(key)
        if line[start] == '"':
            start += 1
            end = line.find('"', start)
            if end != -1:
                return line[start:end]
    except:
        pass
    return None

def find_potential_secrets(strings_output):
    """Find potential hardcoded secrets in strings"""
    secrets = []
    lines = strings_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Check for API keys
        if any(keyword in line.lower() for keyword in ['api_key', 'apikey', 'secret_key', 'access_key']):
            if len(line) > 10 and len(line) < 100:  # Reasonable length for keys
                secrets.append(f"Potential API key: {line[:50]}...")
        
        # Check for tokens
        elif any(keyword in line.lower() for keyword in ['token', 'bearer', 'jwt']):
            if len(line) > 20 and len(line) < 200:
                secrets.append(f"Potential token: {line[:50]}...")
        
        # Check for passwords
        elif any(keyword in line.lower() for keyword in ['password', 'passwd', 'pwd']):
            if len(line) > 5 and len(line) < 50:
                secrets.append(f"Potential password: {line[:30]}...")
        
        # Check for URLs with credentials
        elif '://' in line and ('@' in line or 'user' in line.lower()):
            secrets.append(f"Potential URL with credentials: {line[:50]}...")
    
    return secrets

def generate_report(results, output_dir):
    """Generate comprehensive security report"""
    print("📊 Generating security report...")
    
    report = f"""# MaynDrive Security Analysis Report

## Analysis Summary
- **Timestamp**: {results['timestamp']}
- **APK Path**: {results['apk_path']}
- **APK Size**: {results['apk_size']:,} bytes

## Security Issues Found
"""
    
    security_issues = results['analysis_results'].get('security_issues', [])
    
    if security_issues:
        for issue in security_issues:
            report += f"""
### {issue['type']}
- **Severity**: {issue.get('severity', 'Unknown')}
- **Description**: {issue['description']}
"""
            if 'permission' in issue:
                report += f"- **Permission**: {issue['permission']}\n"
            if 'secrets' in issue:
                report += f"- **Secrets Found**: {len(issue['secrets'])}\n"
    else:
        report += "\nNo specific security issues detected.\n"
    
    # Add recommendations
    report += """
## Security Recommendations

### High Priority
1. **Review Dangerous Permissions**: Remove unnecessary dangerous permissions
2. **Disable Debugging**: Ensure debuggable=false in production builds
3. **Certificate Pinning**: Implement SSL certificate pinning
4. **Data Protection**: Disable allowBackup if not needed

### Medium Priority
1. **Runtime Permissions**: Use runtime permissions for sensitive operations
2. **Code Obfuscation**: Implement code obfuscation
3. **Root Detection**: Add root detection mechanisms
4. **Anti-Tampering**: Implement anti-tampering measures

### Low Priority
1. **Regular Updates**: Keep dependencies updated
2. **Security Testing**: Implement automated security testing
3. **Monitoring**: Add runtime security monitoring

## Next Steps
1. Address all HIGH severity issues immediately
2. Implement recommended security measures
3. Perform dynamic analysis and penetration testing
4. Regular security audits and updates

---
*Report generated by MaynDrive Security Analysis*
"""
    
    # Save report
    with open(Path(output_dir) / 'security_report.md', 'w') as f:
        f.write(report)
    
    print("✅ Security report generated")

def main():
    """Main analysis function"""
    print("=" * 60)
    print("🔒 MaynDrive Security Analysis")
    print("=" * 60)
    
    # Paths
    apk_path = Path("/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk")
    output_dir = Path("/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/results")
    
    if not apk_path.exists():
        print(f"❌ APK file not found: {apk_path}")
        return False
    
    try:
        # Run comprehensive analysis
        results = analyze_apk_with_tools(apk_path, output_dir)
        
        # Generate report
        generate_report(results, output_dir)
        
        print("\n" + "=" * 60)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"📁 Results saved to: {output_dir}")
        print(f"📄 Report: {output_dir}/security_report.md")
        print(f"📊 JSON Data: {output_dir}/analysis_results.json")
        
        return True
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
