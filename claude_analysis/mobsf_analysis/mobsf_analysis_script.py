#!/usr/bin/env python3
"""
MaynDrive MobSF Vulnerability Analysis Script
Comprehensive security analysis using Mobile Security Framework (MobSF)
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

class MaynDriveMobSFAnalysis:
    def __init__(self, apk_path, output_dir):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_results = {}
        
    def setup_mobsf(self):
        """Initialize MobSF environment"""
        print("🔧 Setting up MobSF environment...")
        
        # Check if MobSF is installed
        try:
            result = subprocess.run(['mobsf', '--version'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print(f"✅ MobSF version: {result.stdout.strip()}")
                return True
        except Exception as e:
            print(f"❌ MobSF not found: {e}")
            return False
    
    def start_mobsf_server(self):
        """Start MobSF server in background"""
        print("🚀 Starting MobSF server...")
        
        try:
            # Start MobSF server in background
            self.mobsf_process = subprocess.Popen(
                ['mobsf', '--host', '127.0.0.1', '--port', '8000'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start
            time.sleep(10)
            
            # Check if server is running
            import requests
            try:
                response = requests.get('http://127.0.0.1:8000', timeout=5)
                if response.status_code == 200:
                    print("✅ MobSF server started successfully")
                    return True
            except:
                pass
                
            print("❌ Failed to start MobSF server")
            return False
            
        except Exception as e:
            print(f"❌ Error starting MobSF server: {e}")
            return False
    
    def run_static_analysis(self):
        """Run static analysis on the APK"""
        print("🔍 Running static analysis...")
        
        try:
            # Use MobSF API for static analysis
            import requests
            
            # Upload APK
            with open(self.apk_path, 'rb') as f:
                files = {'file': (self.apk_path.name, f, 'application/vnd.android.package-archive')}
                response = requests.post('http://127.0.0.1:8000/api/v1/upload', files=files)
            
            if response.status_code == 200:
                upload_data = response.json()
                file_hash = upload_data['hash']
                print(f"✅ APK uploaded successfully. Hash: {file_hash}")
                
                # Start static analysis
                analysis_response = requests.post(f'http://127.0.0.1:8000/api/v1/scan', 
                                                json={'hash': file_hash})
                
                if analysis_response.status_code == 200:
                    print("✅ Static analysis started")
                    
                    # Wait for analysis to complete
                    time.sleep(30)
                    
                    # Get analysis results
                    results_response = requests.get(f'http://127.0.0.1:8000/api/v1/report_json', 
                                                  params={'hash': file_hash})
                    
                    if results_response.status_code == 200:
                        self.analysis_results['static'] = results_response.json()
                        print("✅ Static analysis completed")
                        
                        # Save results
                        with open(self.output_dir / 'static_analysis.json', 'w') as f:
                            json.dump(self.analysis_results['static'], f, indent=2)
                        
                        return True
                    else:
                        print(f"❌ Failed to get analysis results: {results_response.status_code}")
                        return False
                else:
                    print(f"❌ Failed to start analysis: {analysis_response.status_code}")
                    return False
            else:
                print(f"❌ Failed to upload APK: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error during static analysis: {e}")
            return False
    
    def run_dynamic_analysis(self):
        """Run dynamic analysis (requires Android device/emulator)"""
        print("🔍 Running dynamic analysis...")
        
        try:
            # Check if Android device is connected
            result = subprocess.run(['adb', 'devices'], 
                                  capture_output=True, text=True, timeout=10)
            
            if 'device' not in result.stdout:
                print("⚠️  No Android device connected. Skipping dynamic analysis.")
                print("   To run dynamic analysis, connect an Android device or start an emulator")
                return False
            
            print("✅ Android device detected")
            
            # Dynamic analysis would go here
            # This requires additional setup with Frida and device configuration
            print("⚠️  Dynamic analysis requires additional setup with Frida")
            print("   This will be implemented in the next phase")
            
            return False
            
        except Exception as e:
            print(f"❌ Error during dynamic analysis: {e}")
            return False
    
    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        print("📊 Generating vulnerability report...")
        
        report = {
            'analysis_info': {
                'timestamp': datetime.now().isoformat(),
                'apk_path': str(self.apk_path),
                'apk_size': self.apk_path.stat().st_size,
                'analysis_type': 'MobSF Static Analysis'
            },
            'summary': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        if 'static' in self.analysis_results:
            static_data = self.analysis_results['static']
            
            # Extract key information
            report['summary'] = {
                'app_name': static_data.get('app_name', 'Unknown'),
                'package_name': static_data.get('package_name', 'Unknown'),
                'version': static_data.get('version_name', 'Unknown'),
                'permissions': len(static_data.get('permissions', [])),
                'activities': len(static_data.get('activities', [])),
                'services': len(static_data.get('services', [])),
                'receivers': len(static_data.get('receivers', [])),
                'providers': len(static_data.get('providers', []))
            }
            
            # Analyze vulnerabilities
            vulnerabilities = static_data.get('vulnerabilities', {})
            for vuln_type, vuln_data in vulnerabilities.items():
                if isinstance(vuln_data, dict) and vuln_data.get('files'):
                    report['vulnerabilities'].append({
                        'type': vuln_type,
                        'severity': vuln_data.get('metadata', {}).get('severity', 'Unknown'),
                        'description': vuln_data.get('metadata', {}).get('description', 'No description'),
                        'files_affected': len(vuln_data.get('files', [])),
                        'files': vuln_data.get('files', [])[:5]  # Limit to first 5 files
                    })
            
            # Generate recommendations
            report['recommendations'] = self._generate_recommendations(static_data)
        
        # Save report
        with open(self.output_dir / 'vulnerability_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate markdown report
        self._generate_markdown_report(report)
        
        print("✅ Vulnerability report generated")
        return report
    
    def _generate_recommendations(self, static_data):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Check for common security issues
        permissions = static_data.get('permissions', [])
        
        # Dangerous permissions
        dangerous_perms = [
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION'
        ]
        
        found_dangerous = [perm for perm in permissions if perm in dangerous_perms]
        if found_dangerous:
            recommendations.append({
                'category': 'Permissions',
                'issue': 'Dangerous permissions detected',
                'recommendation': 'Review and minimize dangerous permissions. Use runtime permissions for sensitive operations.',
                'permissions': found_dangerous
            })
        
        # Network security
        if 'android.permission.INTERNET' in permissions:
            recommendations.append({
                'category': 'Network Security',
                'issue': 'Internet permission detected',
                'recommendation': 'Implement certificate pinning and use HTTPS for all network communications.'
            })
        
        # Backup and debugging
        if static_data.get('allow_backup', False):
            recommendations.append({
                'category': 'Data Protection',
                'issue': 'Allow backup is enabled',
                'recommendation': 'Disable allowBackup to prevent data extraction via ADB backup.'
            })
        
        if static_data.get('debuggable', False):
            recommendations.append({
                'category': 'Debugging',
                'issue': 'App is debuggable',
                'recommendation': 'Disable debuggable flag in production builds.'
            })
        
        return recommendations
    
    def _generate_markdown_report(self, report):
        """Generate markdown vulnerability report"""
        md_content = f"""# MaynDrive Security Analysis Report

## Analysis Information
- **Timestamp**: {report['analysis_info']['timestamp']}
- **APK Path**: {report['analysis_info']['apk_path']}
- **APK Size**: {report['analysis_info']['apk_size']:,} bytes
- **Analysis Type**: {report['analysis_info']['analysis_type']}

## Application Summary
- **App Name**: {report['summary'].get('app_name', 'Unknown')}
- **Package Name**: {report['summary'].get('package_name', 'Unknown')}
- **Version**: {report['summary'].get('version', 'Unknown')}
- **Permissions**: {report['summary'].get('permissions', 0)}
- **Activities**: {report['summary'].get('activities', 0)}
- **Services**: {report['summary'].get('services', 0)}
- **Receivers**: {report['summary'].get('receivers', 0)}
- **Providers**: {report['summary'].get('providers', 0)}

## Vulnerabilities Found
"""
        
        if report['vulnerabilities']:
            for vuln in report['vulnerabilities']:
                md_content += f"""
### {vuln['type']}
- **Severity**: {vuln['severity']}
- **Description**: {vuln['description']}
- **Files Affected**: {vuln['files_affected']}
"""
        else:
            md_content += "\nNo specific vulnerabilities detected in static analysis.\n"
        
        md_content += "\n## Security Recommendations\n"
        
        for rec in report['recommendations']:
            md_content += f"""
### {rec['category']}
- **Issue**: {rec['issue']}
- **Recommendation**: {rec['recommendation']}
"""
        
        md_content += f"""
## Next Steps
1. Review all identified vulnerabilities
2. Implement recommended security measures
3. Consider dynamic analysis for runtime behavior
4. Perform penetration testing
5. Regular security audits

---
*Report generated by MobSF Analysis Script*
"""
        
        with open(self.output_dir / 'vulnerability_report.md', 'w') as f:
            f.write(md_content)
    
    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'mobsf_process'):
            try:
                self.mobsf_process.terminate()
                print("🧹 MobSF server stopped")
            except:
                pass

def main():
    """Main analysis function"""
    print("=" * 60)
    print("🔒 MaynDrive MobSF Security Analysis")
    print("=" * 60)
    
    # Paths
    apk_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk"
    output_dir = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/results"
    
    # Initialize analysis
    analysis = MaynDriveMobSFAnalysis(apk_path, output_dir)
    
    try:
        # Setup MobSF
        if not analysis.setup_mobsf():
            print("❌ MobSF setup failed")
            return False
        
        # Start MobSF server
        if not analysis.start_mobsf_server():
            print("❌ Failed to start MobSF server")
            return False
        
        # Run static analysis
        if analysis.run_static_analysis():
            print("✅ Static analysis completed successfully")
        else:
            print("❌ Static analysis failed")
        
        # Run dynamic analysis
        analysis.run_dynamic_analysis()
        
        # Generate report
        report = analysis.generate_report()
        
        print("\n" + "=" * 60)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"📁 Results saved to: {output_dir}")
        print(f"📄 Report: {output_dir}/vulnerability_report.md")
        print(f"📊 JSON Data: {output_dir}/vulnerability_report.json")
        
        return True
        
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        return False
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False
    finally:
        analysis.cleanup()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
