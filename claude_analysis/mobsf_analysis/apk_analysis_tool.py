#!/usr/bin/env python3
"""
APK Analysis Tool - Educational Purpose Only
Demonstrates how hardcoded secrets can be extracted from APK files
⚠️ FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY
"""

import os
import re
import json
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

class APKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.extracted_secrets = []
        self.api_endpoints = []
        
    def decompile_apk(self, output_dir):
        """Decompile APK using apktool"""
        print("🔧 Decompiling APK...")
        
        try:
            # Use apktool to decompile
            cmd = ['apktool', 'd', str(self.apk_path), '-o', str(output_dir), '-f']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("✅ APK decompiled successfully")
                return True
            else:
                print(f"❌ Decompilation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Decompilation timed out")
            return False
        except FileNotFoundError:
            print("❌ apktool not found. Please install apktool first.")
            return False
    
    def extract_strings_from_apk(self):
        """Extract strings directly from APK using strings command"""
        print("🔍 Extracting strings from APK...")
        
        try:
            cmd = ['strings', str(self.apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return result.stdout.split('\n')
            else:
                print(f"❌ String extraction failed: {result.stderr}")
                return []
                
        except Exception as e:
            print(f"❌ Error extracting strings: {e}")
            return []
    
    def search_for_secrets(self, strings_list):
        """Search for potential hardcoded secrets in strings"""
        print("🔍 Searching for hardcoded secrets...")
        
        secret_patterns = {
            'bearer_tokens': [
                r'Bearer\s+[A-Za-z0-9\-_\.]+',
                r'eyJ[A-Za-z0-9\-_\.]+',  # JWT tokens
                r'[A-Za-z0-9]{32,}',  # Long alphanumeric strings
            ],
            'api_keys': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-_]+',
                r'apikey["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-_]+',
                r'secret[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-_]+',
            ],
            'passwords': [
                r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+',
                r'passwd["\']?\s*[:=]\s*["\']?[^"\'\s]+',
                r'pwd["\']?\s*[:=]\s*["\']?[^"\'\s]+',
            ],
            'urls': [
                r'https?://[A-Za-z0-9\-_\.]+/[A-Za-z0-9\-_\./]*',
                r'api\.[A-Za-z0-9\-_\.]+',
            ]
        }
        
        found_secrets = {
            'bearer_tokens': [],
            'api_keys': [],
            'passwords': [],
            'urls': []
        }
        
        for string in strings_list:
            if len(string) < 10:  # Skip short strings
                continue
                
            for category, patterns in secret_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, string, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 10:  # Only keep substantial matches
                            found_secrets[category].append(match)
        
        # Remove duplicates
        for category in found_secrets:
            found_secrets[category] = list(set(found_secrets[category]))
        
        return found_secrets
    
    def analyze_manifest(self, decompiled_dir):
        """Analyze AndroidManifest.xml for API endpoints and permissions"""
        print("📋 Analyzing AndroidManifest.xml...")
        
        manifest_path = Path(decompiled_dir) / "AndroidManifest.xml"
        if not manifest_path.exists():
            print("❌ AndroidManifest.xml not found")
            return {}
        
        try:
            # Parse manifest (this is simplified - real parsing would need aapt)
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract basic info
            manifest_info = {
                'package_name': '',
                'permissions': [],
                'activities': [],
                'services': []
            }
            
            # Simple regex extraction
            package_match = re.search(r'package="([^"]+)"', content)
            if package_match:
                manifest_info['package_name'] = package_match.group(1)
            
            # Extract permissions
            permission_matches = re.findall(r'android:name="([^"]+permission[^"]*)"', content)
            manifest_info['permissions'] = permission_matches
            
            return manifest_info
            
        except Exception as e:
            print(f"❌ Error analyzing manifest: {e}")
            return {}
    
    def search_decompiled_code(self, decompiled_dir):
        """Search decompiled code for API endpoints and secrets"""
        print("🔍 Searching decompiled code for API endpoints...")
        
        api_endpoints = []
        secret_references = []
        
        try:
            # Search through all files in decompiled directory
            for root, dirs, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith(('.smali', '.xml', '.java')):
                        file_path = Path(root) / file
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Search for API endpoints
                            url_matches = re.findall(r'["\']https?://[^"\']+["\']', content)
                            for match in url_matches:
                                clean_url = match.strip('"\'')
                                if 'api' in clean_url.lower():
                                    api_endpoints.append(clean_url)
                            
                            # Search for secret references
                            secret_matches = re.findall(r'["\'][A-Za-z0-9\-_]{32,}["\']', content)
                            for match in secret_matches:
                                clean_secret = match.strip('"\'')
                                if len(clean_secret) > 32:
                                    secret_references.append(clean_secret)
                                    
                        except Exception as e:
                            continue  # Skip files that can't be read
            
            return {
                'api_endpoints': list(set(api_endpoints)),
                'secret_references': list(set(secret_references))
            }
            
        except Exception as e:
            print(f"❌ Error searching decompiled code: {e}")
            return {'api_endpoints': [], 'secret_references': []}
    
    def generate_report(self, secrets, manifest_info, code_analysis):
        """Generate analysis report"""
        print("📊 Generating analysis report...")
        
        report = {
            'apk_info': {
                'file_path': str(self.apk_path),
                'file_size': self.apk_path.stat().st_size,
                'package_name': manifest_info.get('package_name', 'Unknown')
            },
            'extracted_secrets': secrets,
            'manifest_analysis': manifest_info,
            'code_analysis': code_analysis,
            'security_assessment': {
                'hardcoded_secrets_found': len(secrets.get('bearer_tokens', [])) + len(secrets.get('api_keys', [])),
                'api_endpoints_found': len(code_analysis.get('api_endpoints', [])),
                'risk_level': 'HIGH' if secrets.get('bearer_tokens') else 'MEDIUM'
            }
        }
        
        return report

def main():
    """Main analysis function"""
    print("=" * 60)
    print("🔍 APK Security Analysis Tool")
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    print("=" * 60)
    
    # Path to MaynDrive APK
    apk_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/mayndrive_extracted/base.apk"
    output_dir = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/apk_analysis"
    
    if not Path(apk_path).exists():
        print(f"❌ APK file not found: {apk_path}")
        return False
    
    try:
        # Initialize analyzer
        analyzer = APKAnalyzer(apk_path)
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Step 1: Extract strings directly from APK
        print("\n📱 Step 1: Extracting strings from APK...")
        strings_list = analyzer.extract_strings_from_apk()
        if not strings_list:
            print("❌ Failed to extract strings")
            return False
        
        # Step 2: Search for secrets in strings
        print("\n🔍 Step 2: Searching for hardcoded secrets...")
        secrets = analyzer.search_for_secrets(strings_list)
        
        # Step 3: Decompile APK for deeper analysis
        print("\n🔧 Step 3: Decompiling APK...")
        decompiled_dir = Path(output_dir) / "decompiled"
        if analyzer.decompile_apk(decompiled_dir):
            # Analyze manifest
            manifest_info = analyzer.analyze_manifest(decompiled_dir)
            
            # Search decompiled code
            code_analysis = analyzer.search_decompiled_code(decompiled_dir)
        else:
            manifest_info = {}
            code_analysis = {'api_endpoints': [], 'secret_references': []}
        
        # Step 4: Generate report
        print("\n📊 Step 4: Generating analysis report...")
        report = analyzer.generate_report(secrets, manifest_info, code_analysis)
        
        # Save report
        with open(Path(output_dir) / 'apk_analysis_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 60)
        
        print(f"📱 APK: {report['apk_info']['package_name']}")
        print(f"📏 Size: {report['apk_info']['file_size']:,} bytes")
        print(f"🔑 Bearer Tokens Found: {len(secrets.get('bearer_tokens', []))}")
        print(f"🔐 API Keys Found: {len(secrets.get('api_keys', []))}")
        print(f"🌐 API Endpoints Found: {len(code_analysis.get('api_endpoints', []))}")
        print(f"⚠️  Risk Level: {report['security_assessment']['risk_level']}")
        
        if secrets.get('bearer_tokens'):
            print("\n🚨 CRITICAL: Bearer tokens found!")
            for i, token in enumerate(secrets['bearer_tokens'][:3], 1):
                print(f"   {i}. {token[:50]}...")
        
        if code_analysis.get('api_endpoints'):
            print("\n🌐 API Endpoints found:")
            for i, endpoint in enumerate(code_analysis['api_endpoints'][:5], 1):
                print(f"   {i}. {endpoint}")
        
        print(f"\n📁 Results saved to: {output_dir}")
        print(f"📄 Report: {output_dir}/apk_analysis_report.json")
        
        return True
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
