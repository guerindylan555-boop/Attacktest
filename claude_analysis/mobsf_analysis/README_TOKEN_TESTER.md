# MaynDrive Token Tester - User Interface Options

## 🎯 Overview

I've created multiple user-friendly interfaces for testing the extracted tokens from the MaynDrive APK against your test API environment.

## 📁 Available Interfaces

### 1. 🖥️ Desktop GUI (Recommended)
**File**: `token_tester_gui.py`

**Features**:
- User-friendly desktop application
- Easy configuration of test parameters
- Real-time progress tracking
- Detailed results display
- Save results to files

**How to run**:
```bash
cd /home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis
python3 token_tester_gui.py
```

### 2. 🌐 Web Interface
**File**: `web_token_tester.py`

**Features**:
- Modern web-based interface
- Access from any browser
- Real-time updates
- Mobile-friendly design

**How to run**:
```bash
cd /home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis
python3 web_token_tester.py
```
Then open your browser to: `http://localhost:5000`

### 3. 📝 Command Line Scripts
**Files**: 
- `configured_token_tester.py` - Pre-configured version
- `simple_token_tester.py` - Interactive version

**How to run**:
```bash
# Pre-configured version (edit the configuration at the top of the file)
python3 configured_token_tester.py

# Interactive version
python3 simple_token_tester.py
```

## ⚙️ Configuration

### Required Settings:
1. **API Base URL**: Your test API endpoint (e.g., `https://api-test.knotcity.io`)
2. **Test Scooter Serial**: Serial number for testing vehicle operations
3. **Latitude/Longitude**: Test location coordinates

### Example Configuration:
```python
TEST_API_BASE_URL = "https://your-test-api.com"
TEST_SCOOTER_SERIAL = "TEST123"
TEST_LATITUDE = 40.7128
TEST_LONGITUDE = -74.0060
```

## 🧪 What the Tester Does

1. **Loads 1,141+ tokens** extracted from the MaynDrive APK
2. **Tests each token** against multiple API endpoints:
   - User profile access (`/api/application/users`)
   - Wallet information (`/api/application/users/wallet`)
   - Vehicle unlock operations (`/api/application/vehicles/unlock`)
   - Admin operations (`/api/application/vehicles/unlock/admin`)
3. **Reports results** showing which tokens provide unauthorized access
4. **Generates detailed reports** in JSON and Markdown format

## 📊 Expected Results

When you run this against your **real test API**, you should see:
- ✅ **SUCCESS** messages for valid tokens
- 🚨 **CRITICAL** messages for vehicle operations
- 📊 **Summary report** showing vulnerability confirmation

## 🚨 Security Implications

If valid tokens are found, this indicates:
- **Hardcoded secrets vulnerability** in the APK
- **Unauthorized API access** possible
- **Potential for scooter manipulation**
- **User data exposure risk**

## 📁 Output Files

The tester generates:
- **JSON results** with detailed test data
- **Markdown reports** with vulnerability assessment
- **Configurable test parameters**

## ⚠️ Important Notes

- **Only test against your own test environment**
- **Do not use against production systems**
- **This is for security research purposes only**
- **Make sure you have permission to test the API**

## 🛠️ Troubleshooting

### If you get "Connection error":
- Check that your test API URL is correct
- Ensure the API is running and accessible
- Verify network connectivity

### If no tokens are found:
- Check that the APK analysis was completed successfully
- Verify the `apk_analysis_report.json` file exists
- Ensure the file contains extracted tokens

### If GUI doesn't start:
- Make sure tkinter is installed: `sudo apt install python3-tk`
- Try the web interface instead

## 🎯 Quick Start

1. **Choose your interface** (Desktop GUI recommended)
2. **Configure your test API URL** and parameters
3. **Run the tester** and wait for results
4. **Review the results** for vulnerability confirmation
5. **Save the results** for your security report

## 📞 Support

If you encounter any issues:
1. Check the error messages in the interface
2. Verify your configuration settings
3. Ensure all dependencies are installed
4. Check that the APK analysis was completed successfully

---

**Remember**: This tool is designed to help you test the security of your own application in a controlled test environment. Always follow responsible disclosure practices and only test systems you own or have explicit permission to test.
