# 🚨 MaynDrive Security Exploitation Demo

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0+-green.svg)](https://flask.palletsprojects.com/)

**Interactive web application demonstrating real attack vectors against the MaynDrive scooter-sharing API.**

⚠️ **WARNING: FOR AUTHORIZED SECURITY TESTING ONLY!**

---

## 🎯 What This Tool Does

This tool demonstrates **5 critical security vulnerabilities** that could allow attackers to gain unauthorized admin access to a vehicle fleet management system:

1. **Scope Escalation** (CRITICAL) - Client-controlled role assignment
2. **JWT Token Manipulation** (CRITICAL) - Weak token signature validation
3. **Admin Endpoint Access** (HIGH) - Missing authorization checks
4. **Mass Vehicle Unlock** (CRITICAL) - No rate limiting on admin operations
5. **Device Spoofing** (MEDIUM) - Weak device validation

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/guerindylan555-boop/Attacktest.git
cd Attacktest

# Run with Docker Compose
docker-compose up -d

# Access the application
open http://localhost:5000
```

### Option 2: Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python exploit_demo_webapp.py

# Access the application
open http://localhost:5000
```

### Option 3: One-Click (Windows)

```cmd
# Double-click to run
launch_exploit_demo.bat
```

---

## 📋 Prerequisites

- Python 3.7+ (for local installation)
- Docker & Docker Compose (for containerized deployment)
- Valid test account credentials
- **Written authorization** to test the target system

---

## 🎭 Features

### Interactive Web Interface
- 🎨 Modern, dark-themed UI
- 🎯 One-click exploit execution
- 📊 Real-time results display
- 📋 Detailed JSON responses
- 📜 Exploitation log viewer

### 5 Real Attack Scenarios
Each exploit demonstrates a different vulnerability:

#### 1. Scope Escalation Attack
Tests if users can request admin privileges during login.

```python
# The vulnerability
api.login(email, password, scope="admin")  # ⚠️ Client controls role!
```

#### 2. JWT Token Manipulation
Attempts to tamper with authentication tokens to forge admin access.

```python
# Decode, modify, re-sign
payload = jwt.decode(token, verify_signature=False)
payload['scope'] = 'admin'
fake_token = jwt.encode(payload, 'weak_key')
```

#### 3. Admin Endpoint Enumeration
Tests if admin endpoints check actual user roles.

```python
# Login as user, access admin endpoints
api.login(email, password, scope="user")
api.unlock_vehicle_admin(...)  # Should fail!
```

#### 4. Mass Vehicle Unlock
Demonstrates fleet-wide compromise without rate limiting.

```python
# Unlock entire fleet
for vehicle in fleet:
    api.unlock_vehicle_admin(vehicle, force=True)
```

#### 5. Device Spoofing
Tests if arbitrary device information is accepted.

```python
# Use fake device ID
device = {"uuid": "00000000-0000-0000-0000-000000000000"}
```

---

## 📊 Understanding Results

### 🚨 VULNERABLE
- System has this security flaw
- Attacker could exploit this
- **ACTION REQUIRED**: Implement fixes

### ✅ SECURE
- System is protected against this attack
- Proper authorization is in place
- No action needed

---

## 🐳 Dockploy Deployment

### Deploy to Dockploy

1. **Create new application** in Dockploy
2. **Connect GitHub repository**: `https://github.com/guerindylan555-boop/Attacktest`
3. **Configure deployment**:
   - Build Type: `Dockerfile`
   - Port: `5000`
   - Environment: `Production`
4. **Deploy and access** your instance

### Environment Variables (Optional)

```env
FLASK_ENV=production
PYTHONUNBUFFERED=1
```

---

## 📖 Documentation

- **[START_HERE.md](START_HERE.md)** - Quick start guide
- **[SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md)** - Detailed vulnerability analysis
- **[EXPLOIT_DEMO_README.md](EXPLOIT_DEMO_README.md)** - Complete usage guide
- **[EXPLOIT_SUMMARY.md](EXPLOIT_SUMMARY.md)** - Overview of exploits

---

## 🔒 Security & Legal

### ⚠️ Important Warnings

- ✅ **Only test systems you own** or have written permission for
- ✅ Use **test accounts** in **test environments**
- ✅ Follow **responsible disclosure** practices
- ❌ **Never test production** without authorization
- ❌ **Never share credentials** or tokens

### Legal Disclaimer

This tool is for **educational and authorized security testing only**. Unauthorized security testing may be illegal. By using this tool, you agree:

- You have explicit written permission to test the target system
- You will only use this on authorized test environments
- You understand unauthorized testing may result in criminal charges
- You accept full responsibility for your actions
- The authors are not liable for misuse

---

## 🛠️ Troubleshooting

### "Login failed"
- Verify credentials are correct
- Check if account is active
- Try logging in through the actual app first

### "Connection refused"
- Ensure the webapp is running
- Check if port 5000 is available
- Verify Docker container is up (if using Docker)

### "ModuleNotFoundError"
- Install dependencies: `pip install -r requirements.txt`
- Use a virtual environment
- Check Python version (3.7+ required)

---

## 📈 Use Cases

### For Security Teams
- Demonstrate vulnerabilities to stakeholders
- Validate security controls
- Test authentication/authorization
- Generate security reports

### For Developers
- Understand common attack vectors
- Learn secure coding practices
- Test API security before deployment
- Verify fixes for vulnerabilities

### For Penetration Testers
- Automated vulnerability testing
- Proof-of-concept exploits
- Security assessment reporting
- Client demonstrations

---

## 🤝 Contributing

Found a new vulnerability? Want to add more exploits?

1. Fork the repository
2. Create a feature branch
3. Add your exploit with documentation
4. Submit a pull request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🔗 Related Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [NIST RBAC Guidelines](https://csrc.nist.gov/projects/role-based-access-control)

---

## 📞 Support

- **Documentation**: See docs folder
- **Issues**: [GitHub Issues](https://github.com/guerindylan555-boop/Attacktest/issues)
- **Security**: Report vulnerabilities responsibly

---

## ⭐ Star This Repository

If this tool helped you secure your application, please star the repository!

---

**🔒 Remember: With great power comes great responsibility. Use these tools ethically!**

---

*Last Updated: October 2, 2025*  
*Version: 1.0.0*
