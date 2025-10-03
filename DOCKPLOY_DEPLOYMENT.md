# 🚀 Dockploy Deployment Guide

## Quick Deployment to Dockploy

Your MaynDrive Security Exploitation Demo is now ready for deployment on Dockploy!

**Repository:** https://github.com/guerindylan555-boop/Attacktest

---

## 📋 Prerequisites

1. Dockploy account with admin access
2. GitHub repository connected (done ✅)
3. Docker support enabled on your Dockploy server

---

## 🚀 Deployment Steps

### Step 1: Create New Application

1. Log into your Dockploy dashboard
2. Click **"Create New Application"**
3. Select **"GitHub Repository"**

### Step 2: Connect Repository

1. **Repository URL:** `https://github.com/guerindylan555-boop/Attacktest`
2. **Branch:** `main`
3. **Auto-deploy:** Enable (optional, for automatic deployments on push)

### Step 3: Configure Build Settings

```yaml
Build Method: Dockerfile
Dockerfile Path: ./Dockerfile
Build Context: .
Port Mapping: 5000:5000
```

### Step 4: Environment Variables (Optional)

Add these environment variables in Dockploy:

```env
FLASK_ENV=production
PYTHONUNBUFFERED=1
```

### Step 5: Deploy

1. Click **"Deploy Application"**
2. Wait for build to complete (~2-3 minutes)
3. Application will be available at your Dockploy URL

---

## 🌐 Accessing Your Application

After deployment, your application will be available at:

```
https://your-dockploy-domain.com/attacktest
```

Or with custom domain:
```
https://security-demo.yourdomain.com
```

---

## 🔧 Configuration Options

### Port Mapping

The application runs on port **5000** inside the container.

Dockploy will automatically map it to your public URL.

### Volume Mounting (Optional)

To persist test reports across deployments:

```yaml
volumes:
  - /path/on/host:/app/security_test_report.json
```

### Resource Limits (Recommended)

```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
    reservations:
      cpus: '0.25'
      memory: 256M
```

---

## 🐳 Using Docker Compose (Alternative)

If Dockploy supports docker-compose:

```bash
# Your docker-compose.yml is already included!
# Dockploy will automatically detect and use it
```

The included `docker-compose.yml` provides:
- Automatic container restart
- Volume mounting for reports
- Proper labeling for Dockploy
- Port mapping

---

## 🔐 Security Recommendations

### 1. Authentication

Add basic authentication for production:

```python
# In exploit_demo_webapp.py
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Add your authentication logic
    return username == "admin" and password == "your_secure_password"

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')
```

### 2. IP Whitelisting

In Dockploy, configure IP restrictions:
- Allow only your company IPs
- Block public access
- Use VPN for remote access

### 3. Environment Variables

Store sensitive data in Dockploy environment variables:
- API endpoints
- Test account credentials (if needed)
- Secret keys

---

## 📊 Monitoring

### Health Check Endpoint

Add this to `exploit_demo_webapp.py`:

```python
@app.route('/health')
def health():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}
```

Configure in Dockploy:
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### Logs

View logs in Dockploy dashboard:
```bash
# Or via docker
docker logs mayndrive-security-demo -f
```

---

## 🔄 Updating Your Application

### Manual Update

1. Push changes to GitHub
2. In Dockploy, click **"Redeploy"**
3. Wait for build to complete

### Automatic Updates

Enable auto-deploy in Dockploy:
- Automatically rebuilds on git push
- Zero-downtime deployments
- Rollback capability

---

## 🐛 Troubleshooting

### Build Fails

**Error:** `requirements.txt not found`

**Solution:**
```bash
# Ensure requirements.txt is in repository root
git add requirements.txt
git commit -m "Add requirements.txt"
git push
```

### Container Won't Start

**Error:** `Port 5000 already in use`

**Solution:** Check Dockploy port mapping configuration

### Application Not Accessible

**Error:** `502 Bad Gateway`

**Solution:**
1. Check if container is running
2. Verify port mapping (5000:5000)
3. Check container logs for errors

### Slow Performance

**Solution:**
1. Increase memory allocation in Dockploy
2. Use production WSGI server (see below)

---

## ⚡ Production Optimizations

### Use Gunicorn (Recommended)

Update `Dockerfile`:

```dockerfile
# Add gunicorn to requirements.txt
RUN pip install gunicorn

# Change CMD
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "exploit_demo_webapp:app"]
```

Update `requirements.txt`:
```
gunicorn==21.2.0
```

### Enable HTTPS

In Dockploy:
1. Add custom domain
2. Enable SSL certificate (Let's Encrypt)
3. Force HTTPS redirect

---

## 📈 Scaling

### Horizontal Scaling

Dockploy supports multiple instances:

```yaml
deploy:
  replicas: 3
  update_config:
    parallelism: 1
    delay: 10s
```

### Load Balancing

Dockploy automatically load-balances between replicas.

---

## 🔒 Advanced Security

### 1. Network Isolation

```yaml
networks:
  - security-demo-network

networks:
  security-demo-network:
    driver: bridge
    internal: true
```

### 2. Read-Only Filesystem

```yaml
security_opt:
  - no-new-privileges:true
read_only: true
```

### 3. User Restrictions

```dockerfile
# Add to Dockerfile
RUN useradd -m -u 1000 appuser
USER appuser
```

---

## 📋 Post-Deployment Checklist

- [ ] Application is accessible at public URL
- [ ] All 5 exploits load correctly
- [ ] Can enter credentials and run tests
- [ ] Results display properly
- [ ] Logs are being captured
- [ ] Health check passes
- [ ] SSL certificate is valid (if using HTTPS)
- [ ] Authentication is enabled (if required)
- [ ] Backups are configured
- [ ] Monitoring is set up

---

## 🎯 Testing Your Deployment

### 1. Basic Functionality

```bash
# Health check
curl https://your-domain.com/health

# Main page
curl https://your-domain.com/
```

### 2. API Endpoints

```bash
# Test scope escalation endpoint
curl -X POST https://your-domain.com/api/exploit/scope-escalation \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'
```

### 3. Load Testing (Optional)

```bash
# Using Apache Bench
ab -n 100 -c 10 https://your-domain.com/

# Using hey
hey -n 100 -c 10 https://your-domain.com/
```

---

## 🆘 Support

### Dockploy Issues
- Check Dockploy documentation
- Contact Dockploy support
- Review deployment logs

### Application Issues
- Check GitHub Issues: https://github.com/guerindylan555-boop/Attacktest/issues
- Review application logs
- Verify environment configuration

---

## 🎉 Success!

Your MaynDrive Security Exploitation Demo is now deployed!

**Next Steps:**
1. Share the URL with your security team
2. Run initial security tests
3. Document findings
4. Implement fixes based on results

---

## 📚 Additional Resources

- **GitHub Repository:** https://github.com/guerindylan555-boop/Attacktest
- **Dockploy Docs:** https://docs.dockploy.io
- **Docker Best Practices:** https://docs.docker.com/develop/dev-best-practices/
- **Flask Deployment:** https://flask.palletsprojects.com/en/latest/deploying/

---

**Deployed Successfully! 🚀**

*Last Updated: October 2, 2025*





