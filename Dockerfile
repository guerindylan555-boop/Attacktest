# MaynDrive Security Exploitation Demo - Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY exploit_demo_webapp.py .
COPY mayn_drive_api.py .
COPY test_security_vulnerabilities.py .
COPY test_app_loads.py .
COPY templates/ templates/

# Copy documentation
COPY START_HERE.md .
COPY SECURITY_ANALYSIS.md .
COPY EXPLOIT_DEMO_README.md .
COPY EXPLOIT_SUMMARY.md .

# Test that the app loads correctly
RUN python test_app_loads.py

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=exploit_demo_webapp.py
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/', timeout=5)" || exit 1

# Run the application with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "--log-level", "debug", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "exploit_demo_webapp:app"]

