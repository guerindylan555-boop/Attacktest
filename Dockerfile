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
COPY templates/ templates/

# Copy documentation
COPY START_HERE.md .
COPY SECURITY_ANALYSIS.md .
COPY EXPLOIT_DEMO_README.md .
COPY EXPLOIT_SUMMARY.md .

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=exploit_demo_webapp.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "exploit_demo_webapp.py"]

