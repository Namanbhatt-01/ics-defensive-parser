# Use a lightweight official Python runtime base image
FROM python:3.10-alpine

# Set system environment settings
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Establish isolated workspace directory
WORKDIR /app

# Copy dependency specifications (Standard Library only, but represents standard practices)
COPY requirements.txt ./

# Install requirements if any are declared
RUN pip install --no-cache-dir -r requirements.txt

# Copy all core files, rules, and mock database entries
COPY . .

# Run the auditor main loop as the default container execution command
CMD ["python", "main.py"]
