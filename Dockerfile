# Use a lightweight official Python runtime base image
FROM python:3.10-alpine

# Set system environment settings
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Establish isolated workspace directory inside the container
WORKDIR /app

# Copy dependency specifications (Standard Library only, but follows standard DevOps practice)
COPY requirements.txt ./

# Install requirements if any are declared
RUN pip install --no-cache-dir -r requirements.txt

# Copy the engine package and data directory (required at runtime)
COPY ics_defensive_parser/ ./ics_defensive_parser/
COPY data/ ./data/

# Run the auditor main loop as the default container execution command
CMD ["python3", "ics_defensive_parser/main.py"]
