#!/bin/bash
# Initialization script for security solution workers

# Set up environment
echo "Setting up security solution worker environment..."

# Check worker type
if [ "$1" == "log_collector" ]; then
  echo "Initializing as log collector (Worker VM 1)..."
  
  # Create required directories
  mkdir -p ~/security-solution-worker/data
  mkdir -p ~/security-solution-worker/logs
  
  # Configure Filebeat and Auditbeat if installed
  if command -v filebeat &> /dev/null; then
    echo "Configuring Filebeat..."
    sudo systemctl enable filebeat
    sudo systemctl start filebeat
  fi
  
  if command -v auditbeat &> /dev/null; then
    echo "Configuring Auditbeat..."
    sudo systemctl enable auditbeat  
    sudo systemctl start auditbeat
  fi
  
elif [ "$1" == "vulnerability_scanner" ]; then
  echo "Initializing as vulnerability scanner (Worker VM 2)..."
  
  # Create required directories
  mkdir -p ~/security-solution-worker/data
  mkdir -p ~/security-solution-worker/logs
  
  # Install additional tools if needed
  if ! command -v nmap &> /dev/null; then
    echo "Installing nmap..."
    sudo apt install -y nmap
  fi
  
  # Configure Metricbeat and Packetbeat if installed
  if command -v metricbeat &> /dev/null; then
    echo "Configuring Metricbeat..."
    sudo systemctl enable metricbeat
    sudo systemctl start metricbeat
  fi
  
  if command -v packetbeat &> /dev/null; then
    echo "Configuring Packetbeat..."
    sudo systemctl enable packetbeat
    sudo systemctl start packetbeat
  fi
  
else
  echo "Unknown worker type. Specify 'log_collector' or 'vulnerability_scanner'"
  exit 1
fi

echo "Worker initialization complete!"