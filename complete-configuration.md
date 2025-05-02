# Configuration for AI-Driven Security Solution

## Directory Structure Overview
Server VM
```
~/security-solution/
├── config/
│   ├── server_config.json
│   ├── log_sources.json
│   └── dashboard_config.json
├── data/
│   ├── raw_logs/
│   └── processed_logs/
├── logs/
├── models/
├── results/
├── dashboard/
└── scripts/
    ├── server_service.py
    ├── dashboard_app.py
    ├── risk_scoring.py
    ├── message_queue.py
    ├── anomaly_detection.py
    ├── hyperparameter_tuning.py
    ├── log_analysis.py
    ├── test_environment.py
    ├── real-log-collector.py
    ├── threat_classification.py
    ├── compliance_checker.py
    └── integrations/
        └── ml_elk_integration.py
```

Worker VMs
```
~/security-solution-worker/
├── config/
│   └── worker_config.json
├── data/
├── logs/
└── scripts/
    ├── log_collector_service.py (Worker VM 1)
    ├── vulnerability_scanner_service.py (Worker VM 2)
    └── compliance_checker.py (Worker VM 2)
```

## Architecture Overview

```
┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│   SERVER VM    │◄────►│   WORKER VM 1  │      │   WORKER VM 2  │
│                │      │                │      │                │
│ - ML Pipeline  │      │ - Log          │      │ - Vulnerability│
│ - Model        │      │   Collection   │      │   Scanning     │
│   Training     │      │ - Network      │      │ - Compliance   │
│ - Dashboard    │      │   Monitoring   │      │   Checking     │
│ - Central Log  │      │ - Initial      │      │ - Data         │
│   Analysis     │      │   Preprocessing│      │   Collection   │
└────────────────┘      └────────────────┘      └────────────────┘
                                                     
                              │                        │
                              └────────────────────────┘
                                          │
                                          ▼
                                ┌──────────────────┐
                                │  Data Exchange   │
                                │  Message Queue   │
                                └──────────────────┘
```

## 1. Base Installation (All VMs)

Run these commands on all three VMs (server and workers) to set up the base environment:

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Install Python and required tools
sudo apt install python3 python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools python3-venv -y

# Install ZeroMQ for message passing
sudo apt install libzmq3-dev -y

# Install network tools
sudo apt install nmap tcpdump wireshark tshark -y

python3 -m venv ~/myenv
source ~/myenv/bin/activate
pip install paramiko requests python-dateutil pytz
```

## 2. Server VM Setup

### 2.1 Create Project Structure

```bash
# Create project directory
mkdir -p ~/security-solution
cd ~/security-solution

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Create project subdirectories
mkdir -p {config,data/{raw_logs,processed_logs},logs,models,results,dashboard,scripts/integrations}
```

### 2.2 Install Required Libraries

```bash
# Upgrade pip
pip install --upgrade pip

# Install core ML and data analysis libraries
pip install pandas numpy scikit-learn matplotlib seaborn

# Install libraries for distributed processing
pip install pyzmq grpcio grpcio-tools protobuf

# Install dashboard and visualization libraries
pip install flask dash plotly dash-bootstrap-components

# Install additional utilities
pip install requests tqdm ipython jupyter

# Save requirements
pip freeze > requirements.txt
```

### 2.3 Configure Server Components

Create configuration files:

```bash
# Create server configuration file
sudo nano config/server_config.json
```

Server configuration should include:
- Server address (0.0.0.0) and port (5555)
- Dashboard port (8050)
- Worker nodes (worker1: 192.168.51.100, worker2: 192.168.51.169)
- Model configuration (contamination: 0.05, algorithms)

```bash
# Create log sources configuration file
sudo nano config/log_sources.json
```

Log sources configuration should include:
- Local file sources (/var/log/syslog, /var/log/auth.log)
- Syslog server configuration (UDP port 514)
- SSH remote log collection settings
- Collection intervals and retention policies

```bash
# Create dashboard configuration file
sudo nano config/dashboard_config.json
```

Dashboard configuration should include:
- Server host and port settings
- Data source paths
- Refresh intervals for different data types
- Display settings for visualizations

```bash
# Create risk scoring configuration file
sudo nano config/risk_scoring_config.json
```

Risk scoring configuration should include:
- Risk weights for different factors (vulnerability, anomaly, compliance)
- Threshold values for high/medium risk classification
- Asset criticality settings
- Threat intelligence integration configuration

```bash
# Create asset criticality file
sudo nano config/asset_criticality.json
```

Asset criticality file should include:
- Critical asset information (IPs and criticality scores)
- Default criticality values for different device types

### 2.4 Copy Python Scripts to Server

Copy Python scripts to the server's scripts directory:

```bash
# Copy main server components
sudo nano scripts/server_service.py
sudo nano scripts/dashboard_app.py
sudo nano scripts/risk_scoring.py
sudo nano scripts/message_queue.py

# Copy existing Python scripts
sudo nano scripts/anomaly_detection.py
sudo nano scripts/hyperparameter_tuning.py
sudo nano scripts/log_analysis.py
sudo nano scripts/test_environment.py
sudo nano scripts/real-log-collector.py
sudo nano scripts/threat_classification.py
sudo nano scripts/compliance_checker.py

# Create integration directory and scripts
mkdir -p scripts/integrations
sudo nano scripts/integrations/ml_elk_integration.py

# Set execute permissions
sudo chmod +x scripts/*.py
sudo chmod +x scripts/integrations/*.py
```

### 2.5 Set Up Server Service

```bash
# Create systemd service for the server
sudo tee /etc/systemd/system/security-solution-server.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Server
After=network.target

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution
ExecStart=/home/kali/security-solution/venv/bin/python /home/kali/security-solution/scripts/server_service.py --config config/server_config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the message queue
sudo tee /etc/systemd/system/security-solution-messagequeue.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Message Queue
After=network.target
Before=security-solution-server.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution
ExecStart=/home/kali/security-solution/venv/bin/python /home/kali/security-solution/scripts/message_queue.py --server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the dashboard
sudo tee /etc/systemd/system/security-solution-dashboard.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Dashboard
After=network.target security-solution-server.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution
ExecStart=/home/kali/security-solution/venv/bin/python /home/kali/security-solution/scripts/dashboard_app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable security-solution-messagequeue.service
sudo systemctl enable security-solution-server.service
sudo systemctl enable security-solution-dashboard.service
```

## 3. Worker VM 1 Setup (Log Collection)

### 3.1 Create Project Structure

```bash
# Create project directory
mkdir -p ~/security-solution-worker
cd ~/security-solution-worker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Create project subdirectories
mkdir -p {config,data,logs,scripts}
```

### 3.2 Install Required Libraries

```bash
# Upgrade pip
pip install --upgrade pip

# Install core libraries (lighter version than server)
pip install pandas numpy scikit-learn

# Install libraries for distributed processing
pip install pyzmq grpcio grpcio-tools protobuf

# Install log processing libraries
pip install python-whois dnspython paramiko requests python-dateutil pytz

# Save requirements
pip freeze > requirements.txt
```

### 3.3 Configure Worker Components

```bash
# Create worker configuration file
sudo nano config/worker_config.json
```

Worker configuration should include:
- Worker ID (worker1)
- Server connection information (192.168.51.160, port 5555)
- Log collection sources and intervals
- Network monitoring settings

```bash
# Copy log collection worker scripts
sudo nano scripts/log_collector_service.py
sudo nano scripts/real-log-collector.py
sudo nano scripts/message_queue.py

# Set execute permissions
sudo chmod +x scripts/*.py
```

### 3.4 Set Up Worker Service

```bash
# Create systemd service for the worker
sudo tee /etc/systemd/system/security-solution-worker.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Worker (Log Collector)
After=network.target

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution-worker
ExecStart=/home/kali/security-solution-worker/venv/bin/python /home/kali/security-solution-worker/scripts/log_collector_service.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the message queue client
sudo tee /etc/systemd/system/security-solution-worker-mq.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Worker Message Queue Client
After=network.target
After=security-solution-worker.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution-worker
ExecStart=/home/kali/security-solution-worker/venv/bin/python /home/kali/security-solution-worker/scripts/message_queue.py --worker --worker-id worker1 --worker-type log_collection --host 192.168.51.160
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable security-solution-worker.service
sudo systemctl enable security-solution-worker-mq.service
```

## 4. Worker VM 2 Setup (Vulnerability Scanner)

### 4.1 Create Project Structure

```bash
# Create project directory
mkdir -p ~/security-solution-worker
cd ~/security-solution-worker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Create project subdirectories
mkdir -p {config,data,logs,scripts}
```

### 4.2 Install Required Libraries

```bash
# Upgrade pip
pip install --upgrade pip

# Install core libraries (lighter version than server)
pip install pandas numpy requests

# Install libraries for distributed processing
pip install pyzmq grpcio grpcio-tools protobuf

# Install vulnerability scanning libraries
pip install python-nmap

# Install OpenVAS
sudo apt install openvas -y
sudo gvm-setup
sudo gvm-start

# Install compliance checking tools
sudo apt install lynis -y
db43ab86-a9d9-46ae-b334-6dbcd5b020e6
# Save requirements
pip freeze > requirements.txt
```

### 4.3 Configure Worker Components

```bash
# Create worker configuration file
sudo nano config/worker_config.json
```

Worker configuration should include:
- Worker ID (worker2)
- Server connection information (192.168.51.160, port 5555)
- Vulnerability scanning targets and intervals
- OpenVAS connection settings
- Compliance frameworks and check intervals

```bash
# Copy vulnerability scanner worker scripts
sudo nano scripts/vulnerability_scanner_service.py
sudo nano scripts/compliance_checker.py
sudo nano scripts/message_queue.py

# Set execute permissions
chmod +x scripts/*.py
```

### 4.4 Set Up Worker Service

```bash
# Create systemd service for the worker
sudo tee /etc/systemd/system/security-solution-worker.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Worker (Vulnerability Scanner)
After=network.target gvm.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution-worker
ExecStart=/home/kali/security-solution-worker/venv/bin/python /home/kali/security-solution-worker/scripts/vulnerability_scanner_service.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the compliance checker
sudo tee /etc/systemd/system/security-solution-compliance.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Compliance Checker
After=network.target security-solution-worker.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution-worker
ExecStart=/home/kali/security-solution-worker/venv/bin/python /home/kali/security-solution-worker/scripts/compliance_checker.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the message queue client
sudo tee /etc/systemd/system/security-solution-worker-mq.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Worker Message Queue Client
After=network.target
After=security-solution-worker.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution-worker
ExecStart=/home/kali/security-solution-worker/venv/bin/python /home/kali/security-solution-worker/scripts/message_queue.py --worker --worker-id worker2 --worker-type vulnerability_scanner --host 192.168.51.160
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable security-solution-worker.service
sudo systemctl enable security-solution-compliance.service
sudo systemctl enable security-solution-worker-mq.service
```

## 5. Startup and Testing

### 5.1 Starting the System

Start the services on all VMs:

```bash
# On Server VM
sudo systemctl start security-solution-messagequeue.service
sudo systemctl start security-solution-server.service
sudo systemctl start security-solution-dashboard.service

# On Worker VM 1
sudo systemctl start security-solution-worker.service
sudo systemctl start security-solution-worker-mq.service

# On Worker VM 2
sudo systemctl start security-solution-worker.service
sudo systemctl start security-solution-compliance.service
sudo systemctl start security-solution-worker-mq.service
```

### 5.2 Testing the System

Test that the environment is correctly set up:

```bash
# On Server VM
cd ~/security-solution
source venv/bin/activate
sudo python scripts/test_environment.py
```

Verify worker connections:

```bash
# On Server VM
cd ~/security-solution
source venv/bin/activate
python scripts/message_queue.py --admin --status
```

### 5.3 Accessing the Dashboard

Access the security dashboard through a web browser:

```
http://192.168.51.160:8050
```

## 6. Maintenance and Management

### 6.1 Log Rotation

Configure log rotation to prevent disk space issues:

```bash
sudo nano /etc/logrotate.d/security-solution

# Add the following content:
/home/kali/security-solution/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 kali kali
}
```

### 6.2 Vulnerability Database Updates

Update vulnerability databases periodically:

```bash
# On Worker VM 2
sudo greenbone-nvt-sync
sudo greenbone-feed-sync --type CERT
sudo greenbone-feed-sync --type SCAP
```

### 6.3 Backup Configuration

Create a backup script for configuration files:

```bash
# On Server VM
sudo nano ~/security-solution/scripts/backup_config.sh
```

Add backup script content:

```bash
#!/bin/bash
BACKUP_DIR=~/security-backups
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
cp -r ~/security-solution/config $BACKUP_DIR/config-$TIMESTAMP
echo "Configuration backed up to $BACKUP_DIR/config-$TIMESTAMP"
```

Set permissions and create a cron job:

```bash
chmod +x ~/security-solution/scripts/backup_config.sh
crontab -e

# Add the following line to run backup daily at 1 AM
0 1 * * * ~/security-solution/scripts/backup_config.sh
```

## 7. Troubleshooting

### 7.1 Common Issues and Solutions

#### Server Connection Issues

```bash
# Check if server is running
sudo systemctl status security-solution-server.service

# Check network connectivity
ping 192.168.51.160
nc -zv 192.168.51.160 5555
```

#### Worker Connection Issues

```bash
# Check worker service status
sudo systemctl status security-solution-worker.service
sudo systemctl status security-solution-worker-mq.service

# View logs for connection issues
sudo journalctl -u security-solution-worker-mq.service -f
```

#### Log Collection Issues

```bash
# Check log file permissions
ls -la /var/log/auth.log
sudo chmod 644 /var/log/auth.log

# Test log collection manually
python scripts/real-log-collector.py --collect --time 60
```

#### Dashboard Issues

```bash
# Check dashboard service
sudo systemctl status security-solution-dashboard.service

# Check for port conflicts
netstat -tuln | grep 8050
```

### 7.2 Monitoring System Logs

```bash
# View server logs
tail -f ~/security-solution/logs/server_service.log

# View worker logs
tail -f ~/security-solution-worker/logs/worker.log

# View system service logs
sudo journalctl -u security-solution-server -f
```

### 7.3 Resetting and Restarting

```bash
# Restart all services
sudo systemctl restart security-solution-messagequeue.service
sudo systemctl restart security-solution-server.service
sudo systemctl restart security-solution-dashboard.service

# Clear processed data (if needed)
rm -rf ~/security-solution/data/processed_logs/*
rm -rf ~/security-solution/results/*
```

### 7.4 Version Control (Optional)

If using version control for your implementation:

```bash
# Initialize git repository
cd ~/security-solution
git init

# Create gitignore file
echo "venv/" > .gitignore
echo "*.log" >> .gitignore
echo "data/" >> .gitignore
echo "__pycache__/" >> .gitignore

# Add and commit files
git add .
git commit -m "Initial setup"
```

## 8. Advanced Configuration

### 8.1 Enabling ELK Stack Integration

```bash
# Install ELK dependencies
pip install elasticsearch python-logstash

# Configure ELK integration
sudo nano config/elk_config.json
```

### 8.2 Enhancing Threat Intelligence

```bash
# Create custom threat intelligence sources
sudo nano config/threat_intelligence.json
```

### 8.3 Email Alerts Configuration

```bash
# Configure email alerts
sudo nano config/notification_config.json

# Test email alerts
python scripts/test_notifications.py
```