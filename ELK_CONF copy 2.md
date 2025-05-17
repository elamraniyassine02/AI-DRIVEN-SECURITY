# AI-Driven Security Solution for Automated Vulnerability Assessment & Risk Evaluation

This comprehensive configuration guide provides detailed installation and configuration instructions for setting up the AI-Driven Security Solution across three Ubuntu 22.04.5 virtual machines running on VMware Workstation Pro 16.

## Environment Overview

### Virtual Machine Configuration
- **Server VM (192.168.100.66)**: Central ML processing, ELK stack, analysis pipeline
- **Worker VM 1 (192.168.100.67)**: Log collection, network monitoring, data preprocessing
- **Worker VM 2 (192.168.100.68)**: Vulnerability scanning, compliance checking

### System Requirements
- **CPU**: Minimum 2 cores (4 recommended for Server VM)
- **RAM**: Minimum 4GB (8GB recommended for Server VM)
- **Disk**: Minimum 50GB (100GB recommended for Server VM)
- **Network**: All VMs must have network connectivity to each other

## Architecture Overview

```
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│     SERVER VM       │◄────►│     WORKER VM 1     │      │     WORKER VM 2     │
│  192.168.100.66     │      │   192.168.100.67    │      │   192.168.100.68    │
├─────────────────────┤      ├─────────────────────┤      ├─────────────────────┤
│ - ELK Stack         │      │ - Log Collection    │      │ - Vulnerability     │
│ - ML Pipeline       │      │   (Filebeat)        │      │   Scanning (Nmap)   │
│ - Anomaly Detection │      │ - System Monitoring │      │ - Compliance        │
│ - Risk Scoring      │      │   (Auditbeat)       │      │   Checking (Lynis)  │
│ - Threat Intel      │      │ - Network Traffic   │      │ - Data Collection   │
│ - Kibana Dashboard  │      │   (Packetbeat)      │      │   (Metricbeat)      │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
            ▲                          │                          │
            │                          └──────────────────────────┘
            │                                      │
            │                                      ▼
      ┌─────────────────────────────────────────────────────────────┐
      │                     Data Exchange Layer                      │
      │         (Message Queue & ELK Stack Integration)              │
      └─────────────────────────────────────────────────────────────┘
```

## Directory Structure

### Server VM
```
~/security-solution/
├── config/
│   ├── server_config.json           # Main server configuration
│   ├── log_sources.json             # Log source definitions
│   ├── elk_config.json              # ELK integration settings
│   ├── risk_scoring_config.json     # Risk scoring parameters
│   ├── asset_criticality.json       # Asset importance definitions
│   └── threat_intelligence.json     # Threat intel configuration
├── data/
│   ├── raw_logs/                    # Collected raw logs
│   └── processed_logs/              # Processed and enriched logs
├── logs/                            # Application logs
├── models/                          # Trained ML models
├── results/                         # Analysis results
└── scripts/
    ├── server_service.py            # Main server service
    ├── risk_scoring.py              # Risk scoring engine
    ├── message_queue.py             # Message queue service
    ├── anomaly_detection.py         # ML-based anomaly detection
    ├── hyperparameter_tuning.py     # ML model optimization
    ├── log_analysis.py              # Log processing and analysis
    ├── test_environment.py          # Environment testing utility
    ├── threat_classification.py     # Threat classification service
    ├── compliance_checker.py        # Compliance scanning service
    ├── backup_config.sh             # Config backup utility
    └── integrations/
        ├── ml_elk_integration.py    # ML-ELK data connector
        └── threat_intel_integration.py # External threat intel
```

### Worker VMs
```
~/security-solution-worker/
├── config/
│   └── worker_config.json          # Worker-specific settings
├── data/                           # Local data storage
├── logs/                           # Worker logs
└── scripts/
    ├── log_collector_service.py    # On Worker VM 1
    ├── vulnerability_scanner_service.py # On Worker VM 2
    ├── compliance_checker.py       # On Worker VM 2
    └── message_queue.py            # Shared message queue client
```

## 1. Base Installation (All VMs)

Run these commands on all three VMs to set up the base environment:

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3 python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools python3-venv git curl wget gnupg2

# Install additional tools
sudo apt install -y nmap tcpdump wireshark tshark net-tools libzmq3-dev

# Set up Python virtual environment
python3 -m venv ~/security-venv
echo 'source ~/security-venv/bin/activate' >> ~/.bashrc
source ~/security-venv/bin/activate

# Install base Python packages
pip install --upgrade pip
pip install paramiko requests python-dateutil pytz psutil
```

## 2. Server VM Setup (192.168.100.66)

### 2.1 Install ELK Stack

Follow the ELK installation guide from the ELK_CONF copy.md document. The key steps are:

```bash
# Install Java
sudo apt update
sudo apt install default-jdk -y

# Install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install elasticsearch

# Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
# Modify:
network.host: 0.0.0.0
xpack.security.enabled: false

# Start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
sudo systemctl status elasticsearch

# Install Logstash
sudo apt install logstash -y

# Configure Logstash beats input
sudo nano /etc/logstash/conf.d/beats.conf
# Add input/filter/output configuration

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGLINE}" }
    }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }

  if [type] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
  }
}

```bash

# Start Logstash
sudo systemctl enable logstash
sudo systemctl start logstash
sudo systemctl status logstash

# Install Kibana
sudo apt install kibana -y

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
# Modify:
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]

# Start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana  
sudo systemctl status kibana
```

### 2.2 Create Security Solution Project Structure

```bash
# Create project directory
mkdir -p ~/security-solution
cd ~/security-solution

# Create project subdirectories
mkdir -p config data/{raw_logs,processed_logs} logs models results scripts/integrations
```

### 2.3 Install Required Libraries

```bash
# Activate virtual environment if not already active
source ~/security-venv/bin/activate

# Install ML and data analysis libraries
pip install pandas==2.0.3 numpy==1.24.3 scikit-learn==1.3.0 matplotlib==3.7.2 seaborn==0.12.2

# Install distributed processing libraries
pip install pyzmq==25.1.1 grpcio==1.56.0 grpcio-tools==1.56.0 protobuf==4.23.4

# Install ELK integration libraries
pip install elasticsearch==8.9.0 python-logstash==0.4.8

# Save requirements
pip freeze > requirements.txt
```

### 2.4 Configure Server Components

Create the following configuration files:

#### server_config.json
```bash
sudo nano  ~/security-solution/config/server_config.json 
```

#### log_sources.json
```bash
sudo nano  ~/security-solution/config/log_sources.json 
```

#### elk_config.json
```bash
sudo nano  ~/security-solution/config/elk_config.json 
```

#### risk_scoring_config.json
```bash
sudo nano  ~/security-solution/config/risk_scoring_config.json 
```

#### asset_criticality.json
```bash
sudo nano  ~/security-solution/config/asset_criticality.json 
```

#### threat_intelligence.json
```bash
sudo nano  ~/security-solution/config/threat_intelligence.json 
```

### 2.5 Create Server Scripts

Let's create the necessary Python scripts for the security solution.

#### server_service.py
```bash
sudo nano  ~/security-solution/scripts/server_service.py 
```

#### message_queue.py
```bash
sudo nano  ~/security-solution/scripts/message_queue.py 
```

#### anomaly_detection.py
```bash
sudo nano  ~/security-solution/scripts/anomaly_detection.py 
```

#### risk_scoring.py
```bash
sudo nano  ~/security-solution/scripts/risk_scoring.py 
```

#### integrations/ml_elk_integration.py
```bash
sudo nano  ~/security-solution/scripts/integrations/ml_elk_integration.py 
```

#### test_environment.py
```bash
sudo nano  ~/security-solution/scripts/test_environment.py 
```

### 2.6 Set Up Server Services

Create systemd service files:

```bash
# Create systemd service for the message queue
sudo tee /etc/systemd/system/security-solution-messagequeue.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Message Queue
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution/scripts/message_queue.py --server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the main server
sudo tee /etc/systemd/system/security-solution-server.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Server
After=network.target security-solution-messagequeue.service elasticsearch.service logstash.service kibana.service
Requires=security-solution-messagequeue.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution/scripts/server_service.py --config config/server_config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the ML-ELK integration
sudo tee /etc/systemd/system/security-solution-ml-elk.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution ML-ELK Integration
After=network.target elasticsearch.service logstash.service kibana.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution/scripts/integrations/ml_elk_integration.py --config config/elk_config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd configuration
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable security-solution-messagequeue.service
sudo systemctl enable security-solution-server.service
sudo systemctl enable security-solution-ml-elk.service
```

### 2.7 Prepare Elasticsearch Index Templates

Create index templates for security data:

```bash
# Connect to the virtual environment
source ~/security-venv/bin/activate

# Create Elasticsearch index templates
python -c "
import json
from elasticsearch import Elasticsearch

with open('config/elk_config.json') as f:
    config = json.load(f)

es = Elasticsearch(hosts=config['elasticsearch']['hosts'])

for template_name, template_config in config['index_templates'].items():
    es.indices.put_template(name=template_name, body=template_config)
    print(f'Created index template: {template_name}')
"
```

## 3. Worker VM 1 Setup (192.168.100.67)

### 3.1 Create Project Structure

```bash
# Create project directory
mkdir -p ~/security-solution-worker
cd ~/security-solution-worker

# Create project subdirectories
mkdir -p config data logs scripts
```

### 3.2 Install Required Libraries

```bash
# Connect to the virtual environment
source ~/security-venv/bin/activate

# Install worker libraries
pip install pandas numpy requests python-logstash pyzmq grpcio grpcio-tools protobuf paramiko
```

### 3.3 Create Worker Configuration

```bash
# Create worker configuration file
sudo nano  ~/security-solution-worker/config/worker_config.json 
```

### 3.4 Create Worker Scripts

#### log_collector_service.py
```bash
sudo nano  ~/security-solution-worker/scripts/log_collector_service.py 
```

#### message_queue.py
Copy from the server:
```bash
scp ubuntu@192.168.100.66:~/security-solution/scripts/message_queue.py ~/security-solution-worker/scripts/
```

### 3.5 Set Up Worker Services

```bash
# Create systemd service for the worker
sudo tee /etc/systemd/system/security-solution-worker.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Worker (Log Collector)
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution-worker
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution-worker/scripts/log_collector_service.py --config config/worker_config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd configuration
sudo systemctl daemon-reload

# Enable worker service
sudo systemctl enable security-solution-worker.service
```

### 3.6 Configure Beats Agents
#### 2.1 Install Filebeat

```bash
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.9.2-amd64.deb
sudo dpkg -i filebeat-8.9.2-amd64.deb
```

#### 2.2 Configure Filebeat

```bash
sudo nano /etc/filebeat/filebeat.yml  
```

Modify the following lines:

```yaml
filebeat.inputs:
- type: filestream
  id: system-logs
  enabled: true
  paths:
    - /var/log/*.log
  tags: ["system"]
  fields:
    source_type: syslog
    environment: security

- type: filestream
  id: security-solution-logs
  enabled: true
  paths:
    - /home/ubuntu/security-solution-worker/logs/*.log
  tags: ["security-solution"]
  fields:
    source_type: application
    environment: security

output.logstash:
  hosts: ["192.168.100.66:5044"]
```

Replace `10.12.56.152` with the IP address of the Server VM.

Enable and start the Filebeat service:  

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

#### 2.3 Install Auditbeat

```bash 
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.9.2-amd64.deb
sudo dpkg -i auditbeat-8.9.2-amd64.deb
```

#### 2.4 Configure Auditbeat

```bash
sudo nano /etc/auditbeat/auditbeat.yml
```

Modify the output section:

```yaml
output.logstash:
  hosts: ["10.12.56.152:5044"]
```

Replace `10.12.56.152` with the IP address of the Server VM.

Enable and start the Auditbeat service:

```bash
sudo systemctl enable auditbeat  
sudo systemctl start auditbeat
sudo systemctl status auditbeat  
```

## 4. Worker VM 2 Setup (192.168.100.68)

### 4.1 Create Project Structure

```bash
# Create project directory
mkdir -p ~/security-solution-worker
cd ~/security-solution-worker

# Create project subdirectories
mkdir -p config data logs scripts
```

### 4.2 Install Required Libraries

```bash
# Connect to the virtual environment
source ~/security-venv/bin/activate

# Install worker libraries
pip install pandas numpy requests python-nmap pyzmq grpcio grpcio-tools protobuf

# Install additional security tools
sudo apt install -y nmap lynis
# On Worker VM 2
pip install elasticsearch==8.9.0  # Match the version with your ELK stack version
```

### 4.3 Create Worker Configuration

```bash
# Create worker configuration file
sudo nano  ~/security-solution-worker/config/worker_config.json 
```

### 4.4 Create Worker Scripts

#### vulnerability_scanner_service.py
```bash
# Create the file with the organized structure
sudo nano  ~/security-solution-worker/scripts/vulnerability_scanner_service.py 


```

#### compliance_checker.py
```bash
sudo nano  ~/security-solution-worker/scripts/compliance_checker.py 
```

#### message_queue.py
Copy from the server:
```bash
scp ubuntu@192.168.100.66:~/security-solution/scripts/message_queue.py ~/security-solution-worker/scripts/
```

### 4.5 Set Up Worker Services

```bash
# Create systemd service for the vulnerability scanner
sudo tee /etc/systemd/system/security-solution-vulnerability-scanner.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Vulnerability Scanner
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution-worker
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution-worker/scripts/vulnerability_scanner_service.py --config config/worker_config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for the compliance checker
sudo tee /etc/systemd/system/security-solution-compliance-checker.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Compliance Checker
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution-worker
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution-worker/scripts/compliance_checker.py --config config/worker_config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd configuration
sudo systemctl daemon-reload

# Enable worker services
sudo systemctl enable security-solution-vulnerability-scanner.service
sudo systemctl enable security-solution-compliance-checker.service
```

### 4.6 Configure Beats Agents
#### 3.1 Install Metricbeat

```bash
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.9.2-amd64.deb
sudo dpkg -i metricbeat-8.9.2-amd64.deb  
```

#### 3.2 Configure Metricbeat

```bash 
sudo nano /etc/metricbeat/metricbeat.yml
```

Modify the output section:

```yaml
output.logstash:
  hosts: ["10.12.56.152:5044"] 
```

Replace `10.12.56.152` with the IP address of the Server VM.

Enable and start the Metricbeat service:

```bash
sudo systemctl enable metricbeat
sudo systemctl start metricbeat 
sudo systemctl status metricbeat
```

#### 3.3 Install Packetbeat

```bash
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-8.9.2-amd64.deb
sudo dpkg -i packetbeat-8.9.2-amd64.deb
```

#### 3.4 Configure Packetbeat  

```bash
sudo nano /etc/packetbeat/packetbeat.yml  
```

Modify the output section:

```yaml 
output.logstash:
  hosts: ["10.12.56.152:5044"]
```

Replace `10.12.56.152` with the IP address of the Server VM.

Enable and start the Packetbeat service:

```bash
sudo systemctl enable packetbeat
sudo systemctl start packetbeat
sudo systemctl status packetbeat  
```

## 5. Starting and Testing the System

### 5.1 Start Services on Server VM

```bash
# Start the security solution services
sudo systemctl start security-solution-messagequeue.service
sudo systemctl start security-solution-ml-elk.service
sudo systemctl start security-solution-server.service
```

### 5.2 Start Services on Worker VM 1

```bash
# Start the Beats agents
sudo systemctl start filebeat
sudo systemctl start auditbeat

# Start the security solution worker service
sudo systemctl start security-solution-worker.service
```

### 5.3 Start Services on Worker VM 2

```bash
# Start the Beats agents
sudo systemctl start metricbeat
sudo systemctl start packetbeat

# Start the security solution worker services
sudo systemctl start security-solution-vulnerability-scanner.service
sudo systemctl start security-solution-compliance-checker.service
```

### 5.4 Test the System

On the Server VM, run the test_environment.py script to verify that everything is set up correctly:

```bash
cd ~/security-solution
source ~/security-venv/bin/activate
python scripts/test_environment.py
```

### 5.5 Access Kibana Dashboard

Access the Kibana dashboard at http://192.168.100.66:5601 in your web browser.

## 6. Kibana Dashboard Setup

### 6.1 Create Index Patterns

1. In Kibana, go to Stack Management > Data > Index Patterns
2. Create the following index patterns:
   - `security-anomalies-*`
   - `security-vulnerabilities-*`
   - `security-compliance-*`
   - `security-risk-scores-*`
   - `filebeat-*`
   - `auditbeat-*`
   - `metricbeat-*`
   - `packetbeat-*`

### 6.2 Create Security Dashboard

1. Go to Dashboard > Create Dashboard
2. Add the following visualizations:

#### Security Overview Panels
- Risk Score by Asset (Bar Chart)
- Recent Anomalies (Data Table)
- Open Services by Host (Pie Chart)
- Compliance Status by Framework (Gauge)
- System Metrics Over Time (Line Chart)

## 7. Maintenance and Management

### 7.1 Backup Configuration

Create a backup script:

```bash
sudo nano  ~/security-solution/scripts/backup_config.sh << 'EOF'
#!/bin/bash
BACKUP_DIR=~/security-backups
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup security solution configuration
cp -r ~/security-solution/config $BACKUP_DIR/security-config-$TIMESTAMP

# Backup ELK configuration
sudo cp /etc/elasticsearch/elasticsearch.yml $BACKUP_DIR/elasticsearch-$TIMESTAMP.yml
sudo cp /etc/logstash/conf.d/beats.conf $BACKUP_DIR/logstash-beats-$TIMESTAMP.conf
sudo cp /etc/kibana/kibana.yml $BACKUP_DIR/kibana-$TIMESTAMP.yml

echo "Configuration backed up to $BACKUP_DIR"
EOF
```

Set permissions and create a cron job:

```bash
chmod +x ~/security-solution/scripts/backup_config.sh
crontab -e

# Add the following line to run backup daily at 1 AM
0 1 * * * ~/security-solution/scripts/backup_config.sh
```

### 7.2 Log Rotation

Configure log rotation:

```bash
sudo tee /etc/logrotate.d/security-solution << 'EOF'
/home/ubuntu/security-solution/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ubuntu ubuntu
}
EOF
```

## 8. Troubleshooting

### 8.1 Check Service Status

```bash
# Check ELK stack services
sudo systemctl status elasticsearch
sudo systemctl status logstash
sudo systemctl status kibana

# Check security solution services
sudo systemctl status security-solution-messagequeue.service
sudo systemctl status security-solution-server.service
sudo systemctl status security-solution-ml-elk.service
```

### 8.2 View Logs

```bash
# View ELK stack logs
sudo journalctl -u elasticsearch
sudo journalctl -u logstash
sudo journalctl -u kibana

# View security solution logs
tail -f ~/security-solution/logs/*.log
```

### 8.3 Test Components Individually

```bash
# Test message queue
cd ~/security-solution
source ~/security-venv/bin/activate
python scripts/message_queue.py --admin

# Test vulnerability scanner directly
cd ~/security-solution-worker
source ~/security-venv/bin/activate
python scripts/vulnerability_scanner_service.py --scan-now

# Test compliance checker directly
cd ~/security-solution-worker
source ~/security-venv/bin/activate
python scripts/compliance_checker.py --check-now
```

## 9. Integration Testing

### 9.1 Test Data Flow from Beats to Elasticsearch

```bash
# Check if Elasticsearch is receiving data from Beats
curl -X GET "http://192.168.100.66:9200/_cat/indices/filebeat-*?v"
curl -X GET "http://192.168.100.66:9200/_cat/indices/metricbeat-*?v"
```

### 9.2 Test Data Flow from AI Components to Elasticsearch

```bash
# Check if security indices are being created and populated
curl -X GET "http://192.168.100.66:9200/_cat/indices/security-*?v"
```

### 9.3 Verify End-to-End Integration

1. Access Kibana at http://192.168.100.66:5601
2. Check each index pattern for incoming data
3. Verify that dashboards are displaying the expected visualizations

## Conclusion

This AI-Driven Security Solution provides comprehensive security monitoring, vulnerability assessment, and compliance checking across your virtual infrastructure. The system integrates advanced machine learning algorithms with the ELK stack to provide real-time detection of security threats and anomalies.

The modular architecture allows for easy expansion and customization to meet specific security requirements. All components run automatically and are integrated with systemd for reliable operation and automatic startup.

### some additions after testing :
You're right! Let's address both issues:

### 1. Fix the missing configuration file on Worker VM 2 (192.168.100.68)

You need to create the worker_config.json file:

```bash
# On Worker VM 2
mkdir -p ~/security-solution-worker/config

# Create the worker config file
cat > ~/security-solution-worker/config/worker_config.json << 'EOF'
{
  "worker_id": "worker2",
  "worker_type": "vulnerability_scanner",
  "server": {
    "host": "192.168.100.66",
    "port": 5555
  },
  "vulnerability_scanning": {
    "targets": [
      {
        "host": "192.168.100.66",
        "ports": "1-1024"
      },
      {
        "host": "192.168.100.67",
        "ports": "1-1024"
      },
      {
        "host": "192.168.100.68",
        "ports": "1-1024"
      }
    ],
    "interval": 3600
  },
  "compliance": {
    "frameworks": {
      "cis_ubuntu": [
        {
          "name": "Ensure SSH root login is disabled",
          "command": "grep \"^PermitRootLogin\" /etc/ssh/sshd_config | grep -v \"#\" | awk '{print $2}'"
        },
        {
          "name": "Ensure password authentication is disabled in SSH",
          "command": "grep \"^PasswordAuthentication\" /etc/ssh/sshd_config | grep -v \"#\" | awk '{print $2}'"
        }
      ],
      "nist_800_53": [
        {
          "name": "Ensure system is up to date",
          "command": "apt list --upgradable"
        },
        {
          "name": "Ensure auditd is installed",
          "command": "dpkg -s auditd"
        }
      ]
    },
    "interval": 86400
  },
  "elk": {
    "elasticsearch": {
      "hosts": ["http://192.168.100.66:9200"],
      "vulnerabilities_index": "security-vulnerabilities",
      "compliance_index": "security-compliance"
    }
  }
}
EOF
```

### 2. Test Worker VM 1 (192.168.100.67) for Log Collection

On Worker VM 1, you need to:

```bash
# First create the config directory and file if not already present
mkdir -p ~/security-solution-worker/config

# Create the worker config file
cat > ~/security-solution-worker/config/worker_config.json << 'EOF'
{
  "worker_id": "worker1",
  "worker_type": "log_collector",
  "server": {
    "host": "192.168.100.66",
    "port": 5555
  },
  "log_collection": {
    "sources": [
      {
        "path": "/var/log/syslog",
        "type": "syslog"
      },
      {
        "path": "/var/log/auth.log",
        "type": "auth"
      }
    ],
    "interval": 60
  },
  "logstash": {
    "host": "192.168.100.66",
    "port": 5044
  }
}
EOF

# Now test the log collector
cd ~/security-solution-worker
source ~/security-venv/bin/activate
python scripts/log_collector_service.py --collect-now
```

Note: The log collector script might not have a `--collect-now` option like the others. If it doesn't, you might need to modify the script to add that functionality or just run it normally and let it complete one collection cycle:

```bash
python scripts/log_collector_service.py
```

And then press Ctrl+C after it completes one collection cycle.

After fixing these issues, the individual components should work properly. The message queue on the Server VM is already working and showing worker1 as connected, which is good!


You need to run these commands on different VMs depending on which component you're testing:

### On Server VM (192.168.100.66)

```bash
# Test message queue
cd ~/security-solution
source ~/security-venv/bin/activate
python scripts/message_queue.py --admin
```

This will start the message queue in admin mode, allowing you to see the status of connected workers.

### On Worker VM 2 (192.168.100.68)

```bash
# Test vulnerability scanner directly
cd ~/security-solution-worker
source ~/security-venv/bin/activate
python scripts/vulnerability_scanner_service.py --scan-now

# After the vulnerability scan completes, test compliance checker
cd ~/security-solution-worker
source ~/security-venv/bin/activate
python scripts/compliance_checker.py --check-now
```

These tests run a single scan/check cycle and exit, which is perfect for testing.

### Important prerequisites:

1. **Make sure all scripts exist on the appropriate VMs** - you may need to copy files between VMs if you haven't done so yet

2. **Run these tests in this order**:
   - First start the message queue on the server
   - Then run the worker tests while the message queue is running
   - This ensures the workers can send their data back to the server

3. **After testing**:
   - Check your Elasticsearch indices for new data
   - Refresh your Kibana dashboard to see if visualizations populate with the test data

This testing approach helps verify each component works correctly before setting up the full automated system with systemd services.

I understand the issue now. In Kibana 8.x, there's a stricter requirement - you can't create data views for index patterns that don't currently exist.

Here's what we can do instead:

### Solution 1: Create the views later
Wait until your security services are running and have created some sample data before creating these data views. This is the simplest approach:

1. First, start your security services (vulnerability scanner, compliance checker, etc.)
2. Once they've run and sent some data to Elasticsearch, then create the data views

### Solution 2: Create temporary placeholder indices
If you want to create the data views now, we can create empty placeholder indices:

```bash
# Connect to your server VM
# Run these commands to create empty placeholder indices

# Create a security-vulnerabilities index
curl -X PUT "http://localhost:9200/security-vulnerabilities-2025.05.15" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" }
    }
  }
}
'

# Create a security-compliance index
curl -X PUT "http://localhost:9200/security-compliance-2025.05.15" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" }
    }
  }
}
'

# Create a security-risk-scores index
curl -X PUT "http://localhost:9200/security-risk-scores-2025.05.15" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" }
    }
  }
}
'
```

After running these commands, refresh the data view creation page, and you should be able to create the data views.

Which solution would you prefer to proceed with?

That's interesting! The libraries are already installed according to pip, but the test script reports them as missing. This is likely a Python environment detection issue.

Let's try to fix this:

1. **First, ensure your virtual environment is properly activated**:
   ```bash
   # Make sure you're using the right environment
   which python
   # Should show: /home/ubuntu/security-venv/bin/python
   ```

2. **Try importing the libraries directly**:
   ```bash
   python -c "import sklearn; import zmq; import grpc; import google.protobuf; print('All imports successful!')"
   ```

3. **If the direct imports work, let's fix the test script**:
   ```bash
   # Open the test_environment.py file
   nano scripts/test_environment.py
   ```

   Look for the `test_required_libraries` function. The issue might be that it's trying to import specific modules incorrectly. If you're comfortable editing Python code, you can modify it to use the correct import names:

   ```python
   def test_required_libraries():
       """Test required Python libraries."""
       logger.info("Testing required Python libraries")
       
       required_libraries = {
           'pandas': 'pandas',
           'numpy': 'numpy',
           'scikit-learn': 'sklearn',  # This might be the issue - should check for 'sklearn' not 'scikit-learn'
           'elasticsearch': 'elasticsearch', 
           'pyzmq': 'zmq',  # This should be 'zmq' not 'pyzmq'
           'grpcio': 'grpc',  # This should be 'grpc' not 'grpcio'
           'protobuf': 'google.protobuf',  # This should be 'google.protobuf' not 'protobuf'
           'requests': 'requests',
           'paramiko': 'paramiko'
       }
       
       all_installed = True
       for display_name, import_name in required_libraries.items():
           try:
               __import__(import_name)
               logger.info(f"✅ {display_name} is installed")
           except ImportError:
               logger.error(f"❌ {display_name} is not installed")
               all_installed = False
               
       return all_installed
   ```

4. **Run the test again**:
   ```bash
   python scripts/test_environment.py
   ```

This should resolve the library detection issues. The packages are installed, but the test script might be using incorrect module names to check for their presence.

You're making great progress! The test shows a few missing Python libraries, but overall your setup is looking good. The ELK stack is running properly, your configuration files are in place, and your worker VMs are reachable.

## Missing Python Libraries

You need to install these libraries:
```bash
pip install scikit-learn pyzmq grpcio protobuf
```

Run this command on your server VM to install the missing dependencies. After installing them, run the test again to make sure everything passes.

## Good Signs From Your Test

✅ **Working well:**
- ELK Stack (Elasticsearch, Logstash, Kibana) is running
- All configuration files are in place
- Directory structure is correct
- Worker VMs are pingable

⚠️ **Expected warnings:**
- Worker VM ports aren't open yet (this is normal since we haven't started the services)

After installing the missing Python libraries, you should be ready to proceed with setting up the worker VMs and starting the services. This test confirms that your core infrastructure is set up correctly.
Yes, you need to copy the `message_queue.py` file from the server to the worker, but the SSH connection is being refused. Let's troubleshoot this and provide alternatives:

### SSH Connection Issue

The "Connection refused" error indicates that either:
1. SSH server isn't running on 192.168.100.66
2. A firewall is blocking port 22
3. The IP address might be incorrect

### Solutions:

1. **First, check if SSH is installed and running on the server**:
   ```bash
   # On the server VM (192.168.100.66):
   sudo apt install openssh-server
   sudo systemctl status ssh
   ```

2. **If SSH is running, check firewall settings**:
   ```bash
   # On the server VM:
   sudo ufw status
   # If it's active, allow SSH:
   sudo ufw allow ssh
   ```

3. **Alternative: Create the file manually** if SSH isn't working:
   Since you already have the message_queue.py content from our installation guide, you can create it directly:

   ```bash
   # On Worker VM (192.168.100.67 or 192.168.100.68):
   mkdir -p ~/security-solution-worker/scripts
   nano ~/security-solution-worker/scripts/message_queue.py
   ```

   Then paste the message_queue.py content into the editor.

4. **Another option: Use a USB drive** to transfer the file between VMs if they're on the same physical machine.

### Updated IP Addresses

I've noted your new IP addresses:
- Server VM: 192.168.100.66
- Worker VM 1: 192.168.100.67
- Worker VM 2: 192.168.100.68

Make sure to update all configuration files to use these IP addresses instead of the ones in my original instructions.

Would you like me to provide the complete content of the message_queue.py file so you can create it manually?


You're getting an error because the index templates are missing the required "index_patterns" field. Every Elasticsearch index template must specify which indices it applies to. Let's fix the `elk_config.json` file:

```bash
cat > ~/security-solution/config/elk_config.json << 'EOF'
{
  "elasticsearch": {
    "hosts": ["http://localhost:9200"],
    "indices": {
      "anomalies": "security-anomalies",
      "vulnerabilities": "security-vulnerabilities",
      "compliance": "security-compliance",
      "risk_scores": "security-risk-scores",
      "logs": "security-logs"
    }
  },
  "logstash": {
    "host": "localhost",
    "port": 5044
  },
  "kibana": {
    "host": "localhost",
    "port": 5601
  },
  "index_templates": {
    "anomalies": {
      "index_patterns": ["security-anomalies*"],
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "score": { "type": "float" },
          "asset": { "type": "keyword" },
          "description": { "type": "text" }
        }
      }
    },
    "vulnerabilities": {
      "index_patterns": ["security-vulnerabilities*"],
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "host": { "type": "keyword" },
          "port": { "type": "integer" },
          "service": { "type": "keyword" },
          "severity": { "type": "keyword" },
          "description": { "type": "text" }
        }
      }
    },
    "compliance": {
      "index_patterns": ["security-compliance*"],
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "host": { "type": "keyword" },
          "framework": { "type": "keyword" },
          "check_name": { "type": "keyword" },
          "status": { "type": "keyword" },
          "output": { "type": "text" }
        }
      }
    },
    "risk_scores": {
      "index_patterns": ["security-risk-scores*"],
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "asset": { "type": "keyword" },
          "score": { "type": "float" },
          "risk_level": { "type": "keyword" },
          "anomaly_score": { "type": "float" },
          "vulnerability_score": { "type": "float" },
          "compliance_score": { "type": "float" }
        }
      }
    }
  }
}
EOF
```

I've added the `index_patterns` field to each template. This tells Elasticsearch which indices the template should be applied to.

Now try running the Elasticsearch template creation script again:

```bash
python -c "
import json
from elasticsearch import Elasticsearch

with open('config/elk_config.json') as f:
    config = json.load(f)

es = Elasticsearch(hosts=config['elasticsearch']['hosts'])

for template_name, template_config in config['index_templates'].items():
    es.indices.put_template(name=template_name, body=template_config)
    print(f'Created index template: {template_name}')
"
```

You might see a deprecation warning about the 'body' parameter, but that's just a warning and shouldn't prevent the templates from being created.