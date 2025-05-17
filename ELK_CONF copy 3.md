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
```
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

# Set up Git for version control
git init
echo "security-venv/" > .gitignore
echo "*.log" >> .gitignore
echo "data/raw_logs/" >> .gitignore
echo "__pycache__/" >> .gitignore
git add .gitignore
git commit -m "Initial project structure"
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
cat > ~/security-solution/config/server_config.json << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 5555
  },
  "workers": {
    "worker1": {
      "host": "192.168.100.67",
      "port": 5555
    },
    "worker2": {
      "host": "192.168.100.68",
      "port": 5555
    }
  },
  "model": {
    "contamination": 0.05,
    "algorithms": ["isolation_forest", "local_outlier_factor"]
  },
  "elk": {
    "elasticsearch": {
      "hosts": ["localhost:9200"],
      "indices": {
        "anomalies": "security-anomalies",
        "vulnerabilities": "security-vulnerabilities",
        "compliance": "security-compliance",
        "risk_scores": "security-risk-scores"
      }
    },
    "logstash": {
      "host": "localhost",
      "port": 5044
    },
    "kibana": {
      "host": "localhost",
      "port": 5601
    }
  }
}
EOF
```

#### log_sources.json
```bash
cat > ~/security-solution/config/log_sources.json << 'EOF'
{
  "local_files": [
    {
      "path": "/var/log/syslog",
      "type": "syslog"
    },
    {
      "path": "/var/log/auth.log",
      "type": "auth"
    }
  ],
  "syslog_server": {
    "host": "localhost",
    "port": 514,
    "protocol": "udp"
  },
  "ssh_remote": {
    "hosts": [
      "192.168.100.67",
      "192.168.100.68"
    ],
    "user": "ubuntu",
    "key_file": "/home/ubuntu/.ssh/id_rsa",
    "logs": [
      {
        "path": "/var/log/syslog",
        "type": "syslog"
      },
      {
        "path": "/var/log/auth.log",
        "type": "auth"
      }
    ]
  },
  "collection_interval": 60,
  "retention_days": 90
}
EOF
```

#### elk_config.json
```bash
cat > ~/security-solution/config/elk_config.json << 'EOF'
{
  "elasticsearch": {
    "hosts": ["localhost:9200"],
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

#### risk_scoring_config.json
```bash
cat > ~/security-solution/config/risk_scoring_config.json << 'EOF'
{
  "risk_weights": {
    "vulnerability": 0.4,
    "anomaly": 0.3,
    "compliance": 0.3
  },
  "risk_thresholds": {
    "high": 0.7,
    "medium": 0.4
  },
  "data": {
    "anomalies": "results/anomalies.json",
    "vulnerabilities": "results/vulnerabilities.json",
    "compliance_issues": "results/compliance_issues.json"
  },
  "asset_criticality": "config/asset_criticality.json",
  "output": {
    "path": "results/risk_scores.json"
  }
}
EOF
```

#### asset_criticality.json
```bash
cat > ~/security-solution/config/asset_criticality.json << 'EOF'
{
  "192.168.100.66": {
    "name": "Server VM",
    "criticality": "high",
    "anomaly_weight": 0.3,
    "vulnerability_weight": 0.4,
    "compliance_weight": 0.3,
    "total_weight": 1.0
  },
  "192.168.100.67": {
    "name": "Worker VM 1",
    "criticality": "medium",
    "anomaly_weight": 0.4,
    "vulnerability_weight": 0.3,
    "compliance_weight": 0.3,
    "total_weight": 1.0
  },
  "192.168.100.68": {
    "name": "Worker VM 2",
    "criticality": "medium",
    "anomaly_weight": 0.3,
    "vulnerability_weight": 0.4,
    "compliance_weight": 0.3,
    "total_weight": 1.0
  },
  "default": {
    "name": "Default Asset",
    "criticality": "low",
    "anomaly_weight": 0.3,
    "vulnerability_weight": 0.3,
    "compliance_weight": 0.4,
    "total_weight": 1.0
  }
}
EOF
```

#### threat_intelligence.json
```bash
cat > ~/security-solution/config/threat_intelligence.json << 'EOF'
{
  "sources": [
    {
      "name": "internal",
      "type": "file",
      "path": "data/threat_intel/indicators.json",
      "format": "json",
      "refresh_interval": 86400
    }
  ],
  "indicators": {
    "ip": "data/threat_intel/ip_indicators.json",
    "domain": "data/threat_intel/domain_indicators.json",
    "url": "data/threat_intel/url_indicators.json",
    "hash": "data/threat_intel/hash_indicators.json"
  },
  "elk_index": "security-threat-intel"
}
EOF
```

### 2.5 Create Server Scripts

Let's create the necessary Python scripts for the security solution.

#### server_service.py
```bash
cat > ~/security-solution/scripts/server_service.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import time
from concurrent import futures

import grpc
import importlib.util

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/server_service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ServerService:
    def __init__(self, config):
        self.config = config
        self.services = []
        
    def start(self):
        logger.info("Starting server services...")
        
        # Initialize ELK connection
        try:
            from elasticsearch import Elasticsearch
            self.es = Elasticsearch(hosts=self.config['elk']['elasticsearch']['hosts'])
            logger.info(f"Connected to Elasticsearch at {self.config['elk']['elasticsearch']['hosts']}")
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            
        # Start anomaly detection service
        try:
            self.start_anomaly_detection()
        except Exception as e:
            logger.error(f"Failed to start anomaly detection service: {e}")
            
        # Start risk scoring service
        try:
            self.start_risk_scoring()
        except Exception as e:
            logger.error(f"Failed to start risk scoring service: {e}")
            
        logger.info("All services started successfully")
        
    def start_anomaly_detection(self):
        logger.info("Starting anomaly detection service...")
        # Import the module dynamically
        spec = importlib.util.spec_from_file_location(
            "anomaly_detection", 
            os.path.join(os.path.dirname(__file__), "anomaly_detection.py")
        )
        anomaly_detection = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(anomaly_detection)
        
        # Create a thread for anomaly detection
        executor = futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            anomaly_detection.run_anomaly_detection_service, 
            self.config
        )
        self.services.append((future, executor, "anomaly_detection"))
        logger.info("Anomaly detection service started")
        
    def start_risk_scoring(self):
        logger.info("Starting risk scoring service...")
        # Import the module dynamically
        spec = importlib.util.spec_from_file_location(
            "risk_scoring", 
            os.path.join(os.path.dirname(__file__), "risk_scoring.py")
        )
        risk_scoring = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(risk_scoring)
        
        # Create a thread for risk scoring
        executor = futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            risk_scoring.run_risk_scoring_service, 
            self.config
        )
        self.services.append((future, executor, "risk_scoring"))
        logger.info("Risk scoring service started")
        
    def run(self):
        self.start()
        
        try:
            while True:
                # Check if any service has crashed
                for future, executor, name in self.services:
                    if future.done():
                        exception = future.exception()
                        if exception:
                            logger.error(f"Service {name} crashed: {exception}")
                            # Restart the service
                            logger.info(f"Restarting {name} service...")
                            if name == "anomaly_detection":
                                self.start_anomaly_detection()
                            elif name == "risk_scoring":
                                self.start_risk_scoring()
                                
                time.sleep(10)  # Check every 10 seconds
        except KeyboardInterrupt:
            logger.info("Server shutting down gracefully...")
            # Clean up
            for _, executor, _ in self.services:
                executor.shutdown(wait=False)

def run_server(config_path):
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Load configuration
    try:
        with open(config_path) as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Create and start the server
    server = ServerService(config)
    server.run()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AI-Driven Security Solution Server')
    parser.add_argument('--config', type=str, default='config/server_config.json',
                        help='Path to the configuration file')
    args = parser.parse_args()
    
    run_server(args.config)
EOF
```

#### message_queue.py
```bash
cat > ~/security-solution/scripts/message_queue.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import time
import uuid
from concurrent import futures

import grpc
import zmq

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/message_queue.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MessageQueue:
    def __init__(self, host="0.0.0.0", port=5555):
        self.host = host
        self.port = port
        self.context = zmq.Context()
        self.socket = None
        self.workers = {}
        
    def start_server(self):
        os.makedirs("logs", exist_ok=True)
        logger.info(f"Starting message queue server on {self.host}:{self.port}")
        
        try:
            self.socket = self.context.socket(zmq.REP)
            self.socket.bind(f"tcp://{self.host}:{self.port}")
            logger.info("Message queue server started successfully")
            
            while True:
                # Wait for next request from client
                message = self.socket.recv_json()
                
                if "type" not in message:
                    response = {"status": "error", "message": "Invalid message format"}
                else:
                    message_type = message["type"]
                    
                    if message_type == "register":
                        response = self.handle_register(message)
                    elif message_type == "heartbeat":
                        response = self.handle_heartbeat(message)
                    elif message_type == "send_data":
                        response = self.handle_send_data(message)
                    elif message_type == "get_status":
                        response = self.handle_get_status(message)
                    else:
                        response = {"status": "error", "message": f"Unknown message type: {message_type}"}
                        
                # Send reply back to client
                self.socket.send_json(response)
                
        except Exception as e:
            logger.error(f"Error in message queue server: {e}")
            if self.socket:
                self.socket.close()
            self.context.term()
            
    def handle_register(self, message):
        if "worker_id" not in message or "worker_type" not in message:
            return {"status": "error", "message": "Missing worker_id or worker_type"}
            
        worker_id = message["worker_id"]
        worker_type = message["worker_type"]
        worker_host = message.get("host", "unknown")
        
        self.workers[worker_id] = {
            "id": worker_id,
            "type": worker_type,
            "host": worker_host,
            "last_heartbeat": time.time(),
            "status": "online"
        }
        
        logger.info(f"Worker registered: {worker_id} ({worker_type}) at {worker_host}")
        return {"status": "success", "message": f"Worker {worker_id} registered successfully"}
        
    def handle_heartbeat(self, message):
        if "worker_id" not in message:
            return {"status": "error", "message": "Missing worker_id"}
            
        worker_id = message["worker_id"]
        
        if worker_id not in self.workers:
            return {"status": "error", "message": f"Worker {worker_id} not registered"}
            
        self.workers[worker_id]["last_heartbeat"] = time.time()
        self.workers[worker_id]["status"] = "online"
        
        return {"status": "success", "message": f"Heartbeat received from {worker_id}"}
        
    def handle_send_data(self, message):
        if "worker_id" not in message or "data" not in message:
            return {"status": "error", "message": "Missing worker_id or data"}
            
        worker_id = message["worker_id"]
        data = message["data"]
        
        if worker_id not in self.workers:
            return {"status": "error", "message": f"Worker {worker_id} not registered"}
            
        # Process the data (in a real implementation, this would store the data or forward it)
        logger.info(f"Received data from {worker_id}: {json.dumps(data)[:100]}...")
        
        return {"status": "success", "message": f"Data received from {worker_id}"}
        
    def handle_get_status(self, message):
        # Check for workers that haven't sent a heartbeat in the last 60 seconds
        current_time = time.time()
        for worker_id, worker in list(self.workers.items()):
            if current_time - worker["last_heartbeat"] > 60:
                worker["status"] = "offline"
                
        return {
            "status": "success",
            "workers": self.workers
        }
        
    def stop(self):
        if self.socket:
            self.socket.close()
        self.context.term()
        logger.info("Message queue server stopped")

class MessageClient:
    def __init__(self, server_host, server_port=5555, worker_id=None, worker_type=None):
        self.server_host = server_host
        self.server_port = server_port
        self.worker_id = worker_id or str(uuid.uuid4())
        self.worker_type = worker_type or "generic"
        self.context = zmq.Context()
        self.socket = None
        
    def connect(self):
        logger.info(f"Connecting to message queue server at {self.server_host}:{self.server_port}")
        
        try:
            self.socket = self.context.socket(zmq.REQ)
            self.socket.connect(f"tcp://{self.server_host}:{self.server_port}")
            
            # Register with the server
            response = self.send_message({
                "type": "register",
                "worker_id": self.worker_id,
                "worker_type": self.worker_type,
                "host": os.uname().nodename
            })
            
            if response.get("status") == "success":
                logger.info("Connected to message queue server successfully")
                return True
            else:
                logger.error(f"Failed to register with message queue server: {response.get('message')}")
                return False
                
        except Exception as e:
            logger.error(f"Error connecting to message queue server: {e}")
            if self.socket:
                self.socket.close()
            return False
            
    def send_message(self, message):
        if not self.socket:
            logger.error("Not connected to message queue server")
            return {"status": "error", "message": "Not connected to server"}
            
        try:
            self.socket.send_json(message)
            response = self.socket.recv_json()
            return response
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return {"status": "error", "message": str(e)}
            
    def send_heartbeat(self):
        return self.send_message({
            "type": "heartbeat",
            "worker_id": self.worker_id
        })
        
    def send_data(self, data):
        return self.send_message({
            "type": "send_data",
            "worker_id": self.worker_id,
            "data": data
        })
        
    def get_status(self):
        return self.send_message({
            "type": "get_status"
        })
        
    def start_heartbeat_thread(self):
        def heartbeat_loop():
            while True:
                try:
                    response = self.send_heartbeat()
                    if response.get("status") != "success":
                        logger.warning(f"Heartbeat failed: {response.get('message')}")
                except Exception as e:
                    logger.error(f"Heartbeat error: {e}")
                time.sleep(30)
                
        executor = futures.ThreadPoolExecutor(max_workers=1)
        executor.submit(heartbeat_loop)
        
    def disconnect(self):
        if self.socket:
            self.socket.close()
        self.context.term()
        logger.info("Disconnected from message queue server")

def run_server_mode(host, port):
    os.makedirs("logs", exist_ok=True)
    server = MessageQueue(host, port)
    try:
        server.start_server()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        server.stop()

def run_worker_mode(server_host, server_port, worker_id, worker_type):
    os.makedirs("logs", exist_ok=True)
    client = MessageClient(server_host, server_port, worker_id, worker_type)
    if client.connect():
        client.start_heartbeat_thread()
        
        # In a real implementation, the worker would do its work here
        # For demonstration purposes, we'll just sleep
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Worker shutting down...")
            client.disconnect()

def run_admin_mode(server_host, server_port):
    os.makedirs("logs", exist_ok=True)
    client = MessageClient(server_host, server_port, "admin", "admin")
    if client.connect():
        try:
            while True:
                command = input("Enter command (status/exit): ")
                if command == "status":
                    response = client.get_status()
                    if response.get("status") == "success":
                        workers = response.get("workers", {})
                        print(f"Connected workers: {len(workers)}")
                        for worker_id, worker in workers.items():
                            print(f"  {worker_id} ({worker['type']}): {worker['status']}")
                    else:
                        print(f"Error getting status: {response.get('message')}")
                elif command == "exit":
                    break
                else:
                    print("Unknown command")
        except KeyboardInterrupt:
            pass
        finally:
            client.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Message Queue Service")
    parser.add_argument("--server", action="store_true", help="Run in server mode")
    parser.add_argument("--worker", action="store_true", help="Run in worker mode")
    parser.add_argument("--admin", action="store_true", help="Run in admin mode")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind/connect to")
    parser.add_argument("--port", type=int, default=5555, help="Port to bind/connect to")
    parser.add_argument("--worker-id", type=str, help="Worker ID")
    parser.add_argument("--worker-type", type=str, help="Worker type")
    
    args = parser.parse_args()
    
    if args.server:
        run_server_mode(args.host, args.port)
    elif args.worker:
        if not args.worker_id or not args.worker_type:
            print("Worker ID and worker type must be specified in worker mode")
            sys.exit(1)
        run_worker_mode(args.host, args.port, args.worker_id, args.worker_type)
    elif args.admin:
        run_admin_mode(args.host, args.port)
    else:
        parser.print_help()
EOF
```

#### anomaly_detection.py
```bash
cat > ~/security-solution/scripts/anomaly_detection.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/anomaly_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_data(es, index, time_range='1h'):
    """Load data from Elasticsearch for anomaly detection."""
    logger.info(f"Loading data from {index} for the last {time_range}")
    
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{time_range}",
                    "lte": "now"
                }
            }
        },
        "size": 10000  # Adjust based on your needs
    }
    
    try:
        result = es.search(index=index, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} records from Elasticsearch")
        
        if not hits:
            logger.warning(f"No data found in {index} for the last {time_range}")
            return None
            
        # Extract features for anomaly detection
        data = []
        for hit in hits:
            source = hit['_source']
            # Extract relevant features for anomaly detection
            # This needs to be adjusted based on your data structure
            features = {
                'host': source.get('host', {}).get('name', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            
            # Include metrics based on the data type
            if 'system' in source:
                if 'cpu' in source['system']:
                    features['cpu_usage'] = source['system']['cpu'].get('total', {}).get('norm', {}).get('pct', 0)
                if 'memory' in source['system']:
                    features['memory_usage'] = source['system']['memory'].get('actual', {}).get('used', {}).get('pct', 0)
                if 'load' in source['system']:
                    features['load_1m'] = source['system']['load'].get('1', 0)
            
            # Add network metrics if available
            if 'network' in source:
                features['network_in_bytes'] = source['network'].get('in', {}).get('bytes', 0)
                features['network_out_bytes'] = source['network'].get('out', {}).get('bytes', 0)
                
            data.append(features)
            
        df = pd.DataFrame(data)
        
        # Convert timestamp to datetime and sort
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Extract numerical features for anomaly detection
        numerical_features = df.select_dtypes(include=[np.number]).columns.tolist()
        if not numerical_features:
            logger.warning("No numerical features found for anomaly detection")
            return None
            
        return df
        
    except Exception as e:
        logger.error(f"Error loading data from Elasticsearch: {e}")
        return None

def detect_anomalies(data, algorithm='isolation_forest', contamination=0.05):
    """Detect anomalies in the data using the specified algorithm."""
    logger.info(f"Detecting anomalies using {algorithm} with contamination {contamination}")
    
    # Select numerical features for anomaly detection
    numerical_features = data.select_dtypes(include=[np.number]).columns.tolist()
    X = data[numerical_features].fillna(0)
    
    # Store original index for mapping back to data
    original_index = data.index
    
    try:
        if algorithm == 'isolation_forest':
            model = IsolationForest(contamination=contamination, random_state=42)
            scores = model.fit_predict(X)
        elif algorithm == 'local_outlier_factor':
            model = LocalOutlierFactor(contamination=contamination, novelty=False)
            scores = model.fit_predict(X)
        else:
            logger.error(f"Unsupported algorithm: {algorithm}")
            return None
            
        # Convert predictions: -1 for anomalies, 1 for normal
        anomalies = data.iloc[np.where(scores == -1)[0]].copy()
        
        if len(anomalies) == 0:
            logger.info("No anomalies detected")
            return pd.DataFrame()
            
        logger.info(f"Detected {len(anomalies)} anomalies")
        
        # Add anomaly scores (decision function gives distance from boundary)
        if algorithm == 'isolation_forest':
            # For Isolation Forest, lower scores indicate anomalies
            anomaly_scores = model.decision_function(X)
            # Invert and normalize scores so higher means more anomalous
            normalized_scores = 1 - (anomaly_scores - np.min(anomaly_scores)) / (np.max(anomaly_scores) - np.min(anomaly_scores))
            
            # Add scores to anomalies
            anomalies['anomaly_score'] = normalized_scores[np.where(scores == -1)[0]]
            
        return anomalies
        
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        return None

def format_anomalies_for_elk(anomalies, index_name):
    """Format anomalies for sending to Elasticsearch."""
    docs = []
    for _, row in anomalies.iterrows():
        timestamp = row.get('timestamp', datetime.now())
        if isinstance(timestamp, pd.Timestamp):
            timestamp = timestamp.isoformat()
            
        doc = {
            "@timestamp": timestamp,
            "host": row.get('host', 'unknown'),
            "anomaly_score": float(row.get('anomaly_score', 0)),
            "anomaly_type": "system_metrics",
            "source": "AI-Driven Security Solution",
            "details": {
                "cpu_usage": float(row.get('cpu_usage', 0)),
                "memory_usage": float(row.get('memory_usage', 0)),
                "load_1m": float(row.get('load_1m', 0)),
                "network_in_bytes": float(row.get('network_in_bytes', 0)),
                "network_out_bytes": float(row.get('network_out_bytes', 0))
            }
        }
        docs.append({
            "_index": index_name,
            "_source": doc
        })
    return docs

def index_anomalies(es, anomalies, index_name):
    """Index detected anomalies to Elasticsearch."""
    if anomalies.empty:
        logger.info("No anomalies to index")
        return
        
    logger.info(f"Indexing {len(anomalies)} anomalies to {index_name}")
    
    try:
        # Format anomalies for Elasticsearch
        docs = format_anomalies_for_elk(anomalies, index_name)
        
        # Use Elasticsearch bulk API for efficiency
        from elasticsearch.helpers import bulk
        success, errors = bulk(es, docs, refresh=True)
        
        logger.info(f"Successfully indexed {success} anomalies, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing anomalies to Elasticsearch: {e}")

def run_anomaly_detection_service(config):
    """Run the anomaly detection service continuously."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        logger.info(f"Connected to Elasticsearch at {config['elk']['elasticsearch']['hosts']}")
        
        # Set up anomalies index if it doesn't exist
        anomalies_index = config['elk']['elasticsearch']['indices']['anomalies']
        
        # Run anomaly detection in a loop
        while True:
            logger.info("Starting anomaly detection cycle")
            
            # Load data from Elasticsearch
            data = load_data(es, "metricbeat-*", "1h")
            
            if data is not None and not data.empty:
                # Detect anomalies
                for algorithm in config['model']['algorithms']:
                    anomalies = detect_anomalies(
                        data, 
                        algorithm=algorithm, 
                        contamination=config['model']['contamination']
                    )
                    
                    if anomalies is not None and not anomalies.empty:
                        # Index anomalies to Elasticsearch
                        index_anomalies(es, anomalies, anomalies_index)
            
            # Sleep before next cycle
            logger.info("Anomaly detection cycle completed, sleeping for 5 minutes")
            time.sleep(300)  # Sleep for 5 minutes
            
    except KeyboardInterrupt:
        logger.info("Anomaly detection service shutting down")
    except Exception as e:
        logger.error(f"Error in anomaly detection service: {e}")
        raise

def run_anomaly_detection(config_path):
    """Run anomaly detection with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Run the anomaly detection service
        run_anomaly_detection_service(config)
        
    except Exception as e:
        logger.error(f"Error running anomaly detection: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Anomaly Detection Service")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
    
    args = parser.parse_args()
    run_anomaly_detection(args.config)
EOF
```

#### risk_scoring.py
```bash
cat > ~/security-solution/scripts/risk_scoring.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/risk_scoring.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_asset_criticality(path):
    """Load asset criticality configuration."""
    logger.info(f"Loading asset criticality from {path}")
    try:
        with open(path) as f:
            asset_criticality = json.load(f)
        return asset_criticality
    except Exception as e:
        logger.error(f"Error loading asset criticality: {e}")
        return None

def get_anomalies_from_elk(es, index, time_range='1d'):
    """Get anomalies from Elasticsearch."""
    logger.info(f"Loading anomalies from {index} for the last {time_range}")
    
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{time_range}",
                    "lte": "now"
                }
            }
        },
        "size": 10000  # Adjust based on your needs
    }
    
    try:
        result = es.search(index=index, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} anomalies from Elasticsearch")
        
        anomalies = []
        for hit in hits:
            source = hit['_source']
            anomaly = {
                'host': source.get('host', 'unknown'),
                'score': source.get('anomaly_score', 0),
                'type': source.get('anomaly_type', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            anomalies.append(anomaly)
            
        return pd.DataFrame(anomalies)
        
    except Exception as e:
        logger.error(f"Error loading anomalies from Elasticsearch: {e}")
        return pd.DataFrame()

def get_vulnerabilities_from_elk(es, index, time_range='7d'):
    """Get vulnerabilities from Elasticsearch."""
    logger.info(f"Loading vulnerabilities from {index} for the last {time_range}")
    
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{time_range}",
                    "lte": "now"
                }
            }
        },
        "size": 10000  # Adjust based on your needs
    }
    
    try:
        result = es.search(index=index, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} vulnerabilities from Elasticsearch")
        
        vulnerabilities = []
        for hit in hits:
            source = hit['_source']
            vuln = {
                'host': source.get('host', {}).get('name', 'unknown') if isinstance(source.get('host'), dict) else source.get('host', 'unknown'),
                'score': source.get('vulnerability_score', 0),
                'severity': source.get('severity', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            vulnerabilities.append(vuln)
            
        return pd.DataFrame(vulnerabilities)
        
    except Exception as e:
        logger.error(f"Error loading vulnerabilities from Elasticsearch: {e}")
        return pd.DataFrame()

def get_compliance_issues_from_elk(es, index, time_range='7d'):
    """Get compliance issues from Elasticsearch."""
    logger.info(f"Loading compliance issues from {index} for the last {time_range}")
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
                    {"term": {"status": "FAIL"}}
                ]
            }
        },
        "size": 10000  # Adjust based on your needs
    }
    
    try:
        result = es.search(index=index, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} compliance issues from Elasticsearch")
        
        issues = []
        for hit in hits:
            source = hit['_source']
            issue = {
                'host': source.get('host', {}).get('name', 'unknown') if isinstance(source.get('host'), dict) else source.get('host', 'unknown'),
                'score': 0.5,  # Default score for compliance issues
                'framework': source.get('framework', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            issues.append(issue)
            
        return pd.DataFrame(issues)
        
    except Exception as e:
        logger.error(f"Error loading compliance issues from Elasticsearch: {e}")
        return pd.DataFrame()

def calculate_risk_scores(anomalies, vulnerabilities, compliance_issues, asset_criticality, risk_weights):
    """Calculate risk scores for assets."""
    logger.info("Calculating risk scores")
    
    # Get unique assets
    assets = set()
    if not anomalies.empty:
        assets.update(anomalies['host'].unique())
    if not vulnerabilities.empty:
        assets.update(vulnerabilities['host'].unique())
    if not compliance_issues.empty:
        assets.update(compliance_issues['host'].unique())
        
    if not assets:
        logger.warning("No assets found for risk scoring")
        return pd.DataFrame()
        
    logger.info(f"Calculating risk scores for {len(assets)} assets")
    
    risk_scores = []
    for asset in assets:
        # Get asset-specific criticality
        if asset in asset_criticality:
            criticality = asset_criticality[asset]
        else:
            criticality = asset_criticality['default']
            
        # Calculate component scores
        asset_anomalies = anomalies[anomalies['host'] == asset] if not anomalies.empty else pd.DataFrame()
        asset_vulns = vulnerabilities[vulnerabilities['host'] == asset] if not vulnerabilities.empty else pd.DataFrame()
        asset_compliance = compliance_issues[compliance_issues['host'] == asset] if not compliance_issues.empty else pd.DataFrame()
        
        anomaly_score = asset_anomalies['score'].sum() if not asset_anomalies.empty else 0
        vulnerability_score = asset_vulns['score'].sum() if not asset_vulns.empty else 0
        compliance_score = asset_compliance['score'].sum() if not asset_compliance.empty else 0
        
        # Normalize scores (0-1 range)
        max_anomaly_score = 10  # Assuming max 10 high-severity anomalies
        max_vuln_score = 20     # Assuming max 20 high-severity vulnerabilities
        max_compliance_score = 10  # Assuming max 10 compliance issues
        
        norm_anomaly_score = min(anomaly_score / max_anomaly_score, 1)
        norm_vuln_score = min(vulnerability_score / max_vuln_score, 1)
        norm_compliance_score = min(compliance_score / max_compliance_score, 1)
        
        # Calculate weighted score
        weighted_score = (
            norm_anomaly_score * risk_weights['anomaly'] +
            norm_vuln_score * risk_weights['vulnerability'] +
            norm_compliance_score * risk_weights['compliance']
        )
        
        risk_scores.append({
            'asset': asset,
            'score': weighted_score,
            'anomaly_score': norm_anomaly_score,
            'vulnerability_score': norm_vuln_score,
            'compliance_score': norm_compliance_score,
            'criticality': criticality['criticality'],
            'timestamp': datetime.now().isoformat()
        })
        
    return pd.DataFrame(risk_scores)

def classify_risk(score, thresholds):
    """Classify risk level based on score and thresholds."""
    if score >= thresholds['high']:
        return 'high'
    elif score >= thresholds['medium']:
        return 'medium'
    else:
        return 'low'

def index_risk_scores(es, risk_scores, index_name):
    """Index risk scores to Elasticsearch."""
    if risk_scores.empty:
        logger.info("No risk scores to index")
        return
        
    logger.info(f"Indexing {len(risk_scores)} risk scores to {index_name}")
    
    try:
        # Format risk scores for Elasticsearch
        docs = []
        for _, row in risk_scores.iterrows():
            doc = {
                "@timestamp": row['timestamp'],
                "asset": row['asset'],
                "score": float(row['score']),
                "risk_level": classify_risk(row['score'], {'high': 0.7, 'medium': 0.4}),
                "anomaly_score": float(row['anomaly_score']),
                "vulnerability_score": float(row['vulnerability_score']),
                "compliance_score": float(row['compliance_score']),
                "criticality": row['criticality'],
                "source": "AI-Driven Security Solution"
            }
            docs.append({
                "_index": index_name,
                "_source": doc
            })
            
        # Use Elasticsearch bulk API for efficiency
        success, errors = bulk(es, docs, refresh=True)
        
        logger.info(f"Successfully indexed {success} risk scores, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing risk scores to Elasticsearch: {e}")

def run_risk_scoring_service(config):
    """Run the risk scoring service continuously."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        logger.info(f"Connected to Elasticsearch at {config['elk']['elasticsearch']['hosts']}")
        
        # Load asset criticality
        asset_criticality_path = "config/asset_criticality.json"
        asset_criticality = load_asset_criticality(asset_criticality_path)
        if asset_criticality is None:
            logger.error("Failed to load asset criticality, exiting")
            return
            
        # Get index names from config
        anomalies_index = config['elk']['elasticsearch']['indices']['anomalies']
        vulnerabilities_index = config['elk']['elasticsearch']['indices']['vulnerabilities']
        compliance_index = config['elk']['elasticsearch']['indices']['compliance']
        risk_scores_index = config['elk']['elasticsearch']['indices']['risk_scores']
        
        # Define risk weights
        risk_weights = {
            'vulnerability': 0.4,
            'anomaly': 0.3,
            'compliance': 0.3
        }
        
        # Run risk scoring in a loop
        while True:
            logger.info("Starting risk scoring cycle")
            
            # Load data from Elasticsearch
            anomalies = get_anomalies_from_elk(es, anomalies_index, '1d')
            vulnerabilities = get_vulnerabilities_from_elk(es, vulnerabilities_index, '7d')
            compliance_issues = get_compliance_issues_from_elk(es, compliance_index, '7d')
            
            # Calculate risk scores
            risk_scores = calculate_risk_scores(
                anomalies,
                vulnerabilities,
                compliance_issues,
                asset_criticality,
                risk_weights
            )
            
            if not risk_scores.empty:
                # Index risk scores to Elasticsearch
                index_risk_scores(es, risk_scores, risk_scores_index)
            
            # Sleep before next cycle
            logger.info("Risk scoring cycle completed, sleeping for 15 minutes")
            time.sleep(900)  # Sleep for 15 minutes
            
    except KeyboardInterrupt:
        logger.info("Risk scoring service shutting down")
    except Exception as e:
        logger.error(f"Error in risk scoring service: {e}")
        raise

def run_risk_scoring(config_path):
    """Run risk scoring with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Run the risk scoring service
        run_risk_scoring_service(config)
        
    except Exception as e:
        logger.error(f"Error running risk scoring: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Risk Scoring Service")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
    
    args = parser.parse_args()
    run_risk_scoring(args.config)
EOF
```

#### integrations/ml_elk_integration.py
```bash
cat > ~/security-solution/scripts/integrations/ml_elk_integration.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/ml_elk_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def connect_to_elasticsearch(hosts):
    """Connect to Elasticsearch."""
    logger.info(f"Connecting to Elasticsearch at {hosts}")
    try:
        es = Elasticsearch(hosts=hosts)
        logger.info("Connected to Elasticsearch successfully")
        return es
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        return None

def create_index_templates(es, templates):
    """Create index templates in Elasticsearch."""
    logger.info("Creating index templates")
    try:
        for name, template in templates.items():
            logger.info(f"Creating index template: {name}")
            # Check if template exists
            exists = es.indices.exists_template(name=name)
            if exists:
                logger.info(f"Template {name} already exists, updating")
                es.indices.put_template(name=name, body=template)
            else:
                logger.info(f"Creating new template {name}")
                es.indices.put_template(name=name, body=template)
        logger.info("Index templates created successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating index templates: {e}")
        return False

def index_data(es, data, index_name):
    """Index data to Elasticsearch."""
    if not data:
        logger.info(f"No data to index to {index_name}")
        return
        
    logger.info(f"Indexing {len(data)} documents to {index_name}")
    try:
        # Ensure data has proper timestamp field
        for record in data:
            if 'timestamp' in record and 'timestamp' not in record:
                record['@timestamp'] = record['timestamp']
                
        # Prepare bulk actions
        actions = [
            {
                "_index": index_name,
                "_source": record
            }
            for record in data
        ]
        
        # Perform bulk indexing
        success, errors = bulk(es, actions, refresh=True)
        
        logger.info(f"Successfully indexed {success} documents to {index_name}, errors: {errors}")
        return True
    except Exception as e:
        logger.error(f"Error indexing data to {index_name}: {e}")
        return False

def load_data_from_file(path):
    """Load data from a JSON file."""
    logger.info(f"Loading data from {path}")
    try:
        with open(path) as f:
            data = json.load(f)
        logger.info(f"Loaded {len(data)} records from {path}")
        return data
    except Exception as e:
        logger.error(f"Error loading data from {path}: {e}")
        return None

def run_ml_elk_integration(config):
    """Run the ML-ELK integration service."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Connect to Elasticsearch
        es = connect_to_elasticsearch(config['elasticsearch']['hosts'])
        if not es:
            logger.error("Failed to connect to Elasticsearch, exiting")
            return
            
        # Create index templates
        if 'index_templates' in config:
            success = create_index_templates(es, config['index_templates'])
            if not success:
                logger.warning("Failed to create index templates, continuing anyway")
                
        # Check for test mode
        if len(sys.argv) > 1 and sys.argv[1] == '--test':
            logger.info("Running in test mode")
            
            # Generate some test data
            test_data = []
            for i in range(10):
                test_data.append({
                    "@timestamp": datetime.now().isoformat(),
                    "host": f"test-host-{i % 3 + 1}",
                    "anomaly_score": 0.7 + (i * 0.03),
                    "anomaly_type": "test",
                    "source": "AI-Driven Security Solution Test"
                })
                
            # Index test data
            index_data(es, test_data, config['elasticsearch']['indices']['anomalies'])
            
            logger.info("Test completed successfully")
            return
            
        # In normal mode, continuously monitor for new data files
        logger.info("Starting continuous monitoring for ML data files")
        
        while True:
            # Check for anomalies
            anomalies_path = os.path.join("results", "anomalies.json")
            if os.path.exists(anomalies_path) and os.path.getsize(anomalies_path) > 0:
                anomalies = load_data_from_file(anomalies_path)
                if anomalies:
                    index_data(
                        es,
                        anomalies,
                        config['elasticsearch']['indices']['anomalies']
                    )
                    # Rename the file to avoid reprocessing
                    os.rename(
                        anomalies_path,
                        os.path.join("results", f"anomalies.{int(time.time())}.json")
                    )
                    
            # Check for vulnerabilities
            vulns_path = os.path.join("results", "vulnerabilities.json")
            if os.path.exists(vulns_path) and os.path.getsize(vulns_path) > 0:
                vulns = load_data_from_file(vulns_path)
                if vulns:
                    index_data(
                        es,
                        vulns,
                        config['elasticsearch']['indices']['vulnerabilities']
                    )
                    # Rename the file to avoid reprocessing
                    os.rename(
                        vulns_path,
                        os.path.join("results", f"vulnerabilities.{int(time.time())}.json")
                    )
                    
            # Check for compliance issues
            compliance_path = os.path.join("results", "compliance_issues.json")
            if os.path.exists(compliance_path) and os.path.getsize(compliance_path) > 0:
                issues = load_data_from_file(compliance_path)
                if issues:
                    index_data(
                        es,
                        issues,
                        config['elasticsearch']['indices']['compliance']
                    )
                    # Rename the file to avoid reprocessing
                    os.rename(
                        compliance_path,
                        os.path.join("results", f"compliance_issues.{int(time.time())}.json")
                    )
                    
            # Sleep before checking again
            time.sleep(60)  # Check every minute
            
    except KeyboardInterrupt:
        logger.info("ML-ELK integration service shutting down")
    except Exception as e:
        logger.error(f"Error in ML-ELK integration service: {e}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML-ELK Integration Service")
    parser.add_argument("--config", type=str, default="config/elk_config.json",
                      help="Path to the ELK configuration file")
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        with open(args.config) as f:
            config = json.load(f)
            
        # Run the ML-ELK integration service
        run_ml_elk_integration(config)
        
    except Exception as e:
        logger.error(f"Error running ML-ELK integration: {e}")
        sys.exit(1)
EOF
```

#### test_environment.py
```bash
cat > ~/security-solution/scripts/test_environment.py << 'EOF'
import logging
import os
import platform
import socket
import subprocess
import sys
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/test_environment.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def test_python_version():
    """Test Python version."""
    logger.info("Testing Python version")
    required_version = (3, 6)
    current_version = sys.version_info[:2]
    
    logger.info(f"Current Python version: {current_version[0]}.{current_version[1]}")
    
    if current_version >= required_version:
        logger.info(f"✅ Python {current_version[0]}.{current_version[1]} meets the minimum requirement")
        return True
    else:
        logger.error(f"❌ Python {required_version[0]}.{required_version[1]} or higher is required")
        return False

def test_required_libraries():
    """Test required Python libraries."""
    logger.info("Testing required Python libraries")
    
    required_libraries = [
        'pandas', 'numpy', 'scikit-learn', 'elasticsearch',
        'pyzmq', 'grpcio', 'protobuf',
        'requests', 'paramiko'
    ]
    
    all_installed = True
    for library in required_libraries:
        try:
            __import__(library)
            logger.info(f"✅ {library} is installed")
        except ImportError:
            logger.error(f"❌ {library} is not installed")
            all_installed = False
            
    return all_installed

def test_elk_stack():
    """Test ELK stack service status."""
    logger.info("Testing ELK stack services")
    
    elk_components = ['elasticsearch', 'logstash', 'kibana']
    all_running = True
    
    for component in elk_components:
        try:
            result = subprocess.run(['systemctl', 'is-active', component], 
                                   stdout=subprocess.PIPE, text=True)
            status = result.stdout.strip()
            
            if status == 'active':
                logger.info(f"✅ {component} is running")
            else:
                logger.error(f"❌ {component} is not running (status: {status})")
                all_running = False
        except Exception as e:
            logger.error(f"❌ Error checking {component} status: {e}")
            all_running = False
            
    return all_running

def test_elk_connectivity():
    """Test connectivity to ELK stack components."""
    logger.info("Testing connectivity to ELK stack components")
    
    components = [
        ('Elasticsearch', 'localhost', 9200),
        ('Kibana', 'localhost', 5601),
        ('Logstash', 'localhost', 5044)
    ]
    
    all_connected = True
    for name, host, port in components:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                logger.info(f"✅ {name} is reachable at {host}:{port}")
            else:
                logger.error(f"❌ {name} is not reachable at {host}:{port}")
                all_connected = False
        except Exception as e:
            logger.error(f"❌ Error checking {name} connectivity: {e}")
            all_connected = False
            
    return all_connected

def test_worker_connectivity(config):
    """Test connectivity to worker nodes."""
    logger.info("Testing connectivity to worker nodes")
    
    workers = [
        ('Worker 1', config['workers']['worker1']['host'], config['workers']['worker1']['port']),
        ('Worker 2', config['workers']['worker2']['host'], config['workers']['worker2']['port'])
    ]
    
    all_connected = True
    for name, host, port in workers:
        # First ping to check basic connectivity
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', host], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                logger.info(f"✅ {name} responds to ping at {host}")
            else:
                logger.error(f"❌ {name} does not respond to ping at {host}")
                all_connected = False
        except Exception as e:
            logger.error(f"❌ Error pinging {name}: {e}")
            all_connected = False
            
        # Then check port connectivity
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                logger.info(f"✅ {name} port {port} is open")
            else:
                logger.warning(f"⚠️ {name} port {port} is not open (this may be expected if service is not running yet)")
        except Exception as e:
            logger.error(f"❌ Error checking {name} port connectivity: {e}")
            
    return all_connected

def test_directory_structure():
    """Test required directory structure."""
    logger.info("Testing directory structure")
    
    required_directories = [
        'config', 'data', 'data/raw_logs', 'data/processed_logs',
        'logs', 'models', 'results', 'scripts', 'scripts/integrations'
    ]
    
    all_exist = True
    for directory in required_directories:
        if os.path.isdir(directory):
            logger.info(f"✅ {directory} directory exists")
        else:
            logger.error(f"❌ {directory} directory is missing")
            all_exist = False
            
    return all_exist

def test_configuration_files():
    """Test required configuration files."""
    logger.info("Testing configuration files")
    
    required_files = [
        'config/server_config.json',
        'config/log_sources.json',
        'config/elk_config.json',
        'config/risk_scoring_config.json',
        'config/asset_criticality.json'
    ]
    
    all_exist = True
    for file in required_files:
        if os.path.isfile(file):
            logger.info(f"✅ {file} exists")
        else:
            logger.error(f"❌ {file} is missing")
            all_exist = False
            
    return all_exist

def run_tests(config_path="config/server_config.json"):
    """Run all environment tests."""
    os.makedirs("logs", exist_ok=True)
    
    logger.info("Starting environment tests")
    logger.info(f"Host: {platform.node()}")
    logger.info(f"OS: {platform.system()} {platform.release()}")
    
    # Load configuration
    try:
        with open(config_path) as f:
            import json
            config = json.load(f)
    except Exception as e:
        logger.error(f"❌ Failed to load configuration: {e}")
        return False
    
    # Run tests
    python_ok = test_python_version()
    libraries_ok = test_required_libraries()
    elk_ok = test_elk_stack()
    elk_conn_ok = test_elk_connectivity()
    worker_conn_ok = test_worker_connectivity(config)
    dirs_ok = test_directory_structure()
    config_ok = test_configuration_files()
    
    # Print summary
    logger.info("\n=== Test Summary ===")
    logger.info(f"Python Version: {'✅ Pass' if python_ok else '❌ Fail'}")
    logger.info(f"Required Libraries: {'✅ Pass' if libraries_ok else '❌ Fail'}")
    logger.info(f"ELK Stack Services: {'✅ Pass' if elk_ok else '❌ Fail'}")
    logger.info(f"ELK Connectivity: {'✅ Pass' if elk_conn_ok else '❌ Fail'}")
    logger.info(f"Worker Connectivity: {'✅ Pass' if worker_conn_ok else '❌ Fail'}")
    logger.info(f"Directory Structure: {'✅ Pass' if dirs_ok else '❌ Fail'}")
    logger.info(f"Configuration Files: {'✅ Pass' if config_ok else '❌ Fail'}")
    
    # Overall result
    all_passed = python_ok and libraries_ok and elk_ok and elk_conn_ok and dirs_ok and config_ok
    # Worker connectivity is a warning, not an error if it fails (might be expected)
    
    if all_passed:
        logger.info("\n✅ All tests passed successfully!")
    else:
        logger.error("\n❌ One or more tests failed")
        
    return all_passed

if __name__ == "__main__":
    # Get config path from command-line arguments if provided
    config_path = "config/server_config.json"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
        
    success = run_tests(config_path)
    
    if not success:
        sys.exit(1)
EOF
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
      },
      {
        "path": "/var/log/kern.log",
        "type": "kernel"
      }
    ],
    "interval": 60
  },
  "network_monitoring": {
    "interface": "eth0",
    "interval": 30
  },
  "logstash": {
    "host": "192.168.100.66",
    "port": 5044
  }
}
EOF
```

### 3.4 Create Worker Scripts

#### log_collector_service.py
```bash
cat > ~/security-solution-worker/scripts/log_collector_service.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import time
import socket

from datetime import datetime
import paramiko

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/log_collector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import message_queue client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from message_queue import MessageClient
except ImportError:
    logger.error("Failed to import MessageClient, make sure message_queue.py is in the same directory")
    sys.exit(1)

def collect_logs(config):
    """Collect logs from configured sources."""
    logger.info("Collecting logs from configured sources")
    
    collected_logs = []
    hostname = socket.gethostname()
    
    for source in config['log_collection']['sources']:
        path = source['path']
        log_type = source['type']
        
        try:
            # Check if file exists and is accessible
            if not os.path.isfile(path):
                logger.warning(f"Log file {path} does not exist or is not accessible")
                continue
                
            # Read last 100 lines (adjust as needed)
            with open(path, 'r') as f:
                # Go to the end of the file
                f.seek(0, 2)
                file_size = f.tell()
                
                # If file is empty, skip
                if file_size == 0:
                    logger.info(f"Log file {path} is empty")
                    continue
                    
                # Read the last 10KB of the file (adjust as needed)
                bytes_to_read = min(10 * 1024, file_size)
                f.seek(file_size - bytes_to_read, 0)
                
                # Read until the end of the current line
                if bytes_to_read < file_size:
                    f.readline()
                    
                # Read the remaining lines
                lines = f.readlines()
                
                # Process the last 100 lines
                for line in lines[-100:]:
                    log_entry = {
                        '@timestamp': datetime.now().isoformat(),
                        'host': hostname,
                        'log_type': log_type,
                        'source': path,
                        'message': line.strip()
                    }
                    collected_logs.append(log_entry)
                    
            logger.info(f"Collected {len(lines[-100:])} log entries from {path}")
                
        except Exception as e:
            logger.error(f"Error collecting logs from {path}: {e}")
            
    return collected_logs

def send_logs_to_server(client, logs):
    """Send collected logs to the server."""
    if not logs:
        logger.info("No logs to send")
        return
        
    logger.info(f"Sending {len(logs)} logs to server")
    
    try:
        response = client.send_data({
            'type': 'logs',
            'logs': logs,
            'timestamp': datetime.now().isoformat()
        })
        
        if response.get('status') == 'success':
            logger.info("Logs sent successfully")
        else:
            logger.error(f"Failed to send logs: {response.get('message')}")
            
    except Exception as e:
        logger.error(f"Error sending logs to server: {e}")

def save_logs_to_file(logs, directory="data"):
    """Save collected logs to a local file."""
    if not logs:
        return
        
    logger.info(f"Saving {len(logs)} logs to local file")
    
    os.makedirs(directory, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(directory, f"logs_{timestamp}.json")
    
    try:
        with open(filename, 'w') as f:
            json.dump(logs, f, indent=2)
        logger.info(f"Logs saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving logs to file: {e}")

def send_logs_to_logstash(logs, config):
    """Send logs directly to Logstash."""
    if not logs:
        return
        
    logger.info(f"Sending {len(logs)} logs to Logstash")
    
    try:
        # Import here to avoid requiring it if not used
        from logstash import TCPLogstashHandler
        
        # Create a logstash handler
        logstash_handler = logging.getLogger('logstash')
        logstash_handler.setLevel(logging.INFO)
        logstash_handler.addHandler(
            TCPLogstashHandler(
                config['logstash']['host'],
                config['logstash']['port'],
                version=1
            )
        )
        
        # Send each log entry to Logstash
        for log in logs:
            logstash_handler.info(json.dumps(log))
            
        logger.info("Logs sent to Logstash successfully")
        
    except Exception as e:
        logger.error(f"Error sending logs to Logstash: {e}")

def run_log_collector_service(config_path):
    """Run the log collector service."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to message queue
        client = MessageClient(
            config['server']['host'],
            config['server']['port'],
            config['worker_id'],
            config['worker_type']
        )
        
        connected = client.connect()
        if not connected:
            logger.error("Failed to connect to message queue, continuing in standalone mode")
            
        # Start heartbeat thread if connected
        if connected:
            client.start_heartbeat_thread()
            
        logger.info("Log collector service started")
        
        # Main collection loop
        while True:
            try:
                # Collect logs
                logs = collect_logs(config)
                
                # Save locally
                save_logs_to_file(logs)
                
                # Send to server if connected
                if connected:
                    send_logs_to_server(client, logs)
                    
                # Send to Logstash if configured
                if 'logstash' in config:
                    send_logs_to_logstash(logs, config)
                    
            except Exception as e:
                logger.error(f"Error in log collection cycle: {e}")
                
            # Sleep until next collection cycle
            interval = config['log_collection'].get('interval', 60)
            logger.info(f"Log collection cycle completed, sleeping for {interval} seconds")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        logger.info("Log collector service shutting down")
        if 'client' in locals() and connected:
            client.disconnect()
    except Exception as e:
        logger.error(f"Error in log collector service: {e}")
        if 'client' in locals() and connected:
            client.disconnect()
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Collector Service")
    parser.add_argument("--config", type=str, default="config/worker_config.json",
                      help="Path to the configuration file")
    
    args = parser.parse_args()
    run_log_collector_service(args.config)
EOF
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

Install and configure Filebeat by following the instructions in the ELK_CONF copy.md file.

#### Configure Filebeat for Custom Logs
```bash
sudo nano /etc/filebeat/filebeat.yml
```

Replace the contents with:
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

#### Configure Auditbeat for System Audit
```bash
sudo nano /etc/auditbeat/auditbeat.yml
```

Update the outputs section:
```yaml
output.logstash:
  hosts: ["192.168.100.66:5044"]
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
```

### 4.3 Create Worker Configuration

```bash
# Create worker configuration file
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
      "hosts": ["192.168.100.66:9200"],
      "vulnerabilities_index": "security-vulnerabilities",
      "compliance_index": "security-compliance"
    }
  }
}
EOF
```

### 4.4 Create Worker Scripts

#### vulnerability_scanner_service.py
```bash
# Create the file with the organized structure
cat > ~/security-solution-worker/scripts/vulnerability_scanner_service.py << 'EOF'
#!/usr/bin/env python3
"""
Vulnerability Scanner Service for AI-Driven Security Solution

This service performs automated vulnerability scanning on specified targets
and sends results to both Elasticsearch and the central server via message queue.
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

import nmap
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

#######################
# LOGGING CONFIGURATION
#######################
# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/vulnerability_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import message_queue client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from message_queue import MessageClient
except ImportError:
    logger.error("Failed to import MessageClient, make sure message_queue.py is in the same directory")
    sys.exit(1)

#######################
# ELASTICSEARCH FUNCTIONS
#######################
def connect_to_elasticsearch(config):
    """Connect to Elasticsearch.
    
    Args:
        config: Configuration dictionary containing ELK settings
        
    Returns:
        Elasticsearch client object or None if connection fails
    """
    if 'elk' not in config:
        logger.warning("ELK configuration not found")
        return None
        
    hosts = config['elk']['elasticsearch']['hosts']
    logger.info(f"Connecting to Elasticsearch at {hosts}")
    
    try:
        es = Elasticsearch(hosts=hosts)
        logger.info("Connected to Elasticsearch successfully")
        return es
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        return None

def index_vulnerabilities(es, vulnerabilities, index_name):
    """Index vulnerabilities to Elasticsearch.
    
    Args:
        es: Elasticsearch client
        vulnerabilities: List of vulnerability dictionaries
        index_name: Name of the Elasticsearch index
    """
    if not vulnerabilities:
        logger.info("No vulnerabilities to index")
        return
        
    logger.info(f"Indexing {len(vulnerabilities)} vulnerabilities to {index_name}")
    
    try:
        # Prepare bulk actions
        actions = []
        for vuln in vulnerabilities:
            actions.append({
                "_index": index_name,
                "_source": vuln
            })
            
        # Use bulk API
        success, errors = bulk(es, actions, refresh=True)
        
        logger.info(f"Successfully indexed {success} vulnerabilities, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing vulnerabilities to Elasticsearch: {e}")

#######################
# SCANNING FUNCTIONS
#######################
def scan_vulnerabilities(config):
    """Scan targets for vulnerabilities.
    
    Args:
        config: Configuration dictionary containing scan targets
        
    Returns:
        List of vulnerability dictionaries
    """
    logger.info("Starting vulnerability scan")
    
    nm = nmap.PortScanner()
    vulnerabilities = []
    scan_timestamp = datetime.now().isoformat()
    
    for target in config['vulnerability_scanning']['targets']:
        host = target['host']
        ports = target.get('ports', '1-1024')
        
        logger.info(f"Scanning host {host} (ports {ports})")
        
        try:
            # Run a service detection scan with version detection
            nm.scan(hosts=host, arguments=f'-sV -p {ports}')
            
            for scanned_host in nm.all_hosts():
                host_name = nm[scanned_host].hostname() or scanned_host
                
                for proto in nm[scanned_host].all_protocols():
                    lport = list(nm[scanned_host][proto].keys())
                    
                    for port in lport:
                        service = nm[scanned_host][proto][port]
                        
                        # Calculate vulnerability score based on service information
                        vuln_score = 0.0
                        severity = "info"
                        
                        # Detect if service has version info (potential vulnerability)
                        if service['version']:
                            vuln_score += 0.3
                            severity = "low"
                        
                        # Detect if service is typically dangerous when exposed
                        risky_services = ['ftp', 'telnet', 'rsh', 'rlogin', 'rexec', 'tftp']
                        if service['name'] in risky_services:
                            vuln_score += 0.4
                            severity = "medium"
                        
                        # Detect if running as root (port < 1024)
                        if int(port) < 1024:
                            vuln_score += 0.1
                        
                        # Create vulnerability record
                        vulnerability = {
                            '@timestamp': scan_timestamp,
                            'host': host_name,
                            'ip': scanned_host,
                            'port': port,
                            'protocol': proto,
                            'service': service['name'],
                            'product': service['product'],
                            'version': service['version'],
                            'severity': severity,
                            'vulnerability_score': vuln_score,
                            'description': f"Open port {port}/{proto} running {service['name']} {service['product']} {service['version']}",
                            'source': "AI-Driven Security Solution"
                        }
                        
                        vulnerabilities.append(vulnerability)
                        
                logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities on {host_name}")
                        
        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")
            
    return vulnerabilities

#######################
# DATA HANDLING FUNCTIONS
#######################
def save_vulnerabilities_to_file(vulnerabilities, directory="data"):
    """Save vulnerabilities to a local file.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        directory: Directory to save the file
    """
    if not vulnerabilities:
        return
        
    logger.info(f"Saving {len(vulnerabilities)} vulnerabilities to local file")
    
    os.makedirs(directory, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(directory, f"vulnerabilities_{timestamp}.json")
    
    try:
        with open(filename, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        logger.info(f"Vulnerabilities saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving vulnerabilities to file: {e}")

def send_vulnerabilities_to_server(client, vulnerabilities):
    """Send vulnerabilities to the server via message queue.
    
    Args:
        client: MessageClient object
        vulnerabilities: List of vulnerability dictionaries
    """
    if not vulnerabilities:
        logger.info("No vulnerabilities to send")
        return
        
    logger.info(f"Sending {len(vulnerabilities)} vulnerabilities to server")
    
    try:
        response = client.send_data({
            'type': 'vulnerabilities',
            'vulnerabilities': vulnerabilities,
            'timestamp': datetime.now().isoformat()
        })
        
        if response.get('status') == 'success':
            logger.info("Vulnerabilities sent successfully")
        else:
            logger.error(f"Failed to send vulnerabilities: {response.get('message')}")
            
    except Exception as e:
        logger.error(f"Error sending vulnerabilities to server: {e}")

#######################
# MAIN SERVICE FUNCTION
#######################
def run_vulnerability_scanner_service(config_path):
    """Run the vulnerability scanner service.
    
    Args:
        config_path: Path to the configuration file
    """
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to message queue
        client = MessageClient(
            config['server']['host'],
            config['server']['port'],
            config['worker_id'],
            config['worker_type']
        )
        
        connected = client.connect()
        if not connected:
            logger.error("Failed to connect to message queue, continuing in standalone mode")
            
        # Start heartbeat thread if connected
        if connected:
            client.start_heartbeat_thread()
            
        # Connect to Elasticsearch
        es = connect_to_elasticsearch(config)
            
        logger.info("Vulnerability scanner service started")
        
        # Check if we should run once (for testing)
        run_once = '--scan-now' in sys.argv
        
        # Main scanning loop
        while True:
            try:
                # Scan for vulnerabilities
                vulnerabilities = scan_vulnerabilities(config)
                
                # Save locally
                save_vulnerabilities_to_file(vulnerabilities)
                
                # Send to server if connected
                if connected:
                    send_vulnerabilities_to_server(client, vulnerabilities)
                    
                # Index to Elasticsearch if connected
                if es is not None:
                    index_vulnerabilities(
                        es,
                        vulnerabilities,
                        config['elk']['elasticsearch']['vulnerabilities_index']
                    )
                    
                # Exit if running once
                if run_once:
                    logger.info("Scan completed, exiting (--scan-now was specified)")
                    break
                    
            except Exception as e:
                logger.error(f"Error in vulnerability scanning cycle: {e}")
                
            # Sleep until next scan cycle
            interval = config['vulnerability_scanning'].get('interval', 3600)
            logger.info(f"Vulnerability scanning cycle completed, sleeping for {interval} seconds")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        logger.info("Vulnerability scanner service shutting down")
        if 'client' in locals() and connected:
            client.disconnect()
    except Exception as e:
        logger.error(f"Error in vulnerability scanner service: {e}")
        if 'client' in locals() and connected:
            client.disconnect()
        raise

#######################
# ENTRY POINT
#######################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Scanner Service")
    parser.add_argument("--config", type=str, default="config/worker_config.json",
                      help="Path to the configuration file")
    parser.add_argument("--scan-now", action="store_true",
                      help="Run a scan immediately and exit")
    
    args = parser.parse_args()
    run_vulnerability_scanner_service(args.config)
EOF


```

#### compliance_checker.py
```bash
cat > ~/security-solution-worker/scripts/compliance_checker.py << 'EOF'
import argparse
import json
import logging
import os
import sys
import subprocess
import time
from datetime import datetime

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/compliance_checker.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import message_queue client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from message_queue import MessageClient
except ImportError:
    logger.error("Failed to import MessageClient, make sure message_queue.py is in the same directory")
    sys.exit(1)

def connect_to_elasticsearch(config):
    """Connect to Elasticsearch."""
    if 'elk' not in config:
        logger.warning("ELK configuration not found")
        return None
        
    hosts = config['elk']['elasticsearch']['hosts']
    logger.info(f"Connecting to Elasticsearch at {hosts}")
    
    try:
        es = Elasticsearch(hosts=hosts)
        logger.info("Connected to Elasticsearch successfully")
        return es
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        return None

def run_compliance_checks(config):
    """Run compliance checks based on configuration."""
    logger.info("Running compliance checks")
    
    compliance_results = []
    hostname = os.uname().nodename
    check_timestamp = datetime.now().isoformat()
    
    for framework, checks in config['compliance']['frameworks'].items():
        logger.info(f"Running compliance checks for framework: {framework}")
        
        for check in checks:
            check_name = check['name']
            command = check['command']
            
            logger.info(f"Running check: {check_name}")
            
            try:
                # Run the compliance check command
                result = subprocess.run(
                    command.split(),
                    capture_output=True,
                    text=True
                )
                
                # Determine status (PASS/FAIL)
                if result.returncode == 0:
                    status = "PASS"
                else:
                    status = "FAIL"
                    
                # Create compliance result record
                compliance_result = {
                    '@timestamp': check_timestamp,
                    'host': hostname,
                    'framework': framework,
                    'check_name': check_name,
                    'command': command,
                    'status': status,
                    'output': result.stdout[:1000],  # Limit output size
                    'error': result.stderr[:1000] if result.stderr else "",
                    'source': "AI-Driven Security Solution"
                }
                
                compliance_results.append(compliance_result)
                logger.info(f"Check {check_name} completed with status: {status}")
                
            except Exception as e:
                logger.error(f"Error running check {check_name}: {e}")
                
    return compliance_results

def index_compliance_results(es, compliance_results, index_name):
    """Index compliance results to Elasticsearch."""
    if not compliance_results:
        logger.info("No compliance results to index")
        return
        
    logger.info(f"Indexing {len(compliance_results)} compliance results to {index_name}")
    
    try:
        # Prepare bulk actions
        actions = []
        for result in compliance_results:
            actions.append({
                "_index": index_name,
                "_source": result
            })
            
        # Use bulk API
        success, errors = bulk(es, actions, refresh=True)
        
        logger.info(f"Successfully indexed {success} compliance results, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing compliance results to Elasticsearch: {e}")

def save_compliance_results_to_file(compliance_results, directory="data"):
    """Save compliance results to a local file."""
    if not compliance_results:
        return
        
    logger.info(f"Saving {len(compliance_results)} compliance results to local file")
    
    os.makedirs(directory, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(directory, f"compliance_results_{timestamp}.json")
    
    try:
        with open(filename, 'w') as f:
            json.dump(compliance_results, f, indent=2)
        logger.info(f"Compliance results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving compliance results to file: {e}")

def send_compliance_results_to_server(client, compliance_results):
    """Send compliance results to the server via message queue."""
    if not compliance_results:
        logger.info("No compliance results to send")
        return
        
    logger.info(f"Sending {len(compliance_results)} compliance results to server")
    
    try:
        response = client.send_data({
            'type': 'compliance_results',
            'compliance_results': compliance_results,
            'timestamp': datetime.now().isoformat()
        })
        
        if response.get('status') == 'success':
            logger.info("Compliance results sent successfully")
        else:
            logger.error(f"Failed to send compliance results: {response.get('message')}")
            
    except Exception as e:
        logger.error(f"Error sending compliance results to server: {e}")

def run_compliance_checker_service(config_path):
    """Run the compliance checker service."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to message queue
        client = MessageClient(
            config['server']['host'],
            config['server']['port'],
            config['worker_id'],
            config['worker_type']
        )
        
        connected = client.connect()
        if not connected:
            logger.error("Failed to connect to message queue, continuing in standalone mode")
            
        # Start heartbeat thread if connected
        if connected:
            client.start_heartbeat_thread()
            
        # Connect to Elasticsearch
        es = connect_to_elasticsearch(config)
            
        logger.info("Compliance checker service started")
        
        # Check if we should run once (for testing)
        run_once = '--check-now' in sys.argv
        
        # Main checking loop
        while True:
            try:
                # Run compliance checks
                compliance_results = run_compliance_checks(config)
                
                # Save locally
                save_compliance_results_to_file(compliance_results)
                
                # Send to server if connected
                if connected:
                    send_compliance_results_to_server(client, compliance_results)
                    
                # Index to Elasticsearch if connected
                if es is not None:
                    index_compliance_results(
                        es,
                        compliance_results,
                        config['elk']['elasticsearch']['compliance_index']
                    )
                    
                # Exit if running once
                if run_once:
                    logger.info("Compliance check completed, exiting (--check-now was specified)")
                    break
                    
            except Exception as e:
                logger.error(f"Error in compliance checking cycle: {e}")
                
            # Sleep until next check cycle
            interval = config['compliance'].get('interval', 86400)
            logger.info(f"Compliance checking cycle completed, sleeping for {interval} seconds")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        logger.info("Compliance checker service shutting down")
        if 'client' in locals() and connected:
            client.disconnect()
    except Exception as e:
        logger.error(f"Error in compliance checker service: {e}")
        if 'client' in locals() and connected:
            client.disconnect()
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compliance Checker Service")
    parser.add_argument("--config", type=str, default="config/worker_config.json",
                      help="Path to the configuration file")
    parser.add_argument("--check-now", action="store_true",
                      help="Run a compliance check immediately and exit")
    
    args = parser.parse_args()
    run_compliance_checker_service(args.config)
EOF
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

Install and configure Metricbeat and Packetbeat by following the instructions in the ELK_CONF copy.md file.

## 5. Starting and Testing the System

### 5.1 Start Services on Server VM

```bash
# Start the ELK stack (if not already running)
sudo systemctl start elasticsearch
sudo systemctl start logstash
sudo systemctl start kibana

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
cat > ~/security-solution/scripts/backup_config.sh << 'EOF'
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