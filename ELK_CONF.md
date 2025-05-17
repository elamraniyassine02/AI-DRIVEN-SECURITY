# ELK SIEM Configuration Guide

This guide provides instructions for setting up an ELK (Elasticsearch, Logstash, Kibana) SIEM stack on Kali Linux 2024.4, configured specifically for security monitoring and integration with the AI-driven security solution.

## Architecture Overview

- **Master Node**: Runs Elasticsearch, Logstash, and Kibana
- **Worker Nodes**: Run Filebeat to collect and forward logs

## 1. Master Node Setup (Server VM)

### 1.1 Installing Elasticsearch

```bash
# Import the Elasticsearch GPG Key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Install apt-transport-https
sudo apt-get install apt-transport-https -y

# Add the Elasticsearch APT Repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update package lists and install Elasticsearch
sudo apt-get update && sudo apt-get install elasticsearch -y
```

### 1.2 Configuring Elasticsearch

```bash
# Edit Elasticsearch configuration
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Replace the contents with:

```yaml
# ---------------------------------- Cluster -----------------------------------
cluster.name: security-analytics

# ---------------------------------- Network -----------------------------------
network.host: 0.0.0.0
http.port: 9200

# --------------------------------- Discovery ----------------------------------
discovery.type: single-node

# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# ---------------------------------- Security ---------------------------------
xpack.security.enabled: true
```

Save and exit.

> **Note**: The superuser password will be generated during the first startup. Record it as shown in the console output.

### 1.3 Installing Kibana

```bash
# Install Kibana
sudo apt-get install kibana -y
```

### 1.4 Configuring Kibana

```bash
# Generate an encryption key for Kibana
ENCRYPTION_KEY=$(openssl rand -base64 32 | cut -c1-32)

To see the generated key, run:
echo $ENCRYPTION_KEY

# Edit Kibana configuration
sudo nano /etc/kibana/kibana.yml
```

Replace the contents with:

```yaml
# =================== System: Kibana Server ===================
server.port: 5601
server.host: "0.0.0.0"

# =================== System: Elasticsearch ===================
elasticsearch.hosts: ["http://localhost:9200"]

# =================== Security ===================
xpack.encryptedSavedObjects.encryptionKey: "${ENCRYPTION_KEY}"
```

Save and exit.

### 1.5 Installing Logstash

```bash
# Install Logstash
sudo apt-get install logstash -y
```

### 1.6 Configuring Logstash

```bash
# Create Logstash configuration for security logs
sudo nano /etc/logstash/conf.d/security-logs.conf
```

Add the following content:

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  # Filter for audit logs
  if "auditbeat" in [tags] or "audit" in [tags] {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{DATA:app} %{GREEDYDATA:log}" }
    }
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
  
  # Filter for syslog logs
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGLINE}" }
    }
    date {
      match => [ "timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }

  # Filter for Apache logs
  if [type] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    date {
      match => ["timestamp", "dd/MMM/yyyy:HH:mm:ss Z"]
    }
  }

  # Filter for Auditbeat logs (module auditd)
  if [event.module] == "auditd" {
    mutate {
      add_tag => ["auditbeat"]
    }
  }
}

output {
  # Output for Elasticsearch using dynamic indices based on the type of beat
  if "auditbeat" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "auditbeat-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "${ELASTIC_PASSWORD}"
    }
  } else if [type] == "syslog" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "syslog-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "${ELASTIC_PASSWORD}"
    }
  } else if [type] == "apache" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "apache-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "${ELASTIC_PASSWORD}"
    }
  } else {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "${ELASTIC_PASSWORD}"
    }
  }
}
```

Save and exit.

### 1.7 Starting and Enabling ELK Services

```bash
# Start and enable Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Wait for Elasticsearch to start (this can take a minute or two)
echo "Waiting for Elasticsearch to start..."
sleep 60

# Get the auto-generated elastic user password
echo "Note the Elasticsearch superuser password below:"
sudo cat /var/lib/elasticsearch/elasticsearch.keystore

# Set the password as an environment variable for Logstash
echo "ELASTIC_PASSWORD=YOUR_PASSWORD_HERE" | sudo tee -a /etc/environment
source /etc/environment

# Start and enable Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Start and enable Logstash
sudo systemctl enable logstash
sudo systemctl start logstash

# Check status of all services
sudo systemctl status elasticsearch
sudo systemctl status kibana
sudo systemctl status logstash
```
openssl rand -base64 32 | cut -c1-32


## 2. Worker Node Setup (Log Collection)

### 2.1 Installing Filebeat

```bash
# Import the Elasticsearch GPG Key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Install apt-transport-https
sudo apt-get install apt-transport-https -y

# Add the Elasticsearch APT Repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update package lists and install Filebeat
sudo apt-get update && sudo apt-get install filebeat -y
```

### 2.2 Configuring Filebeat

```bash
# Edit Filebeat configuration
sudo nano /etc/filebeat/filebeat.yml
```

Replace the contents with:

```yaml
filebeat.inputs:
- type: filestream
  id: syslog-filestream
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/auth.log
  tags: ["syslog"]

- type: filestream
  id: audit-filestream
  enabled: true
  paths:
    - /var/log/audit/audit.log
  tags: ["audit"]

- type: filestream
  id: apache-filestream
  enabled: true
  paths:
    - /var/log/apache2/*.log
  tags: ["apache"]

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

# ------------------------------ Logstash Output -------------------------------
output.logstash:
  # The Logstash hosts - Replace with your Master node IP
  hosts: ["10.12.72.84:5044"]

# ================================= Processors =================================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
```

### 2.3 Starting and Enabling Filebeat

```bash
# Start and enable Filebeat
sudo systemctl daemon-reload
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

## 3. Integration with AI Security Solution

### 3.1 Creating the ML-ELK Integration Script

On the Server VM, create the ML-ELK integration script:

```bash
# Navigate to the scripts/integrations directory
cd ~/security-solution/scripts/integrations/

# Create the integration script
sudo nano ml_elk_integration.py
```

Add the following content:

```python
#!/usr/bin/env python3
"""
ML-ELK Integration Script

This script connects the AI-driven security solution with the ELK stack by:
1. Fetching security events from Elasticsearch
2. Processing them through ML models
3. Writing results back to Elasticsearch for visualization

Usage: python3 ml_elk_integration.py --config /path/to/elk_config.json
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timedelta
import pandas as pd
from elasticsearch import Elasticsearch

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import anomaly_detection
import threat_classification
import risk_scoring

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logs/ml_elk_integration.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ml_elk_integration')

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='ML-ELK Integration Script')
    parser.add_argument('--config', required=True, help='Path to ELK configuration file')
    return parser.parse_args()

def load_config(config_path):
    """Load configuration from file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        sys.exit(1)

def connect_to_elasticsearch(config):
    """Connect to Elasticsearch using the configuration."""
    try:
        es = Elasticsearch(
            [f"http://{config['elasticsearch']['host']}:{config['elasticsearch']['port']}"],
            basic_auth=(config['elasticsearch']['username'], config['elasticsearch']['password'])
        )
        if not es.ping():
            raise ValueError("Connection failed")
        return es
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        return None

def fetch_security_events(es, config, time_range_minutes=60):
    """Fetch security events from Elasticsearch."""
    try:
        now = datetime.now()
        time_from = now - timedelta(minutes=time_range_minutes)
        
        indices = config['elasticsearch']['indices']
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_from.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": config['elasticsearch']['batch_size']
        }
        
        results = []
        for index in indices:
            response = es.search(index=index, body=query)
            for hit in response['hits']['hits']:
                results.append(hit['_source'])
        
        return pd.DataFrame(results) if results else None
    except Exception as e:
        logger.error(f"Failed to fetch security events: {e}")
        return None

def process_with_ml_models(df, config):
    """Process the data with ML models."""
    try:
        if df is None or df.empty:
            logger.info("No data to process")
            return None
        
        # Preprocess the data for ML models
        # This is a simplified example - actual implementation would depend on your models
        processed_data = df.copy()
        
        # Run anomaly detection
        if 'anomaly_detection' in config['ml_models']:
            anomaly_results = anomaly_detection.detect_anomalies(
                processed_data, 
                contamination=config['ml_models']['anomaly_detection'].get('contamination', 0.05)
            )
            processed_data['anomaly_score'] = anomaly_results['scores']
            processed_data['is_anomaly'] = anomaly_results['is_anomaly']
        
        # Run threat classification
        if 'threat_classification' in config['ml_models']:
            threat_results = threat_classification.classify_threats(
                processed_data
            )
            processed_data['threat_category'] = threat_results['category']
            processed_data['threat_probability'] = threat_results['probability']
        
        # Calculate risk scores
        if 'risk_scoring' in config['ml_models']:
            risk_results = risk_scoring.calculate_risk_scores(
                processed_data, 
                weights=config['ml_models']['risk_scoring'].get('weights', {})
            )
            processed_data['risk_score'] = risk_results['risk_score']
            processed_data['risk_level'] = risk_results['risk_level']
        
        return processed_data
    except Exception as e:
        logger.error(f"Failed to process data with ML models: {e}")
        return None

def write_results_to_elasticsearch(es, df, config):
    """Write ML results back to Elasticsearch."""
    try:
        if df is None or df.empty:
            logger.info("No results to write to Elasticsearch")
            return
        
        # Convert dataframe to list of dictionaries
        records = df.to_dict(orient='records')
        
        # Add timestamp and metadata
        now = datetime.now().isoformat()
        for record in records:
            record['ml_processed_at'] = now
            record['ml_version'] = config['ml_models'].get('version', '1.0.0')
        
        # Write to Elasticsearch using bulk API
        bulk_data = []
        for record in records:
            # Prepare bulk action
            action = {
                "index": {
                    "_index": config['elasticsearch']['output_index'],
                }
            }
            bulk_data.append(action)
            bulk_data.append(record)
        
        if bulk_data:
            es.bulk(body=bulk_data)
            logger.info(f"Successfully wrote {len(records)} records to Elasticsearch")
    except Exception as e:
        logger.error(f"Failed to write results to Elasticsearch: {e}")

def main():
    """Main function."""
    args = parse_args()
    config = load_config(args.config)
    
    # Connect to Elasticsearch
    es = connect_to_elasticsearch(config)
    if not es:
        sys.exit(1)
    
    logger.info("Starting ML-ELK integration process")
    
    while True:
        try:
            # Fetch security events
            df = fetch_security_events(es, config, config['processing']['time_range_minutes'])
            
            # Process with ML models
            results_df = process_with_ml_models(df, config)
            
            # Write results back to Elasticsearch
            write_results_to_elasticsearch(es, results_df, config)
            
            # Sleep for the configured interval
            logger.info(f"Sleeping for {config['processing']['interval_seconds']} seconds")
            time.sleep(config['processing']['interval_seconds'])
        except KeyboardInterrupt:
            logger.info("Process interrupted by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(60)  # Sleep for a minute before retrying

if __name__ == "__main__":
    main()
```

### 3.2 Creating ELK Configuration for ML Integration

```bash
# Create the ELK configuration directory if it doesn't exist
mkdir -p ~/security-solution/config

# Create the ELK configuration file
sudo nano ~/security-solution/config/elk_config.json
```

Add the following content:

```json
{
    "elasticsearch": {
        "host": "localhost",
        "port": 9200,
        "username": "elastic",
        "password": "YOUR_ELASTIC_PASSWORD",
        "indices": [
            "auditbeat-*",
            "filebeat-*",
            "syslog-*"
        ],
        "output_index": "security-ml-results",
        "batch_size": 1000
    },
    "kibana": {
        "host": "localhost",
        "port": 5601
    },
    "processing": {
        "time_range_minutes": 60,
        "interval_seconds": 300
    },
    "ml_models": {
        "version": "1.0.0",
        "anomaly_detection": {
            "contamination": 0.05,
            "algorithm": "isolation_forest"
        },
        "threat_classification": {
            "model_path": "/home/kali/security-solution/models/threat_classifier.pkl"
        },
        "risk_scoring": {
            "weights": {
                "anomaly": 0.4,
                "threat": 0.4,
                "vulnerability": 0.2
            }
        }
    }
}
```

### 3.3 Creating a Systemd Service for ML-ELK Integration

```bash
# Create a systemd service for the ML-ELK integration
sudo tee /etc/systemd/system/security-solution-elk-integration.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution ELK Integration
After=network.target elasticsearch.service logstash.service
Requires=elasticsearch.service

[Service]
User=kali
WorkingDirectory=/home/kali/security-solution
ExecStart=/home/kali/security-solution/venv/bin/python /home/kali/security-solution/scripts/integrations/ml_elk_integration.py --config /home/kali/security-solution/config/elk_config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable security-solution-elk-integration.service
sudo systemctl start security-solution-elk-integration.service
```

## 4. Kibana Dashboard Setup

### 4.1 Accessing Kibana

Access Kibana through a web browser:

```
http://10.12.72.84:5601
```

Use the credentials:
- Username: `elastic`
- Password: [The password generated during Elasticsearch installation]

### 4.2 Index Pattern Creation

1. Navigate to Stack Management > Index Patterns
2. Create index patterns for:
   - `auditbeat-*`
   - `filebeat-*`
   - `syslog-*`
   - `security-ml-results`

### 4.3 Creating Security Dashboards

1. Navigate to Dashboard
2. Create the following dashboards:
   - Security Overview
   - Anomaly Detection Results
   - Threat Classification
   - Risk Assessment

## 5. Maintenance and Troubleshooting

### 5.1 Log Rotation

Configure log rotation for ELK components:

```bash
sudo nano /etc/logrotate.d/elk-stack
```

Add the following content:

```
/var/log/elasticsearch/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 elasticsearch elasticsearch
}

/var/log/kibana/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 kibana kibana
}

/var/log/logstash/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 logstash logstash
}
```

### 5.2 Common Troubleshooting Commands

Check Elasticsearch status:
```bash
curl -u elastic:YOUR_PASSWORD http://localhost:9200/_cluster/health?pretty
```

View Elasticsearch logs:
```bash
sudo tail -f /var/log/elasticsearch/security-analytics.log
```

Check Logstash pipeline status:
```bash
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/
```

View Filebeat logs:
```bash
sudo tail -f /var/log/filebeat/filebeat
```

Restart all services:
```bash
sudo systemctl restart elasticsearch kibana logstash
# On worker nodes:
sudo systemctl restart filebeat
```