<<<<<<< HEAD

=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
import argparse
import json
import logging
import os
<<<<<<< HEAD
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
=======

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from logstash import TCPLogstashHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_to_elasticsearch(config):
    es = Elasticsearch(hosts=config['elasticsearch']['hosts'])
    logger.info(f"Connected to Elasticsearch at {config['elasticsearch']['hosts']}")
    return es

def connect_to_logstash(config):
    handler = TCPLogstashHandler(host=config['logstash']['host'], port=config['logstash']['port'], version=1)
    logger.info(f"Connected to Logstash at {config['logstash']['host']}:{config['logstash']['port']}")
    return handler

def index_data(es, data, index_name):
    actions = [
        {
            "_index": index_name,
            "_source": record
        }
        for record in data
    ]
    
    bulk(es, actions)
    logger.info(f"Indexed {len(data)} documents into {index_name}")

def send_logs_to_logstash(handler, logs):
    for log in logs:
        handler.emit(log)
    logger.info(f"Sent {len(logs)} logs to Logstash")

def run_ml_elk_integration(config):
    es = connect_to_elasticsearch(config['elk'])
    logstash_handler = connect_to_logstash(config['elk'])

    # Index anomalies
    anomalies = json.load(open(config['data']['anomalies']))
    index_data(es, anomalies, config['elasticsearch']['anomalies_index'])

    # Index risk scores  
    risk_scores = json.load(open(config['data']['risk_scores']))
    index_data(es, risk_scores, config['elasticsearch']['risk_scores_index'])

    # Send logs to Logstash
    logs = json.load(open(config['data']['logs']))
    send_logs_to_logstash(logstash_handler, logs)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/ml_elk_integration_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_ml_elk_integration(config)
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
