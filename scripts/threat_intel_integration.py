#!/usr/bin/env python3
"""
Threat intelligence integration for the AI-Driven Security Solution.
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
import requests
from elasticsearch import Elasticsearch

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/threat_intel_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_threat_intelligence(config):
    """Load threat intelligence from configured sources."""
    logger.info("Loading threat intelligence")
    
    intel = {
        'ip': [],
        'domain': [],
        'url': [],
        'hash': []
    }
    
    for source in config['sources']:
        logger.info(f"Loading threat intelligence from {source['name']}")
        
        try:
            if source['type'] == 'file':
                # Load from local file
                if os.path.exists(source['path']):
                    with open(source['path']) as f:
                        data = json.load(f)
                    
                    # Process based on format
                    if source['format'] == 'json':
                        for indicator_type, indicators in data.items():
                            if indicator_type in intel:
                                intel[indicator_type].extend(indicators)
                                
                    logger.info(f"Loaded threat intelligence from {source['path']}")
                else:
                    logger.warning(f"Threat intelligence source file {source['path']} does not exist")
                    
            elif source['type'] == 'api':
                # Load from remote API
                response = requests.get(
                    source['url'],
                    headers=source.get('headers', {}),
                    params=source.get('params', {}),
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Process based on the API format
                    # This is a simplified example - actual processing depends on the API
                    for item in data.get('indicators', []):
                        indicator_type = item.get('type')
                        value = item.get('value')
                        
                        if indicator_type in intel and value:
                            intel[indicator_type].append(value)
                            
                    logger.info(f"Loaded threat intelligence from API {source['url']}")
                else:
                    logger.error(f"Error loading threat intelligence from API: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error loading threat intelligence from {source['name']}: {e}")
            
    # Count the indicators
    total = sum(len(indicators) for indicators in intel.values())
    logger.info(f"Loaded {total} threat intelligence indicators: {', '.join(f'{len(intel[t])} {t}' for t in intel)}")
    
    return intel

def save_threat_intel(intel, config):
    """Save threat intelligence to files."""
    logger.info("Saving threat intelligence to files")
    
    for indicator_type, indicators in intel.items():
        if indicators:
            output_path = config['indicators'].get(indicator_type)
            if output_path:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                try:
                    with open(output_path, 'w') as f:
                        json.dump(indicators, f, indent=2)
                    logger.info(f"Saved {len(indicators)} {indicator_type} indicators to {output_path}")
                except Exception as e:
                    logger.error(f"Error saving {indicator_type} indicators to {output_path}: {e}")

def index_threat_intel(es, intel, index_name):
    """Index threat intelligence to Elasticsearch."""
    logger.info(f"Indexing threat intelligence to {index_name}")
    
    docs = []
    timestamp = datetime.now().isoformat()
    
    for indicator_type, indicators in intel.items():
        for indicator in indicators:
            doc = {
                "@timestamp": timestamp,
                "indicator_type": indicator_type,
                "indicator_value": indicator,
                "source": "threat_intel_integration"
            }
            docs.append({
                "_index": index_name,
                "_source": doc
            })
            
    if docs:
        try:
            from elasticsearch.helpers import bulk
            success, errors = bulk(es, docs, refresh=True)
            logger.info(f"Successfully indexed {success} threat intelligence indicators, errors: {errors}")
        except Exception as e:
            logger.error(f"Error indexing threat intelligence: {e}")

def correlate_with_logs(es, intel, config):
    """Correlate threat intelligence with logs."""
    logger.info("Correlating threat intelligence with logs")
    
    # Flatten indicators for easier lookup
    ip_indicators = set(intel['ip'])
    domain_indicators = set(intel['domain'])
    url_indicators = set(intel['url'])
    hash_indicators = set(intel['hash'])
    
    # Query logs from Elasticsearch
    try:
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1d",
                        "lte": "now"
                    }
                }
            },
            "size": 10000
        }
        
        result = es.search(index="filebeat-*", body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} logs for correlation")
        
        # Correlate logs with threat intelligence
        correlations = []
        for hit in hits:
            source = hit['_source']
            message = source.get('message', '')
            
            # Extract potential indicators from the message
            # This is a simplified example - in a real implementation, you would use regex or better parsing
            words = message.split()
            
            for word in words:
                # Check if the word is an IP address that matches threat intel
                if word in ip_indicators:
                    correlations.append({
                        "@timestamp": source.get('@timestamp', datetime.now().isoformat()),
                        "log_id": hit['_id'],
                        "indicator_type": "ip",
                        "indicator_value": word,
                        "log_message": message,
                        "host": source.get('host', '')
                    })
                    
                # Check if the word is a domain that matches threat intel
                elif word in domain_indicators:
                    correlations.append({
                        "@timestamp": source.get('@timestamp', datetime.now().isoformat()),
                        "log_id": hit['_id'],
                        "indicator_type": "domain",
                        "indicator_value": word,
                        "log_message": message,
                        "host": source.get('host', '')
                    })
                    
        logger.info(f"Found {len(correlations)} correlations between logs and threat intelligence")
        
        # Save correlations
        if correlations:
            output_path = os.path.join(
                config.get('output', {}).get('directory', 'results'),
                'threat_intel_correlations.json'
            )
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(correlations, f, indent=2)
                
            # Index correlations to Elasticsearch
            correlation_index = config.get('elk_index', 'security-threat-intel-correlations')
            
            docs = []
            for correlation in correlations:
                docs.append({
                    "_index": correlation_index,
                    "_source": correlation
                })
                
            from elasticsearch.helpers import bulk
            success, errors = bulk(es, docs, refresh=True)
            logger.info(f"Successfully indexed {success} threat intelligence correlations, errors: {errors}")
            
    except Exception as e:
        logger.error(f"Error correlating threat intelligence with logs: {e}")

def run_threat_intel_integration(config_path):
    """Run the threat intelligence integration process."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        
        # Load threat intelligence
        intel = load_threat_intelligence(config)
        
        # Save threat intelligence
        save_threat_intel(intel, config)
        
        # Index threat intelligence
        index_threat_intel(es, intel, config.get('elk_index', 'security-threat-intel'))
        
        # Correlate with logs
        correlate_with_logs(es, intel, config)
        
    except Exception as e:
        logger.error(f"Error in threat intelligence integration: {e}")
        sys.exit(1)

def run_continuous_integration(config_path, interval):
    """Run threat intelligence integration at regular intervals."""
    logger.info(f"Starting continuous threat intelligence integration every {interval} seconds")
    
    while True:
        try:
            run_threat_intel_integration(config_path)
        except Exception as e:
            logger.error(f"Error in threat intelligence integration cycle: {e}")
            
        logger.info(f"Sleeping for {interval} seconds")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence Integration")
    parser.add_argument("--config", type=str, default="config/threat_intelligence.json",
                      help="Path to the configuration file")
    parser.add_argument("--continuous", action="store_true",
                      help="Run in continuous mode")
    parser.add_argument("--interval", type=int, default=3600,
                      help="Integration interval in seconds (for continuous mode)")
                      
    args = parser.parse_args()
    
    if args.continuous:
        run_continuous_integration(args.config, args.interval)
    else:
        run_threat_intel_integration(args.config)