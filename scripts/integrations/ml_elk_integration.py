import argparse
import json
import logging
import os

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