import argparse
import json
import logging
import os
import subprocess
import time

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_to_elasticsearch(config):
    es = Elasticsearch(hosts=config['elasticsearch']['hosts'])
    logger.info(f"Connected to Elasticsearch at {config['elasticsearch']['hosts']}")
    return es

def run_compliance_checks(config):
    for framework, checks in config['compliance']['frameworks'].items():
        for check in checks:
            command = check['command'].split()
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                status = 'PASS'
            else:
                status = 'FAIL'
            
            compliance_result = {
                'framework': framework,
                'check_name': check['name'],
                'command': check['command'],
                'status': status,
                'output': result.stdout
            }
            yield compliance_result

def index_compliance_results(es, compliance_results, index_name):
    actions = [
        {
            "_index": index_name,
            "_source": compliance_result
        }
        for compliance_result in compliance_results
    ]
    
    bulk(es, actions)
    logger.info(f"Indexed {len(actions)} compliance results into {index_name}")

def run_compliance_checker(config):
    es = connect_to_elasticsearch(config['elk'])
    
    while True:
        compliance_results = run_compliance_checks(config) 
        index_compliance_results(es, compliance_results, config['elk']['elasticsearch']['compliance_index'])
        
        logger.info(f"Compliance checking completed. Sleeping for {config['compliance']['interval']} seconds...")
        time.sleep(config['compliance']['interval'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/worker_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_compliance_checker(config)