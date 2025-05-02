import argparse
import json
import logging
import os
import time

from logstash import TCPLogstashHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_to_logstash(config):
    handler = TCPLogstashHandler(host=config['logstash']['host'], port=config['logstash']['port'], version=1)
    logger.info(f"Connected to Logstash at {config['logstash']['host']}:{config['logstash']['port']}")
    return handler

def collect_logs(config, logstash_handler):
    for source in config['log_collection']['sources']:
        with open(source['path'], 'r') as f:
            logs = f.readlines()
        
        for log in logs:
            log_data = {
                'message': log,
                'type': source['type'],
                'source': source['path']
            }
            logstash_handler.emit(log_data)
        
        logger.info(f"Collected {len(logs)} logs from {source['path']}")

def run_log_collector(config):
    logstash_handler = connect_to_logstash(config)
    
    while True:
        collect_logs(config, logstash_handler)
        logger.info(f"Log collection completed. Sleeping for {config['log_collection']['interval']} seconds...")
        time.sleep(config['log_collection']['interval'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/worker_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_log_collector(config)