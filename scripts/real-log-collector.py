import argparse
import json
import logging
import os
import time

import paramiko

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def collect_local_logs(config):
    for log_source in config['local_files']:
        with open(log_source['path'], 'r') as f:
            logs = f.readlines()
        
        output_path = os.path.join(config['output']['directory'], f"{log_source['type']}.json")
        with open(output_path, 'w') as f:
            json.dump(logs, f)
        
        logger.info(f"Collected {len(logs)} logs from {log_source['path']}")

def collect_remote_logs(config):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for host in config['ssh_remote']['hosts']:
        ssh_client.connect(hostname=host, username=config['ssh_remote']['user'], key_filename=config['ssh_remote']['key_file'])
        
        for log_source in config['ssh_remote']['logs']:
            sftp_client = ssh_client.open_sftp()
            with sftp_client.open(log_source['path'], 'r') as f:
                logs = f.readlines()
            
            output_path = os.path.join(config['output']['directory'], f"{host}_{log_source['type']}.json")
            with open(output_path, 'w') as f:
                json.dump(logs, f)
            
            logger.info(f"Collected {len(logs)} logs from {host}:{log_source['path']}")
            
        ssh_client.close()

def run_log_collection(config):
    while True:
        collect_local_logs(config)
        collect_remote_logs(config)
        
        logger.info(f"Log collection completed. Sleeping for {config['collection_interval']} seconds...")
        time.sleep(config['collection_interval'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/log_sources.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_log_collection(config)