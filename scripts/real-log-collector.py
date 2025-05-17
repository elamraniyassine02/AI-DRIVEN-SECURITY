<<<<<<< HEAD
#!/usr/bin/env python3
"""
Comprehensive log collector for the AI-Driven Security Solution.
"""
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
import paramiko
import subprocess

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/real_log_collector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def collect_local_logs(config):
    """Collect logs from local files."""
    logger.info("Collecting logs from local files")
    
    logs = []
    for log_source in config['local_files']:
        path = log_source['path']
        log_type = log_source['type']
        
        logger.info(f"Collecting logs from {path} of type {log_type}")
        
        try:
            if os.path.isfile(path):
                with open(path, 'r') as f:
                    # Go to the end of the file
                    f.seek(0, 2)
                    file_size = f.tell()
                    
                    # Read the last 10KB of the file
                    bytes_to_read = min(10 * 1024, file_size)
                    f.seek(file_size - bytes_to_read, 0)
                    
                    # Read to the end of the current line if we're in the middle
                    if bytes_to_read < file_size:
                        f.readline()
                        
                    # Read the remaining lines
                    lines = f.readlines()
                    
                    for line in lines:
                        logs.append({
                            '@timestamp': datetime.now().isoformat(),
                            'message': line.strip(),
                            'log_type': log_type,
                            'source': path,
                            'host': os.uname().nodename
                        })
                        
                logger.info(f"Collected {len(lines)} log entries from {path}")
            else:
                logger.warning(f"Log file {path} does not exist")
                
        except Exception as e:
            logger.error(f"Error collecting logs from {path}: {e}")
            
    return logs

def collect_remote_logs(config):
    """Collect logs from remote hosts via SSH."""
    logger.info("Collecting logs from remote hosts")
    
    logs = []
    for host in config['ssh_remote']['hosts']:
        logger.info(f"Connecting to remote host {host}")
        
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh_client.connect(
                hostname=host,
                username=config['ssh_remote']['user'],
                key_filename=config['ssh_remote']['key_file']
            )
            
            for log_source in config['ssh_remote']['logs']:
                path = log_source['path']
                log_type = log_source['type']
                
                logger.info(f"Collecting logs from {host}:{path} of type {log_type}")
                
                # Execute command to read the log file
                command = f"tail -n 100 {path}"
                stdin, stdout, stderr = ssh_client.exec_command(command)
                
                lines = stdout.readlines()
                for line in lines:
                    logs.append({
                        '@timestamp': datetime.now().isoformat(),
                        'message': line.strip(),
                        'log_type': log_type,
                        'source': path,
                        'host': host
                    })
                    
                logger.info(f"Collected {len(lines)} log entries from {host}:{path}")
                
            ssh_client.close()
            
        except Exception as e:
            logger.error(f"Error collecting logs from remote host {host}: {e}")
            
    return logs

def collect_syslog(config):
    """Collect logs from syslog server."""
    logger.info("Collecting logs from syslog server")
    
    logs = []
    try:
        host = config['syslog_server']['host']
        port = config['syslog_server']['port']
        protocol = config['syslog_server']['protocol']
        
        # This is placeholder code - in a real implementation, 
        # you would need to actually set up a syslog server listening on the specified port
        logger.info(f"Syslog server would be listening on {host}:{port} using {protocol}")
        
    except Exception as e:
        logger.error(f"Error collecting logs from syslog server: {e}")
        
    return logs

def save_logs(logs, output_dir):
    """Save collected logs to a file."""
    if not logs:
        logger.warning("No logs to save")
        return
        
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"logs_{timestamp}.json")
    
    try:
        with open(output_path, 'w') as f:
            json.dump(logs, f, indent=2)
        logger.info(f"Saved {len(logs)} logs to {output_path}")
    except Exception as e:
        logger.error(f"Error saving logs to {output_path}: {e}")

def send_to_logstash(logs, config):
    """Send logs to Logstash."""
    if not logs:
        logger.warning("No logs to send to Logstash")
        return
        
    try:
        # This is a simplified implementation - in a real scenario, 
        # you would use a proper Logstash client or HTTP API
        host = config['logstash']['host']
        port = config['logstash']['port']
        
        logger.info(f"Sending {len(logs)} logs to Logstash at {host}:{port}")
        
        # In a real implementation, you'd use something like:
        # from logstash import TCPLogstashHandler
        # handler = TCPLogstashHandler(host, port, version=1)
        # for log in logs:
        #     handler.emit(log)
        
        logger.info("Logs would be sent to Logstash")
        
    except Exception as e:
        logger.error(f"Error sending logs to Logstash: {e}")

def run_log_collection(config_path):
    """Run the log collection process."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Collect logs from different sources
        local_logs = collect_local_logs(config)
        remote_logs = collect_remote_logs(config)
        syslog_logs = collect_syslog(config)
        
        # Combine all logs
        all_logs = local_logs + remote_logs + syslog_logs
        
        if all_logs:
            # Save logs locally
            output_dir = os.path.join(
                config.get('output', {}).get('directory', 'data/raw_logs')
            )
            save_logs(all_logs, output_dir)
            
            # Send logs to Logstash if configured
            if 'logstash' in config:
                send_to_logstash(all_logs, config)
                
    except Exception as e:
        logger.error(f"Error in log collection: {e}")
        sys.exit(1)

def run_continuous_collection(config_path, interval):
    """Run continuous log collection at specified intervals."""
    logger.info(f"Starting continuous log collection every {interval} seconds")
    
    while True:
        try:
            run_log_collection(config_path)
        except Exception as e:
            logger.error(f"Error in log collection cycle: {e}")
            
        logger.info(f"Sleeping for {interval} seconds")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real Log Collector")
    parser.add_argument("--config", type=str, default="config/log_sources.json",
                      help="Path to the configuration file")
    parser.add_argument("--continuous", action="store_true",
                      help="Run in continuous mode")
    parser.add_argument("--interval", type=int, default=60,
                      help="Collection interval in seconds (for continuous mode)")
                      
    args = parser.parse_args()
    
    if args.continuous:
        run_continuous_collection(args.config, args.interval)
    else:
        run_log_collection(args.config)
=======
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
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
