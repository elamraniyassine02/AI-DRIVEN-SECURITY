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
=======
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
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
