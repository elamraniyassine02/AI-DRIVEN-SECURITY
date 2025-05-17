<<<<<<< HEAD

=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
import argparse
import json
import logging
import os
<<<<<<< HEAD
import sys
import subprocess
import time
from datetime import datetime
=======
import subprocess
import time
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

<<<<<<< HEAD
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
=======
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
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
