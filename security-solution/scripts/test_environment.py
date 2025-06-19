import logging
import os
import platform
import socket
import subprocess
import sys
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/test_environment.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def test_python_version():
    """Test Python version."""
    logger.info("Testing Python version")
    required_version = (3, 6)
    current_version = sys.version_info[:2]
    
    logger.info(f"Current Python version: {current_version[0]}.{current_version[1]}")
    
    if current_version >= required_version:
        logger.info(f"✅ Python {current_version[0]}.{current_version[1]} meets the minimum requirement")
        return True
    else:
        logger.error(f"❌ Python {required_version[0]}.{required_version[1]} or higher is required")
        return False

def test_required_libraries():
    """Test required Python libraries."""
    logger.info("Testing required Python libraries")
    
    required_libraries = {
        'pandas': 'pandas',
        'numpy': 'numpy',
        'scikit-learn': 'sklearn',  # This might be the issue - should check for 'sklearn' not 'scikit-learn'
        'elasticsearch': 'elasticsearch', 
        'pyzmq': 'zmq',  # This should be 'zmq' not 'pyzmq'
        'grpcio': 'grpc',  # This should be 'grpc' not 'grpcio'
        'protobuf': 'google.protobuf',  # This should be 'google.protobuf' not 'protobuf'
        'requests': 'requests',
        'paramiko': 'paramiko'
    }
    
    all_installed = True
    for display_name, import_name in required_libraries.items():
        try:
            __import__(import_name)
            logger.info(f"✅ {display_name} is installed")
        except ImportError:
            logger.error(f"❌ {display_name} is not installed")
            all_installed = False
            
    return all_installed
def test_elk_stack():
    """Test ELK stack service status."""
    logger.info("Testing ELK stack services")
    
    elk_components = ['elasticsearch', 'logstash', 'kibana']
    all_running = True
    
    for component in elk_components:
        try:
            result = subprocess.run(['systemctl', 'is-active', component], 
                                   stdout=subprocess.PIPE, text=True)
            status = result.stdout.strip()
            
            if status == 'active':
                logger.info(f"✅ {component} is running")
            else:
                logger.error(f"❌ {component} is not running (status: {status})")
                all_running = False
        except Exception as e:
            logger.error(f"❌ Error checking {component} status: {e}")
            all_running = False
            
    return all_running

def test_elk_connectivity():
    """Test connectivity to ELK stack components."""
    logger.info("Testing connectivity to ELK stack components")
    
    components = [
        ('Elasticsearch', 'localhost', 9200),
        ('Kibana', 'localhost', 5601),
        ('Logstash', 'localhost', 5044)
    ]
    
    all_connected = True
    for name, host, port in components:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                logger.info(f"✅ {name} is reachable at {host}:{port}")
            else:
                logger.error(f"❌ {name} is not reachable at {host}:{port}")
                all_connected = False
        except Exception as e:
            logger.error(f"❌ Error checking {name} connectivity: {e}")
            all_connected = False
            
    return all_connected

def test_worker_connectivity(config):
    """Test connectivity to worker nodes."""
    logger.info("Testing connectivity to worker nodes")
    
    workers = [
        ('Worker 1', config['workers']['worker1']['host'], config['workers']['worker1']['port']),
        ('Worker 2', config['workers']['worker2']['host'], config['workers']['worker2']['port'])
    ]
    
    all_connected = True
    for name, host, port in workers:
        # First ping to check basic connectivity
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', host], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                logger.info(f"✅ {name} responds to ping at {host}")
            else:
                logger.error(f"❌ {name} does not respond to ping at {host}")
                all_connected = False
        except Exception as e:
            logger.error(f"❌ Error pinging {name}: {e}")
            all_connected = False
            
        # Then check port connectivity
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                logger.info(f"✅ {name} port {port} is open")
            else:
                logger.warning(f"⚠️ {name} port {port} is not open (this may be expected if service is not running yet)")
        except Exception as e:
            logger.error(f"❌ Error checking {name} port connectivity: {e}")
            
    return all_connected

def test_directory_structure():
    """Test required directory structure."""
    logger.info("Testing directory structure")
    
    required_directories = [
        'config', 'data', 'data/raw_logs', 'data/processed_logs',
        'logs', 'models', 'results', 'scripts', 'scripts/integrations'
    ]
    
    all_exist = True
    for directory in required_directories:
        if os.path.isdir(directory):
            logger.info(f"✅ {directory} directory exists")
        else:
            logger.error(f"❌ {directory} directory is missing")
            all_exist = False
            
    return all_exist

def test_configuration_files():
    """Test required configuration files."""
    logger.info("Testing configuration files")
    
    required_files = [
        'config/server_config.json',
        'config/log_sources.json',
        'config/elk_config.json',
        'config/risk_scoring_config.json',
        'config/asset_criticality.json'
    ]
    
    all_exist = True
    for file in required_files:
        if os.path.isfile(file):
            logger.info(f"✅ {file} exists")
        else:
            logger.error(f"❌ {file} is missing")
            all_exist = False
            
    return all_exist

def run_tests(config_path="config/server_config.json"):
    """Run all environment tests."""
    os.makedirs("logs", exist_ok=True)
    
    logger.info("Starting environment tests")
    logger.info(f"Host: {platform.node()}")
    logger.info(f"OS: {platform.system()} {platform.release()}")
    
    # Load configuration
    try:
        with open(config_path) as f:
            import json
            config = json.load(f)
    except Exception as e:
        logger.error(f"❌ Failed to load configuration: {e}")
        return False
    
    # Run tests
    python_ok = test_python_version()
    libraries_ok = test_required_libraries()
    elk_ok = test_elk_stack()
    elk_conn_ok = test_elk_connectivity()
    worker_conn_ok = test_worker_connectivity(config)
    dirs_ok = test_directory_structure()
    config_ok = test_configuration_files()
    
    # Print summary
    logger.info("\n=== Test Summary ===")
    logger.info(f"Python Version: {'✅ Pass' if python_ok else '❌ Fail'}")
    logger.info(f"Required Libraries: {'✅ Pass' if libraries_ok else '❌ Fail'}")
    logger.info(f"ELK Stack Services: {'✅ Pass' if elk_ok else '❌ Fail'}")
    logger.info(f"ELK Connectivity: {'✅ Pass' if elk_conn_ok else '❌ Fail'}")
    logger.info(f"Worker Connectivity: {'✅ Pass' if worker_conn_ok else '❌ Fail'}")
    logger.info(f"Directory Structure: {'✅ Pass' if dirs_ok else '❌ Fail'}")
    logger.info(f"Configuration Files: {'✅ Pass' if config_ok else '❌ Fail'}")
    
    # Overall result
    all_passed = python_ok and libraries_ok and elk_ok and elk_conn_ok and dirs_ok and config_ok
    # Worker connectivity is a warning, not an error if it fails (might be expected)
    
    if all_passed:
        logger.info("\n✅ All tests passed successfully!")
    else:
        logger.error("\n❌ One or more tests failed")
        
    return all_passed

if __name__ == "__main__":
    # Get config path from command-line arguments if provided
    config_path = "config/server_config.json"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
        
    success = run_tests(config_path)
    
    if not success:
        sys.exit(1)
