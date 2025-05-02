import logging
import os
import subprocess
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_python_version():
    required_version = (3, 6)
    current_version = sys.version_info[:2]
    assert current_version >= required_version, f"Python {required_version[0]}.{required_version[1]} or higher is required (you have {current_version[0]}.{current_version[1]})"
    logger.info(f"Python version {current_version[0]}.{current_version[1]} is installed")

def test_required_libraries():
    required_libraries = [
        'pandas', 'numpy', 'scikit-learn', 'matplotlib', 'seaborn',
        'pyzmq', 'grpcio', 'protobuf',
        'flask', 'dash', 'plotly', 'dash-bootstrap-components',
        'requests', 'tqdm', 'ipython', 'jupyter'
    ]
    
    for library in required_libraries:
        try:
            __import__(library)
            logger.info(f"{library} is installed")
        except ImportError:
            logger.error(f"{library} is not installed")
            sys.exit(1)

def test_elk_stack():
    elk_components = ['elasticsearch', 'logstash', 'kibana']
    
    for component in elk_components:
        result = subprocess.run(['systemctl', 'is-active', component], stdout=subprocess.PIPE)
        if result.stdout.decode().strip() == 'active':
            logger.info(f"{component} is running")
        else:
            logger.error(f"{component} is not running")
            sys.exit(1)

def test_worker_connectivity():
    worker_ips = ['192.168.100.72', '192.168.100.73']
    
    for ip in worker_ips:
        result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE)
        if result.returncode == 0:
            logger.info(f"Worker {ip} is reachable")
        else:
            logger.error(f"Worker {ip} is not reachable")
            sys.exit(1)

def test_directory_structure():
    required_directories = [
        'config', 'data', 'data/raw_logs', 'data/processed_logs',
        'logs', 'models', 'results', 'dashboard', 'scripts'
    ]
    
    for directory in required_directories:
        if os.path.isdir(directory):
            logger.info(f"{directory} directory exists")
        else:
            logger.error(f"{directory} directory is missing")
            sys.exit(1)

if __name__ == '__main__':
    test_python_version()
    test_required_libraries()
    test_elk_stack()
    test_worker_connectivity()
    test_directory_structure()
    
    logger.info("Environment testing completed successfully")