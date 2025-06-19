import argparse
import json
import logging
import os
import sys
import time
from concurrent import futures

import grpc
import importlib.util

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/server_service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ServerService:
    def __init__(self, config):
        self.config = config
        self.services = []
        
    def start(self):
        logger.info("Starting server services...")
        
        # Initialize ELK connection
        try:
            from elasticsearch import Elasticsearch
            self.es = Elasticsearch(hosts=self.config['elk']['elasticsearch']['hosts'])
            logger.info(f"Connected to Elasticsearch at {self.config['elk']['elasticsearch']['hosts']}")
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            
        # Start anomaly detection service
        try:
            self.start_anomaly_detection()
        except Exception as e:
            logger.error(f"Failed to start anomaly detection service: {e}")
            
        # Start risk scoring service
        try:
            self.start_risk_scoring()
        except Exception as e:
            logger.error(f"Failed to start risk scoring service: {e}")
            
        logger.info("All services started successfully")
        
    def start_anomaly_detection(self):
        logger.info("Starting anomaly detection service...")
        # Import the module dynamically
        spec = importlib.util.spec_from_file_location(
            "anomaly_detection", 
            os.path.join(os.path.dirname(__file__), "anomaly_detection.py")
        )
        anomaly_detection = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(anomaly_detection)
        
        # Create a thread for anomaly detection
        executor = futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            anomaly_detection.run_anomaly_detection_service, 
            self.config
        )
        self.services.append((future, executor, "anomaly_detection"))
        logger.info("Anomaly detection service started")
        
    def start_risk_scoring(self):
        logger.info("Starting risk scoring service...")
        # Import the module dynamically
        spec = importlib.util.spec_from_file_location(
            "risk_scoring", 
            os.path.join(os.path.dirname(__file__), "risk_scoring.py")
        )
        risk_scoring = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(risk_scoring)
        
        # Create a thread for risk scoring
        executor = futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            risk_scoring.run_risk_scoring_service, 
            self.config
        )
        self.services.append((future, executor, "risk_scoring"))
        logger.info("Risk scoring service started")
        
    def run(self):
        self.start()
        
        try:
            while True:
                # Check if any service has crashed
                for future, executor, name in self.services:
                    if future.done():
                        exception = future.exception()
                        if exception:
                            logger.error(f"Service {name} crashed: {exception}")
                            # Restart the service
                            logger.info(f"Restarting {name} service...")
                            if name == "anomaly_detection":
                                self.start_anomaly_detection()
                            elif name == "risk_scoring":
                                self.start_risk_scoring()
                                
                time.sleep(10)  # Check every 10 seconds
        except KeyboardInterrupt:
            logger.info("Server shutting down gracefully...")
            # Clean up
            for _, executor, _ in self.services:
                executor.shutdown(wait=False)

def run_server(config_path):
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Load configuration
    try:
        with open(config_path) as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Create and start the server
    server = ServerService(config)
    server.run()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AI-Driven Security Solution Server')
    parser.add_argument('--config', type=str, default='config/server_config.json',
                        help='Path to the configuration file')
    args = parser.parse_args()
    
    run_server(args.config)
