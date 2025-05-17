
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/anomaly_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_data(es, index, time_range='1h'):
    """Load data from Elasticsearch for anomaly detection."""
    logger.info(f"Loading data from {index} for the last {time_range}")
    
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{time_range}",
                    "lte": "now"
                }
            }
        },
        "size": 10000  # Adjust based on your needs
    }
    
    try:
        result = es.search(index=index, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} records from Elasticsearch")
        
        if not hits:
            logger.warning(f"No data found in {index} for the last {time_range}")
            return None
            
        # Extract features for anomaly detection
        data = []
        for hit in hits:
            source = hit['_source']
            # Extract relevant features for anomaly detection
            # This needs to be adjusted based on your data structure
            features = {
                'host': source.get('host', {}).get('name', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            
            # Include metrics based on the data type
            if 'system' in source:
                if 'cpu' in source['system']:
                    features['cpu_usage'] = source['system']['cpu'].get('total', {}).get('norm', {}).get('pct', 0)
                if 'memory' in source['system']:
                    features['memory_usage'] = source['system']['memory'].get('actual', {}).get('used', {}).get('pct', 0)
                if 'load' in source['system']:
                    features['load_1m'] = source['system']['load'].get('1', 0)
            
            # Add network metrics if available
            if 'network' in source:
                features['network_in_bytes'] = source['network'].get('in', {}).get('bytes', 0)
                features['network_out_bytes'] = source['network'].get('out', {}).get('bytes', 0)
                
            data.append(features)
            
        df = pd.DataFrame(data)
        
        # Convert timestamp to datetime and sort
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Extract numerical features for anomaly detection
        numerical_features = df.select_dtypes(include=[np.number]).columns.tolist()
        if not numerical_features:
            logger.warning("No numerical features found for anomaly detection")
            return None
            
        return df
        
    except Exception as e:
        logger.error(f"Error loading data from Elasticsearch: {e}")
        return None

def detect_anomalies(data, algorithm='isolation_forest', contamination=0.05):
    """Detect anomalies in the data using the specified algorithm."""
    logger.info(f"Detecting anomalies using {algorithm} with contamination {contamination}")
    
    # Select numerical features for anomaly detection
    numerical_features = data.select_dtypes(include=[np.number]).columns.tolist()
    X = data[numerical_features].fillna(0)
    
    # Store original index for mapping back to data
    original_index = data.index
    
    try:
        if algorithm == 'isolation_forest':
            model = IsolationForest(contamination=contamination, random_state=42)
            scores = model.fit_predict(X)
        elif algorithm == 'local_outlier_factor':
            model = LocalOutlierFactor(contamination=contamination, novelty=False)
            scores = model.fit_predict(X)
        else:
            logger.error(f"Unsupported algorithm: {algorithm}")
            return None
            
        # Convert predictions: -1 for anomalies, 1 for normal
        anomalies = data.iloc[np.where(scores == -1)[0]].copy()
        
        if len(anomalies) == 0:
            logger.info("No anomalies detected")
            return pd.DataFrame()
            
        logger.info(f"Detected {len(anomalies)} anomalies")
        
        # Add anomaly scores (decision function gives distance from boundary)
        if algorithm == 'isolation_forest':
            # For Isolation Forest, lower scores indicate anomalies
            anomaly_scores = model.decision_function(X)
            # Invert and normalize scores so higher means more anomalous
            normalized_scores = 1 - (anomaly_scores - np.min(anomaly_scores)) / (np.max(anomaly_scores) - np.min(anomaly_scores))
            
            # Add scores to anomalies
            anomalies['anomaly_score'] = normalized_scores[np.where(scores == -1)[0]]
            
        return anomalies
        
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        return None

def format_anomalies_for_elk(anomalies, index_name):
    """Format anomalies for sending to Elasticsearch."""
    docs = []
    for _, row in anomalies.iterrows():
        timestamp = row.get('timestamp', datetime.now())
        if isinstance(timestamp, pd.Timestamp):
            timestamp = timestamp.isoformat()
            
        doc = {
            "@timestamp": timestamp,
            "host": row.get('host', 'unknown'),
            "anomaly_score": float(row.get('anomaly_score', 0)),
            "anomaly_type": "system_metrics",
            "source": "AI-Driven Security Solution",
            "details": {
                "cpu_usage": float(row.get('cpu_usage', 0)),
                "memory_usage": float(row.get('memory_usage', 0)),
                "load_1m": float(row.get('load_1m', 0)),
                "network_in_bytes": float(row.get('network_in_bytes', 0)),
                "network_out_bytes": float(row.get('network_out_bytes', 0))
            }
        }
        docs.append({
            "_index": index_name,
            "_source": doc
        })
    return docs

def index_anomalies(es, anomalies, index_name):
    """Index detected anomalies to Elasticsearch."""
    if anomalies.empty:
        logger.info("No anomalies to index")
        return
        
    logger.info(f"Indexing {len(anomalies)} anomalies to {index_name}")
    
    try:
        # Format anomalies for Elasticsearch
        docs = format_anomalies_for_elk(anomalies, index_name)
        
        # Use Elasticsearch bulk API for efficiency
        from elasticsearch.helpers import bulk
        success, errors = bulk(es, docs, refresh=True)
        
        logger.info(f"Successfully indexed {success} anomalies, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing anomalies to Elasticsearch: {e}")

def run_anomaly_detection_service(config):
    """Run the anomaly detection service continuously."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        logger.info(f"Connected to Elasticsearch at {config['elk']['elasticsearch']['hosts']}")
        
        # Set up anomalies index if it doesn't exist
        anomalies_index = config['elk']['elasticsearch']['indices']['anomalies']
        
        # Run anomaly detection in a loop
        while True:
            logger.info("Starting anomaly detection cycle")
            
            # Load data from Elasticsearch
            data = load_data(es, "metricbeat-*", "1h")
            
            if data is not None and not data.empty:
                # Detect anomalies
                for algorithm in config['model']['algorithms']:
                    anomalies = detect_anomalies(
                        data, 
                        algorithm=algorithm, 
                        contamination=config['model']['contamination']
                    )
                    
                    if anomalies is not None and not anomalies.empty:
                        # Index anomalies to Elasticsearch
                        index_anomalies(es, anomalies, anomalies_index)
            
            # Sleep before next cycle
            logger.info("Anomaly detection cycle completed, sleeping for 5 minutes")
            time.sleep(300)  # Sleep for 5 minutes
            
    except KeyboardInterrupt:
        logger.info("Anomaly detection service shutting down")
    except Exception as e:
        logger.error(f"Error in anomaly detection service: {e}")
        raise

def run_anomaly_detection(config_path):
    """Run anomaly detection with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Run the anomaly detection service
        run_anomaly_detection_service(config)
        
    except Exception as e:
        logger.error(f"Error running anomaly detection: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Anomaly Detection Service")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
    
    args = parser.parse_args()
    run_anomaly_detection(args.config)