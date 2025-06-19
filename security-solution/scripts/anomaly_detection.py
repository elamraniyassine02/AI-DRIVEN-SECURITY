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

# Set up logging to a file and the console
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_dir = os.path.join(project_root, 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'anomaly_detection.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_data(es, index, time_range='1h'):
    logger.info(f"Loading data from {index} for the last {time_range}")
    query = {
        "range": {
            "@timestamp": {
                "gte": f"now-{time_range}",
                "lte": "now"
            }
        }
    }
    try:
        result = es.search(index=index, query=query, size=10000)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} records from Elasticsearch")
        if not hits:
            logger.warning(f"No data found in {index} for the last {time_range}")
            return None

        data = []
        for hit in hits:
            source = hit['_source']
            features = {
                'host': source.get('host', {}).get('name', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            if 'system' in source:
                if 'cpu' in source['system']:
                    features['cpu_usage'] = source['system']['cpu'].get('total', {}).get('norm', {}).get('pct', 0)
                if 'memory' in source['system']:
                    features['memory_usage'] = source['system']['memory'].get('actual', {}).get('used', {}).get('pct', 0)
                if 'load' in source['system']:
                    features['load_1m'] = source['system']['load'].get('1', 0)
            if 'network' in source:
                features['network_in_bytes'] = source['network'].get('in', {}).get('bytes', 0)
                features['network_out_bytes'] = source['network'].get('out', {}).get('bytes', 0)
            data.append(features)
        df = pd.DataFrame(data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        numerical_features = df.select_dtypes(include=[np.number]).columns.tolist()
        if not numerical_features:
            logger.warning("No numerical features found for anomaly detection")
            return None
        return df
    except Exception as e:
        logger.error(f"Error loading data from Elasticsearch: {e}")
        return None

def detect_anomalies(data, algorithm='isolation_forest', contamination=0.05):
    logger.info(f"Detecting anomalies using {algorithm} with contamination {contamination}")
    numerical_features = data.select_dtypes(include=[np.number]).columns.tolist()
    X = data[numerical_features].fillna(0)
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
        anomalies = data.iloc[np.where(scores == -1)[0]].copy()
        if len(anomalies) == 0:
            logger.info("No anomalies detected")
            return pd.DataFrame()
        logger.info(f"Detected {len(anomalies)} anomalies")
        if algorithm == 'isolation_forest':
            anomaly_scores = model.decision_function(X)
            normalized_scores = 1 - (anomaly_scores - np.min(anomaly_scores)) / (np.max(anomaly_scores) - np.min(anomaly_scores))
            anomalies['anomaly_score'] = normalized_scores[np.where(scores == -1)[0]]
        return anomalies
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        return None

def format_anomalies_for_elk(anomalies, index_name):
    docs = []
    for _, row in anomalies.iterrows():
        # Convert all NaNs to None for proper JSON encoding
        def nan_to_none(x):
            try:
                if pd.isna(x):
                    return None
            except Exception:
                pass
            return x
        timestamp = row.get('timestamp', datetime.now())
        if isinstance(timestamp, pd.Timestamp):
            timestamp = timestamp.isoformat()
        doc = {
            "@timestamp": timestamp,
            "host": nan_to_none(row.get('host', 'unknown')),
            "anomaly_score": nan_to_none(row.get('anomaly_score', 0)),
            "anomaly_type": "system_metrics",
            "source": "AI-Driven Security Solution",
            "details": {
                "cpu_usage": nan_to_none(row.get('cpu_usage', 0)),
                "memory_usage": nan_to_none(row.get('memory_usage', 0)),
                "load_1m": nan_to_none(row.get('load_1m', 0)),
                "network_in_bytes": nan_to_none(row.get('network_in_bytes', 0)),
                "network_out_bytes": nan_to_none(row.get('network_out_bytes', 0))
            }
        }
        docs.append({
            "_index": index_name,
            "_source": doc
        })
    return docs

def index_anomalies(es, anomalies, index_name):
    if anomalies.empty:
        logger.info("No anomalies to index")
        return
    logger.info(f"Indexing {len(anomalies)} anomalies to {index_name}")
    try:
        docs = format_anomalies_for_elk(anomalies, index_name)
        # Build the bulk payload
        payload = ""
        for doc in docs:
            action = {"index": {"_index": doc["_index"]}}
            payload += json.dumps(action) + "\n"
            payload += json.dumps(doc["_source"]) + "\n"
        # Send to Elasticsearch using the bulk API
        resp = es.transport.perform_request(
            "POST",
            "/_bulk",
            body=payload,
            headers={"Content-Type": "application/x-ndjson"}
        )
        # Handle TransportApiResponse object
        if hasattr(resp, "body"):
            resp_body = resp.body
        else:
            resp_body = resp
        # Log errors if any
        if isinstance(resp_body, dict):
            if resp_body.get("errors"):
                for i, item in enumerate(resp_body["items"][:3]):
                    logger.error(f"Error in item {i+1}: {item}")
                logger.error("Bulk API call returned errors.")
            else:
                logger.info("Successfully indexed all anomalies")
    except Exception as e:
        logger.error(f"Error indexing anomalies to Elasticsearch: {e}")

def run_anomaly_detection_service(config):
    os.makedirs(log_dir, exist_ok=True)
    try:
        elk = config.get('elk')
        if not elk and 'elasticsearch' in config:
            elk = {"elasticsearch": config['elasticsearch']}
            if 'logstash' in config: elk["logstash"] = config['logstash']
            if 'kibana' in config: elk["kibana"] = config['kibana']
        if not elk or 'elasticsearch' not in elk:
            logger.error('Config missing "elk.elasticsearch" settings!')
            raise ValueError('Config missing "elk.elasticsearch" settings!')
        es = Elasticsearch(hosts=elk['elasticsearch']['hosts'])
        logger.info(f"Connected to Elasticsearch at {elk['elasticsearch']['hosts']}")
        anomalies_index = elk['elasticsearch']['indices']['anomalies']

        model_cfg = config.get('model', {
            "algorithms": ["isolation_forest"],
            "contamination": 0.05
        })

        while True:
            logger.info("Starting anomaly detection cycle")
            data = load_data(es, "metricbeat-*", "1h")
            if data is not None and not data.empty:
                for algorithm in model_cfg['algorithms']:
                    anomalies = detect_anomalies(
                        data,
                        algorithm=algorithm,
                        contamination=model_cfg['contamination']
                    )
                    if anomalies is not None and not anomalies.empty:
                        index_anomalies(es, anomalies, anomalies_index)
            logger.info("Anomaly detection cycle completed, sleeping for 5 minutes")
            time.sleep(300)
    except KeyboardInterrupt:
        logger.info("Anomaly detection service shutting down")
    except Exception as e:
        logger.error(f"Error in anomaly detection service: {e}")
        raise

def run_anomaly_detection(config_path):
    try:
        with open(config_path) as f:
            config = json.load(f)
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
