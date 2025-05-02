import argparse
import json
import logging
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_data(path):
    if os.path.isfile(path):
        return pd.read_json(path)
    elif os.path.isdir(path):
        files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith('.json')]
        return pd.concat([pd.read_json(f) for f in files], ignore_index=True)
    else:
        raise ValueError(f"Invalid data path: {path}")

def detect_anomalies(data, config):
    if config['algorithm'] == 'isolation_forest':
        model = IsolationForest(contamination=config['contamination'], random_state=42)
    elif config['algorithm'] == 'local_outlier_factor':
        model = LocalOutlierFactor(contamination=config['contamination'])
    else:
        raise ValueError(f"Unsupported algorithm: {config['algorithm']}")
    
    scores = model.fit_predict(data)
    anomalies = data[scores == -1].copy()
    anomalies['score'] = model.decision_function(anomalies)
    
    return anomalies

def run_anomaly_detection(config):
    data = load_data(config['data']['path'])
    anomalies = detect_anomalies(data, config['model'])
    
    output_path = config['output']['path']
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    anomalies.to_json(output_path, orient='records')
    
    logger.info(f"Anomalies detected and saved to {output_path}")
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/anomaly_detection_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_anomaly_detection(config)