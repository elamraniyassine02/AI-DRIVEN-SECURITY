import argparse
import json
import logging
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

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

def train_classifier(data, config):
    X = data[config['features']]
    y = data[config['target']]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=config['test_size'], random_state=42)
    
    model = RandomForestClassifier(n_estimators=config['n_estimators'], random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred)
    logger.info(f"Classification Report:\n{report}")
    
    return model

def save_model(model, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        pickle.dump(model, f)

def run_threat_classification(config):
    data = load_data(config['data']['path'])
    model = train_classifier(data, config['model'])
    save_model(model, config['output']['model_path'])
    
    logger.info(f"Threat classification model trained and saved to {config['output']['model_path']}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/threat_classification_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_threat_classification(config)