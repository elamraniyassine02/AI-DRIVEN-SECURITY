import argparse
import json
import logging
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import GridSearchCV
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

def tune_hyperparameters(data, config):
    if config['algorithm'] == 'isolation_forest':
        model = IsolationForest(random_state=42)
        param_grid = {
            'n_estimators': config['param_grid']['n_estimators'],
            'max_samples': config['param_grid']['max_samples'],
            'contamination': config['param_grid']['contamination']
        }
    elif config['algorithm'] == 'local_outlier_factor':
        model = LocalOutlierFactor()
        param_grid = {
            'n_neighbors': config['param_grid']['n_neighbors'],
            'leaf_size': config['param_grid']['leaf_size'],
            'contamination': config['param_grid']['contamination']  
        }
    else:
        raise ValueError(f"Unsupported algorithm: {config['algorithm']}")
    
    grid_search = GridSearchCV(model, param_grid, cv=config['cv'], scoring='neg_mean_squared_error', n_jobs=-1)
    grid_search.fit(data)
    
    best_params = grid_search.best_params_
    logger.info(f"Best hyperparameters: {best_params}")
    
    return best_params

def run_hyperparameter_tuning(config):
    data = load_data(config['data']['path'])
    best_params = tune_hyperparameters(data, config['tuning'])
    
    output_path = config['output']['path']
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(best_params, f)
    
    logger.info(f"Hyperparameter tuning completed. Best parameters saved to {output_path}")
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/hyperparameter_tuning_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_hyperparameter_tuning(config)