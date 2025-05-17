<<<<<<< HEAD
#!/usr/bin/env python3
"""
Hyperparameter tuning for machine learning models in the security solution.
"""
=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
import argparse
import json
import logging
import os
<<<<<<< HEAD
import sys
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import make_scorer, f1_score
from elasticsearch import Elasticsearch

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/hyperparameter_tuning.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_data_from_elasticsearch(es, index_pattern, time_range='7d'):
    """Load training data from Elasticsearch indices."""
    logger.info(f"Loading data from {index_pattern} for the last {time_range}")
    
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
        result = es.search(index=index_pattern, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} documents from Elasticsearch")
        
        if not hits:
            logger.warning(f"No data found in {index_pattern}")
            return None
            
        # Extract features for anomaly detection
        data = []
        for hit in hits:
            source = hit['_source']
            features = {}
            
            # Extract numerical features from the data
            # This is a simplified example - in a real scenario, you'd extract relevant features
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
                
            # Only add rows that have at least some values
            if features:
                features['timestamp'] = source.get('@timestamp', '')
                features['host'] = source.get('host', {}).get('name', 'unknown')
                data.append(features)
            
        df = pd.DataFrame(data)
        
        # Convert timestamp to datetime and sort
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
        
        logger.info(f"Created DataFrame with {df.shape[0]} rows and {df.shape[1]} columns")
        return df
        
    except Exception as e:
        logger.error(f"Error loading data from Elasticsearch: {e}")
        return None

def tune_isolation_forest(X, param_grid=None):
    """Tune hyperparameters for Isolation Forest."""
    logger.info("Tuning Isolation Forest hyperparameters")
    
    if param_grid is None:
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_samples': ['auto', 0.5, 0.7],
            'contamination': [0.01, 0.05, 0.1],
            'max_features': [1.0, 0.7, 0.5]
        }
    
    # Create a custom scoring function - this is tricky for unsupervised learning
    # For demonstration, we're using a simpler approach
    model = IsolationForest()
    
    # Since we don't have labels for unsupervised learning, we use a heuristic
    # This is a simplified example - in practice, you might use a more sophisticated approach
    grid_search = GridSearchCV(
        model, 
        param_grid, 
        cv=3,  # Since this is unsupervised, CV is used differently
        scoring='neg_mean_squared_error',  # Not ideal for anomaly detection but serves for demo
        n_jobs=-1
    )
    
    # Fit the model
    grid_search.fit(X)
    
    # Get best parameters
    best_params = grid_search.best_params_
    logger.info(f"Best parameters for Isolation Forest: {best_params}")
    
    return best_params

def tune_local_outlier_factor(X, param_grid=None):
    """Tune hyperparameters for Local Outlier Factor."""
    logger.info("Tuning Local Outlier Factor hyperparameters")
    
    if param_grid is None:
        param_grid = {
            'n_neighbors': [5, 10, 20, 30],
            'algorithm': ['auto', 'ball_tree', 'kd_tree', 'brute'],
            'leaf_size': [10, 20, 30, 40],
            'metric': ['euclidean', 'manhattan', 'minkowski']
        }
    
    # Create the model
    model = LocalOutlierFactor(novelty=True)  # Must use novelty=True for GridSearchCV
    
    # Again, for unsupervised learning this is not ideal but serves as an example
    grid_search = GridSearchCV(
        model, 
        param_grid, 
        cv=3,
        scoring='neg_mean_squared_error',
        n_jobs=-1
    )
    
    # Fit the model
    grid_search.fit(X)
    
    # Get best parameters
    best_params = grid_search.best_params_
    logger.info(f"Best parameters for Local Outlier Factor: {best_params}")
    
    return best_params

def save_best_params(best_params, output_path):
    """Save best hyperparameters to a file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(best_params, f, indent=2)
    logger.info(f"Best parameters saved to {output_path}")

def run_hyperparameter_tuning(config_path):
    """Run hyperparameter tuning with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        
        # Load data
        data = load_data_from_elasticsearch(
            es,
            'metricbeat-*',  # Use metricbeat data for system metrics
            '7d'  # Use the last 7 days of data
        )
        
        if data is None or data.empty:
            logger.error("No data available for hyperparameter tuning")
            return
            
        # Prepare the features
        numerical_cols = data.select_dtypes(include=['number']).columns.tolist()
        X = data[numerical_cols].fillna(0)
        
        # Tune Isolation Forest
        isolation_forest_params = tune_isolation_forest(X)
        
        # Tune Local Outlier Factor
        lof_params = tune_local_outlier_factor(X)
        
        # Combine the results
        best_params = {
            'isolation_forest': isolation_forest_params,
            'local_outlier_factor': lof_params,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Save the results
        output_path = os.path.join(
            config.get('output', {}).get('directory', 'models'),
            'hyperparameters.json'
        )
        save_best_params(best_params, output_path)
        
    except Exception as e:
        logger.error(f"Error in hyperparameter tuning: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hyperparameter Tuning")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
                      
    args = parser.parse_args()
    run_hyperparameter_tuning(args.config)
=======

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
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
