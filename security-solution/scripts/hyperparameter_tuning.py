#!/usr/bin/env python3
"""
Hyperparameter tuning for machine learning models in the security solution (UNSUPERVISED VERSION).
"""
import argparse
import json
import logging
import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
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
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
        logger.info(f"Created DataFrame with {df.shape[0]} rows and {df.shape[1]} columns")
        return df
    except Exception as e:
        logger.error(f"Error loading data from Elasticsearch: {e}")
        return None

def manual_isolation_forest_search(X, param_grid):
    logger.info("Manual grid search for Isolation Forest (unsupervised)")
    best_params = None
    best_score = -np.inf  # maximize std of scores (proxy for outlier separation)
    for n_estimators in param_grid['n_estimators']:
        for max_samples in param_grid['max_samples']:
            for contamination in param_grid['contamination']:
                for max_features in param_grid['max_features']:
                    try:
                        model = IsolationForest(
                            n_estimators=n_estimators,
                            max_samples=max_samples,
                            contamination=contamination,
                            max_features=max_features,
                            random_state=42
                        )
                        model.fit(X)
                        scores = model.decision_function(X)
                        score = np.std(scores)
                        logger.info(f"Params: n_estimators={n_estimators}, max_samples={max_samples}, contamination={contamination}, max_features={max_features}, STD(score)={score:.5f}")
                        if score > best_score:
                            best_score = score
                            best_params = {
                                'n_estimators': n_estimators,
                                'max_samples': max_samples,
                                'contamination': contamination,
                                'max_features': max_features
                            }
                    except Exception as e:
                        logger.warning(f"IF search failed: {e}")
    logger.info(f"Best params (by std of decision function): {best_params}")
    return best_params

def manual_lof_search(X, param_grid):
    logger.info("Manual grid search for Local Outlier Factor (unsupervised)")
    best_params = None
    best_score = -np.inf
    for n_neighbors in param_grid['n_neighbors']:
        for algorithm in param_grid['algorithm']:
            for leaf_size in param_grid['leaf_size']:
                for metric in param_grid['metric']:
                    try:
                        model = LocalOutlierFactor(
                            n_neighbors=n_neighbors,
                            algorithm=algorithm,
                            leaf_size=leaf_size,
                            metric=metric,
                            novelty=True
                        )
                        model.fit(X)
                        scores = model.negative_outlier_factor_
                        score = np.std(scores)
                        logger.info(f"Params: n_neighbors={n_neighbors}, algo={algorithm}, leaf_size={leaf_size}, metric={metric}, STD(score)={score:.5f}")
                        if score > best_score:
                            best_score = score
                            best_params = {
                                'n_neighbors': n_neighbors,
                                'algorithm': algorithm,
                                'leaf_size': leaf_size,
                                'metric': metric
                            }
                    except Exception as e:
                        logger.warning(f"LOF search failed: {e}")
    logger.info(f"Best params (by std of negative_outlier_factor): {best_params}")
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
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        data = load_data_from_elasticsearch(
            es,
            'metricbeat-*',
            '7d'
        )
        if data is None or data.empty:
            logger.error("No data available for hyperparameter tuning")
            return
        numerical_cols = data.select_dtypes(include=['number']).columns.tolist()
        X = data[numerical_cols].fillna(0)

        # Parameter grids
        if_params = {
            'n_estimators': [100, 200],
            'max_samples': ['auto', 0.5],
            'contamination': [0.01, 0.05],
            'max_features': [1.0, 0.7]
        }
        lof_params = {
            'n_neighbors': [5, 10],
            'algorithm': ['auto'],
            'leaf_size': [20, 30],
            'metric': ['euclidean']
        }

        # Tune Isolation Forest
        isolation_forest_params = manual_isolation_forest_search(X, if_params)
        # Tune Local Outlier Factor
        lof_best_params = manual_lof_search(X, lof_params)
        # Save and log
        best_params = {
            'isolation_forest': isolation_forest_params,
            'local_outlier_factor': lof_best_params,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        output_path = os.path.join(
            config.get('output', {}).get('directory', 'models'),
            'hyperparameters.json'
        )
        save_best_params(best_params, output_path)
    except Exception as e:
        logger.error(f"Error in hyperparameter tuning: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hyperparameter Tuning (Unsupervised)")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
    args = parser.parse_args()
    run_hyperparameter_tuning(args.config)
