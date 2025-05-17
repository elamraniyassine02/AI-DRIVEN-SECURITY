#!/usr/bin/env python3
"""
AI-based threat classification for the security solution.
"""
import argparse
import json
import logging
import os
import sys
import pickle
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from elasticsearch import Elasticsearch

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/threat_classification.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_training_data(data_path=None, es=None, index_pattern=None):
    """Load training data from file or Elasticsearch."""
    if data_path and os.path.exists(data_path):
        logger.info(f"Loading training data from {data_path}")
        try:
            df = pd.read_json(data_path)
            logger.info(f"Loaded {len(df)} training examples from file")
            return df
        except Exception as e:
            logger.error(f"Error loading training data from file: {e}")
            
    if es and index_pattern:
        logger.info(f"Loading training data from Elasticsearch index {index_pattern}")
        try:
            query = {
                "query": {
                    "match_all": {}
                },
                "size": 10000
            }
            
            result = es.search(index=index_pattern, body=query)
            hits = result['hits']['hits']
            
            data = []
            for hit in hits:
                source = hit['_source']
                data.append(source)
                
            df = pd.DataFrame(data)
            logger.info(f"Loaded {len(df)} training examples from Elasticsearch")
            return df
            
        except Exception as e:
            logger.error(f"Error loading training data from Elasticsearch: {e}")
            
    # If we reach here, both methods failed
    logger.error("Could not load training data from any source")
    return pd.DataFrame()

def prepare_features(df, text_column='message', label_column='threat_type'):
    """Prepare features for threat classification."""
    logger.info("Preparing features for threat classification")
    
    if df.empty or text_column not in df.columns or label_column not in df.columns:
        logger.error("Data format is incorrect for feature preparation")
        return None, None, None, None, None
        
    try:
        # Split into features and labels
        X = df[text_column].fillna('')
        y = df[label_column]
        
        # Create a TF-IDF vectorizer
        vectorizer = TfidfVectorizer(
            max_features=5000,
            min_df=5,
            max_df=0.7,
            stop_words='english'
        )
        
        # Fit and transform the text data
        X_vectorized = vectorizer.fit_transform(X)
        
        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectorized, y, test_size=0.2, random_state=42
        )
        
        logger.info(f"Prepared {X_train.shape[0]} training examples and {X_test.shape[0]} testing examples")
        return X_train, X_test, y_train, y_test, vectorizer
        
    except Exception as e:
        logger.error(f"Error preparing features: {e}")
        return None, None, None, None, None

def train_classifier(X_train, y_train, params=None):
    """Train a threat classifier."""
    logger.info("Training threat classifier")
    
    if X_train is None or y_train is None:
        logger.error("Training data is not available")
        return None
        
    try:
        # Set default parameters if not provided
        if params is None:
            params = {
                'n_estimators': 100,
                'max_depth': 10,
                'min_samples_split': 2,
                'min_samples_leaf': 1,
                'random_state': 42
            }
            
        # Create and train the classifier
        clf = RandomForestClassifier(**params)
        clf.fit(X_train, y_train)
        
        logger.info("Classifier training completed")
        return clf
        
    except Exception as e:
        logger.error(f"Error training classifier: {e}")
        return None

def evaluate_classifier(clf, X_test, y_test):
    """Evaluate the classifier performance."""
    logger.info("Evaluating classifier performance")
    
    if clf is None or X_test is None or y_test is None:
        logger.error("Classifier or test data is not available")
        return {}
        
    try:
        # Make predictions
        y_pred = clf.predict(X_test)
        
        # Calculate metrics
        report = classification_report(y_test, y_pred, output_dict=True)
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        # Convert confusion matrix to a dictionary for JSON serialization
        cm_dict = {
            'matrix': conf_matrix.tolist(),
            'labels': list(set(y_test))
        }
        
        evaluation = {
            'classification_report': report,
            'confusion_matrix': cm_dict
        }
        
        logger.info(f"Overall accuracy: {report['accuracy']:.4f}")
        return evaluation
        
    except Exception as e:
        logger.error(f"Error evaluating classifier: {e}")
        return {}

def save_model(clf, vectorizer, output_dir, model_name='threat_classifier'):
    """Save the trained model and vectorizer."""
    if clf is None or vectorizer is None:
        logger.error("Nothing to save: classifier or vectorizer is None")
        return False
        
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Save the classifier
        model_path = os.path.join(output_dir, f"{model_name}.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump(clf, f)
            
        # Save the vectorizer
        vectorizer_path = os.path.join(output_dir, f"{model_name}_vectorizer.pkl")
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f)
            
        logger.info(f"Model saved to {model_path}")
        logger.info(f"Vectorizer saved to {vectorizer_path}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error saving model: {e}")
        return False

def classify_threats(data, clf, vectorizer):
    """Classify threats in new data."""
    logger.info("Classifying threats in new data")
    
    if clf is None or vectorizer is None:
        logger.error("Classifier or vectorizer is not available")
        return pd.DataFrame()
        
    try:
        # Prepare the messages
        messages = data['message'].fillna('')
        
        # Transform the messages
        X = vectorizer.transform(messages)
        
        # Make predictions
        predictions = clf.predict(X)
        probabilities = clf.predict_proba(X)
        
        # Add predictions to the data
        result = data.copy()
        result['threat_type'] = predictions
        
        # Add probability for each class
        for i, class_name in enumerate(clf.classes_):
            result[f"prob_{class_name}"] = probabilities[:, i]
            
        # Add confidence (highest probability)
        result['confidence'] = probabilities.max(axis=1)
        
        logger.info(f"Classified {len(result)} messages")
        return result
        
    except Exception as e:
        logger.error(f"Error classifying threats: {e}")
        return pd.DataFrame()

def load_model(model_dir, model_name='threat_classifier'):
    """Load a trained model and vectorizer."""
    logger.info(f"Loading model from {model_dir}")
    
    try:
        # Load the classifier
        model_path = os.path.join(model_dir, f"{model_name}.pkl")
        with open(model_path, 'rb') as f:
            clf = pickle.load(f)
            
        # Load the vectorizer
        vectorizer_path = os.path.join(model_dir, f"{model_name}_vectorizer.pkl")
        with open(vectorizer_path, 'rb') as f:
            vectorizer = pickle.load(f)
            
        logger.info("Model and vectorizer loaded successfully")
        return clf, vectorizer
        
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return None, None

def index_classifications(es, data, index_name):
    """Index threat classifications to Elasticsearch."""
    if es is None or data.empty:
        logger.warning("Cannot index classifications: Elasticsearch client or data is not available")
        return
        
    logger.info(f"Indexing {len(data)} threat classifications to {index_name}")
    
    try:
        # Prepare documents for indexing
        docs = []
        for _, row in data.iterrows():
            doc = row.to_dict()
            # Ensure timestamp field
            if '@timestamp' not in doc:
                doc['@timestamp'] = datetime.now().isoformat()
            docs.append({
                "_index": index_name,
                "_source": doc
            })
            
        # Index documents
        from elasticsearch.helpers import bulk
        success, errors = bulk(es, docs, refresh=True)
        
        logger.info(f"Successfully indexed {success} documents, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing classifications: {e}")

def run_threat_classification(config_path):
    """Run threat classification with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        
        # Check if model exists and should be loaded
        model_dir = os.path.join(config.get('model', {}).get('directory', 'models'))
        model_name = config.get('model', {}).get('name', 'threat_classifier')
        model_path = os.path.join(model_dir, f"{model_name}.pkl")
        
        if os.path.exists(model_path) and not config.get('model', {}).get('retrain', False):
            # Load existing model
            clf, vectorizer = load_model(model_dir, model_name)
        else:
            # Train a new model
            logger.info("Training a new model")
            
            # Load training data
            training_data_path = config.get('data', {}).get('training_data_path')
            training_index = config.get('elk', {}).get('elasticsearch', {}).get('indices', {}).get('threat_training')
            
            data = load_training_data(training_data_path, es, training_index)
            
            if data.empty:
                logger.error("No training data available, cannot train model")
                return
                
            # Prepare features
            X_train, X_test, y_train, y_test, vectorizer = prepare_features(data)
            
            if X_train is None:
                logger.error("Failed to prepare features, cannot train model")
                return
                
            # Train classifier
            clf = train_classifier(X_train, y_train)
            
            if clf is None:
                logger.error("Failed to train classifier")
                return
                
            # Evaluate classifier
            evaluation = evaluate_classifier(clf, X_test, y_test)
            
            # Save evaluation results
            if evaluation:
                eval_path = os.path.join(
                    config.get('output', {}).get('directory', 'results'),
                    'threat_classifier_evaluation.json'
                )
                os.makedirs(os.path.dirname(eval_path), exist_ok=True)
                with open(eval_path, 'w') as f:
                    json.dump(evaluation, f, indent=2)
                    
            # Save model
            save_model(clf, vectorizer, model_dir, model_name)
            
        # Classify new data
        if clf is not None and vectorizer is not None:
            # Load data to classify
            index_pattern = config.get('elk', {}).get('elasticsearch', {}).get('indices', {}).get('logs', 'filebeat-*')
            time_range = config.get('classification', {}).get('time_range', '1h')
            
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{time_range}",
                            "lte": "now"
                        }
                    }
                },
                "size": 10000
            }
            
            try:
                result = es.search(index=index_pattern, body=query)
                hits = result['hits']['hits']
                
                if hits:
                    data = []
                    for hit in hits:
                        source = hit['_source']
                        data.append(source)
                        
                    new_data = pd.DataFrame(data)
                    
                    if 'message' in new_data.columns:
                        # Classify the data
                        classified_data = classify_threats(new_data, clf, vectorizer)
                        
                        if not classified_data.empty:
                            # Save classifications
                            output_path = os.path.join(
                                config.get('output', {}).get('directory', 'results'),
                                'threat_classifications.json'
                            )
                            os.makedirs(os.path.dirname(output_path), exist_ok=True)
                            classified_data.to_json(output_path, orient='records')
                            
                            # Index classifications to Elasticsearch
                            index_name = config.get('elk', {}).get('elasticsearch', {}).get('indices', {}).get('threat_classifications', 'security-threat-classifications')
                            index_classifications(es, classified_data, index_name)
                else:
                    logger.warning("No new data to classify")
                    
            except Exception as e:
                logger.error(f"Error getting data for classification: {e}")
                
    except Exception as e:
        logger.error(f"Error in threat classification: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Classification")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
                      
    args = parser.parse_args()
    run_threat_classification(args.config)