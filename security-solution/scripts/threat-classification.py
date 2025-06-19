import logging
import json
import sys
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

logging.basicConfig(level=logging.INFO)

def load_config(path):
    with open(path) as f:
        return json.load(f)

def load_training_data(path):
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return json.load(f)

def main(config_path):
    config = load_config(config_path)
    data_path = "data/threat_training.json"
    logging.info(f"Training a new model")
    logging.info(f"Loading training data from {data_path}")
    data = load_training_data(data_path)
    if not data or len(data) < 2:
        logging.error("Could not load training data from any source")
        logging.error("No training data available, cannot train model")
        return

    X = [entry["message"] for entry in data]
    y = [entry["threat_type"] for entry in data]

    logging.info(f"Loaded {len(X)} training examples from file")
    logging.info("Preparing features for threat classification")

    try:
        # FIX: Set min_df=1 (instead of 2)
        vectorizer = TfidfVectorizer(min_df=1, max_df=0.95)
        clf = LogisticRegression(max_iter=500)
        pipe = Pipeline([
            ('vec', vectorizer),
            ('clf', clf)
        ])

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)

        logging.info("Model training completed")
        logging.info("\n" + classification_report(y_test, y_pred))
        logging.info(f"Accuracy: {accuracy_score(y_test, y_pred):.3f}")

        # Save model
        model_path = "models/threat_classifier.joblib"
        joblib.dump(pipe, model_path)
        logging.info(f"Saved trained model to {model_path}")

    except Exception as e:
        logging.error(f"Error preparing features: {e}")
        logging.error("Failed to prepare features, cannot train model")

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "--config":
        print("Usage: python threat-classification.py --config <config_path>")
        sys.exit(1)
    config_path = sys.argv[2]
    main(config_path)
