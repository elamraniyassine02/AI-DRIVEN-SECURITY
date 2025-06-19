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
from elasticsearch.helpers import bulk

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/risk_scoring.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_asset_criticality(path):
    """Load asset criticality configuration."""
    logger.info(f"Loading asset criticality from {path}")
    try:
        with open(path) as f:
            asset_criticality = json.load(f)
        return asset_criticality
    except Exception as e:
        logger.error(f"Error loading asset criticality: {e}")
        return None

def get_anomalies_from_elk(es, index, time_range='1d'):
    """Get anomalies from Elasticsearch."""
    logger.info(f"Loading anomalies from {index} for the last {time_range}")
    
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
        logger.info(f"Loaded {len(hits)} anomalies from Elasticsearch")
        
        anomalies = []
        for hit in hits:
            source = hit['_source']
            anomaly = {
                'host': source.get('host', 'unknown'),
                'score': source.get('anomaly_score', 0),
                'type': source.get('anomaly_type', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            anomalies.append(anomaly)
            
        return pd.DataFrame(anomalies)
        
    except Exception as e:
        logger.error(f"Error loading anomalies from Elasticsearch: {e}")
        return pd.DataFrame()

def get_vulnerabilities_from_elk(es, index, time_range='7d'):
    """Get vulnerabilities from Elasticsearch."""
    logger.info(f"Loading vulnerabilities from {index} for the last {time_range}")
    
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
        logger.info(f"Loaded {len(hits)} vulnerabilities from Elasticsearch")
        
        vulnerabilities = []
        for hit in hits:
            source = hit['_source']
            vuln = {
                'host': source.get('host', {}).get('name', 'unknown') if isinstance(source.get('host'), dict) else source.get('host', 'unknown'),
                'score': source.get('vulnerability_score', 0),
                'severity': source.get('severity', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            vulnerabilities.append(vuln)
            
        return pd.DataFrame(vulnerabilities)
        
    except Exception as e:
        logger.error(f"Error loading vulnerabilities from Elasticsearch: {e}")
        return pd.DataFrame()

def get_compliance_issues_from_elk(es, index, time_range='7d'):
    """Get compliance issues from Elasticsearch."""
    logger.info(f"Loading compliance issues from {index} for the last {time_range}")
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
                    {"term": {"status": "FAIL"}}
                ]
            }
        },
        "size": 10000  # Adjust based on your needs
    }
    
    try:
        result = es.search(index=index, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} compliance issues from Elasticsearch")
        
        issues = []
        for hit in hits:
            source = hit['_source']
            issue = {
                'host': source.get('host', {}).get('name', 'unknown') if isinstance(source.get('host'), dict) else source.get('host', 'unknown'),
                'score': 0.5,  # Default score for compliance issues
                'framework': source.get('framework', 'unknown'),
                'timestamp': source.get('@timestamp', datetime.now().isoformat())
            }
            issues.append(issue)
            
        return pd.DataFrame(issues)
        
    except Exception as e:
        logger.error(f"Error loading compliance issues from Elasticsearch: {e}")
        return pd.DataFrame()

def calculate_risk_scores(anomalies, vulnerabilities, compliance_issues, asset_criticality, risk_weights):
    """Calculate risk scores for assets."""
    logger.info("Calculating risk scores")
    
    # Get unique assets
    assets = set()
    if not anomalies.empty:
        assets.update(anomalies['host'].unique())
    if not vulnerabilities.empty:
        assets.update(vulnerabilities['host'].unique())
    if not compliance_issues.empty:
        assets.update(compliance_issues['host'].unique())
        
    if not assets:
        logger.warning("No assets found for risk scoring")
        return pd.DataFrame()
        
    logger.info(f"Calculating risk scores for {len(assets)} assets")
    
    risk_scores = []
    for asset in assets:
        # Get asset-specific criticality
        if asset in asset_criticality:
            criticality = asset_criticality[asset]
        else:
            criticality = asset_criticality['default']
            
        # Calculate component scores
        asset_anomalies = anomalies[anomalies['host'] == asset] if not anomalies.empty else pd.DataFrame()
        asset_vulns = vulnerabilities[vulnerabilities['host'] == asset] if not vulnerabilities.empty else pd.DataFrame()
        asset_compliance = compliance_issues[compliance_issues['host'] == asset] if not compliance_issues.empty else pd.DataFrame()
        
        anomaly_score = asset_anomalies['score'].sum() if not asset_anomalies.empty else 0
        vulnerability_score = asset_vulns['score'].sum() if not asset_vulns.empty else 0
        compliance_score = asset_compliance['score'].sum() if not asset_compliance.empty else 0
        
        # Normalize scores (0-1 range)
        max_anomaly_score = 10  # Assuming max 10 high-severity anomalies
        max_vuln_score = 20     # Assuming max 20 high-severity vulnerabilities
        max_compliance_score = 10  # Assuming max 10 compliance issues
        
        norm_anomaly_score = min(anomaly_score / max_anomaly_score, 1)
        norm_vuln_score = min(vulnerability_score / max_vuln_score, 1)
        norm_compliance_score = min(compliance_score / max_compliance_score, 1)
        
        # Calculate weighted score
        weighted_score = (
            norm_anomaly_score * risk_weights['anomaly'] +
            norm_vuln_score * risk_weights['vulnerability'] +
            norm_compliance_score * risk_weights['compliance']
        )
        
        risk_scores.append({
            'asset': asset,
            'score': weighted_score,
            'anomaly_score': norm_anomaly_score,
            'vulnerability_score': norm_vuln_score,
            'compliance_score': norm_compliance_score,
            'criticality': criticality['criticality'],
            'timestamp': datetime.now().isoformat()
        })
        
    return pd.DataFrame(risk_scores)

def classify_risk(score, thresholds):
    """Classify risk level based on score and thresholds."""
    if score >= thresholds['high']:
        return 'high'
    elif score >= thresholds['medium']:
        return 'medium'
    else:
        return 'low'

def index_risk_scores(es, risk_scores, index_name):
    """Index risk scores to Elasticsearch."""
    if risk_scores.empty:
        logger.info("No risk scores to index")
        return
        
    logger.info(f"Indexing {len(risk_scores)} risk scores to {index_name}")
    
    try:
        # Format risk scores for Elasticsearch
        docs = []
        for _, row in risk_scores.iterrows():
            doc = {
                "@timestamp": row['timestamp'],
                "asset": row['asset'],
                "score": float(row['score']),
                "risk_level": classify_risk(row['score'], {'high': 0.7, 'medium': 0.4}),
                "anomaly_score": float(row['anomaly_score']),
                "vulnerability_score": float(row['vulnerability_score']),
                "compliance_score": float(row['compliance_score']),
                "criticality": row['criticality'],
                "source": "AI-Driven Security Solution"
            }
            docs.append({
                "_index": index_name,
                "_source": doc
            })
            
        # Use Elasticsearch bulk API for efficiency
        success, errors = bulk(es, docs, refresh=True)
        
        logger.info(f"Successfully indexed {success} risk scores, errors: {errors}")
        
    except Exception as e:
        logger.error(f"Error indexing risk scores to Elasticsearch: {e}")

def run_risk_scoring_service(config):
    """Run the risk scoring service continuously."""
    os.makedirs("logs", exist_ok=True)
    
    try:
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        logger.info(f"Connected to Elasticsearch at {config['elk']['elasticsearch']['hosts']}")
        
        # Load asset criticality
        asset_criticality_path = "config/asset_criticality.json"
        asset_criticality = load_asset_criticality(asset_criticality_path)
        if asset_criticality is None:
            logger.error("Failed to load asset criticality, exiting")
            return
            
        # Get index names from config
        anomalies_index = config['elk']['elasticsearch']['indices']['anomalies']
        vulnerabilities_index = config['elk']['elasticsearch']['indices']['vulnerabilities']
        compliance_index = config['elk']['elasticsearch']['indices']['compliance']
        risk_scores_index = config['elk']['elasticsearch']['indices']['risk_scores']
        
        # Define risk weights
        risk_weights = {
            'vulnerability': 0.4,
            'anomaly': 0.3,
            'compliance': 0.3
        }
        
        # Run risk scoring in a loop
        while True:
            logger.info("Starting risk scoring cycle")
            
            # Load data from Elasticsearch
            anomalies = get_anomalies_from_elk(es, anomalies_index, '1d')
            vulnerabilities = get_vulnerabilities_from_elk(es, vulnerabilities_index, '7d')
            compliance_issues = get_compliance_issues_from_elk(es, compliance_index, '7d')
            
            # Calculate risk scores
            risk_scores = calculate_risk_scores(
                anomalies,
                vulnerabilities,
                compliance_issues,
                asset_criticality,
                risk_weights
            )
            
            if not risk_scores.empty:
                # Index risk scores to Elasticsearch
                index_risk_scores(es, risk_scores, risk_scores_index)
            
            # Sleep before next cycle
            logger.info("Risk scoring cycle completed, sleeping for 15 minutes")
            time.sleep(900)  # Sleep for 15 minutes
            
    except KeyboardInterrupt:
        logger.info("Risk scoring service shutting down")
    except Exception as e:
        logger.error(f"Error in risk scoring service: {e}")
        raise

def run_risk_scoring(config_path):
    """Run risk scoring with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Run the risk scoring service
        run_risk_scoring_service(config)
        
    except Exception as e:
        logger.error(f"Error running risk scoring: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Risk Scoring Service")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
    
    args = parser.parse_args()
    run_risk_scoring(args.config)
