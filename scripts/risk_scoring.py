import argparse
import json
import logging
import os

import numpy as np
import pandas as pd

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

def load_asset_criticality(path):
    with open(path) as f:
        asset_criticality = json.load(f)
    return asset_criticality

def calculate_risk_scores(anomalies, vulnerabilities, compliance_issues, asset_criticality):
    risk_scores = []
    for asset in set(anomalies['asset'].unique()) | set(vulnerabilities['asset'].unique()) | set(compliance_issues['asset'].unique()):
        asset_anomalies = anomalies[anomalies['asset'] == asset]
        asset_vulnerabilities = vulnerabilities[vulnerabilities['asset'] == asset]
        asset_compliance_issues = compliance_issues[compliance_issues['asset'] == asset]
        
        anomaly_score = asset_anomalies['score'].sum()
        vulnerability_score = asset_vulnerabilities['score'].sum()
        compliance_score = asset_compliance_issues['score'].sum()
        
        criticality = asset_criticality.get(asset, asset_criticality['default'])
        
        risk_score = (anomaly_score * criticality['anomaly_weight'] + 
                      vulnerability_score * criticality['vulnerability_weight'] + 
                      compliance_score * criticality['compliance_weight']) / criticality['total_weight']
        
        risk_scores.append({
            'asset': asset,
            'score': risk_score,
            'anomaly_score': anomaly_score,
            'vulnerability_score': vulnerability_score,
            'compliance_score': compliance_score
        })
    
    return pd.DataFrame(risk_scores)

def classify_risk(score, thresholds):
    if score >= thresholds['high']:
        return 'high'
    elif score >= thresholds['medium']:
        return 'medium'
    else:
        return 'low'
    
def run_risk_scoring(config):
    anomalies = load_data(config['data']['anomalies'])
    vulnerabilities = load_data(config['data']['vulnerabilities'])
    compliance_issues = load_data(config['data']['compliance_issues'])
    asset_criticality = load_asset_criticality(config['asset_criticality'])
    
    risk_scores = calculate_risk_scores(anomalies, vulnerabilities, compliance_issues, asset_criticality)
    risk_scores['risk_level'] = risk_scores['score'].apply(lambda x: classify_risk(x, config['risk_thresholds']))
    
    output_path = config['output']['path']
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    risk_scores.to_json(output_path, orient='records')
    
    logger.info(f"Risk scores calculated and saved to {output_path}")
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/risk_scoring_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_risk_scoring(config)