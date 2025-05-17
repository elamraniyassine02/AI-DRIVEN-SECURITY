#!/usr/bin/env python3
"""
Server-side compliance analysis module for the AI-Driven Security Solution.
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime

import pandas as pd
from elasticsearch import Elasticsearch

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/compliance_analyzer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_compliance_data(es, index_name, time_range='7d'):
    """Load compliance data from Elasticsearch."""
    logger.info(f"Loading compliance data from {index_name} for the last {time_range}")
    
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
        result = es.search(index=index_name, body=query)
        hits = result['hits']['hits']
        logger.info(f"Loaded {len(hits)} compliance results from Elasticsearch")
        
        if not hits:
            logger.warning(f"No compliance data found in {index_name}")
            return pd.DataFrame()
            
        data = []
        for hit in hits:
            source = hit['_source']
            data.append(source)
            
        return pd.DataFrame(data)
        
    except Exception as e:
        logger.error(f"Error loading compliance data: {e}")
        return pd.DataFrame()

def analyze_compliance_data(data):
    """Analyze compliance check results to identify patterns and trends."""
    if data.empty:
        logger.warning("No compliance data to analyze")
        return {}
        
    logger.info("Analyzing compliance data")
    
    # Calculate overall compliance rate
    compliance_rate = data[data['status'] == 'PASS'].shape[0] / data.shape[0]
    logger.info(f"Overall compliance rate: {compliance_rate:.2%}")
    
    # Analyze by framework
    framework_stats = {}
    for framework in data['framework'].unique():
        framework_data = data[data['framework'] == framework]
        pass_rate = framework_data[framework_data['status'] == 'PASS'].shape[0] / framework_data.shape[0]
        framework_stats[framework] = {
            'pass_rate': pass_rate,
            'total_checks': framework_data.shape[0],
            'passed_checks': framework_data[framework_data['status'] == 'PASS'].shape[0],
            'failed_checks': framework_data[framework_data['status'] == 'FAIL'].shape[0]
        }
        logger.info(f"Framework {framework} compliance rate: {pass_rate:.2%}")
        
    # Identify most common failures
    failures = data[data['status'] == 'FAIL']
    if not failures.empty:
        failure_counts = failures['check_name'].value_counts()
        top_failures = failure_counts.head(5).to_dict()
        logger.info(f"Top compliance failures: {top_failures}")
    else:
        top_failures = {}
        
    # Generate recommendations based on failures
    recommendations = []
    if 'Ensure SSH root login is disabled' in failures['check_name'].values:
        recommendations.append("Disable SSH root login to improve security.")
    if 'Ensure password authentication is disabled in SSH' in failures['check_name'].values:
        recommendations.append("Use key-based authentication instead of passwords for SSH.")
    if 'Ensure auditd is installed' in failures['check_name'].values:
        recommendations.append("Install auditd for better system auditing capabilities.")
        
    analysis_results = {
        'timestamp': datetime.now().isoformat(),
        'compliance_rate': compliance_rate,
        'framework_stats': framework_stats,
        'top_failures': top_failures,
        'recommendations': recommendations
    }
    
    return analysis_results

def save_analysis_results(results, output_path):
    """Save analysis results to a file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Analysis results saved to {output_path}")

def index_analysis_results(es, results, index_name):
    """Index analysis results to Elasticsearch."""
    if not results:
        return
        
    try:
        es.index(index=index_name, document=results)
        logger.info(f"Analysis results indexed to {index_name}")
    except Exception as e:
        logger.error(f"Error indexing analysis results: {e}")

def run_compliance_analysis(config_path):
    """Run compliance analysis with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        
        # Load compliance data
        data = load_compliance_data(
            es, 
            config['elk']['elasticsearch']['indices']['compliance']
        )
        
        # Analyze the data
        results = analyze_compliance_data(data)
        
        # Save the results
        if results:
            output_path = os.path.join(
                config.get('output', {}).get('directory', 'results'),
                'compliance_analysis.json'
            )
            save_analysis_results(results, output_path)
            
            # Index the results
            index_analysis_results(
                es, 
                results, 
                config['elk']['elasticsearch']['indices'].get('compliance_analysis', 'security-compliance-analysis')
            )
            
    except Exception as e:
        logger.error(f"Error in compliance analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compliance Analyzer")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
                      
    args = parser.parse_args()
    run_compliance_analysis(args.config)