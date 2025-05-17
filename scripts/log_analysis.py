<<<<<<< HEAD
#!/usr/bin/env python3
"""
Advanced log analysis for the AI-Driven Security Solution.
"""
=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
import argparse
import json
import logging
import os
import re
<<<<<<< HEAD
import sys
from datetime import datetime, timedelta

import pandas as pd
import numpy as np
from elasticsearch import Elasticsearch
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/log_analysis.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_logs_from_elasticsearch(es, index_pattern, time_range='1d'):
    """Load logs from Elasticsearch indices."""
    logger.info(f"Loading logs from {index_pattern} for the last {time_range}")
    
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
        logger.info(f"Loaded {len(hits)} logs from Elasticsearch")
        
        if not hits:
            logger.warning(f"No logs found in {index_pattern}")
            return pd.DataFrame()
            
        logs = []
        for hit in hits:
            source = hit['_source']
            log_entry = {
                'timestamp': source.get('@timestamp', ''),
                'message': source.get('message', ''),
                'host': source.get('host', ''),
                'log_type': source.get('log_type', ''),
                'source': source.get('source', '')
            }
            logs.append(log_entry)
            
        df = pd.DataFrame(logs)
        
        # Convert timestamp to datetime and sort
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
        
        return df
        
    except Exception as e:
        logger.error(f"Error loading logs from Elasticsearch: {e}")
        return pd.DataFrame()

def extract_patterns(logs, patterns):
    """Extract patterns from log messages using regular expressions."""
    logger.info("Extracting patterns from logs")
    
    results = {}
    for pattern_name, pattern_config in patterns.items():
        logger.info(f"Extracting pattern: {pattern_name}")
        
        regex = re.compile(pattern_config['regex'])
        matches = logs['message'].str.extractall(regex)
        
        if not matches.empty:
            results[pattern_name] = {
                'matches': matches.reset_index().to_dict(orient='records'),
                'count': len(matches),
                'sample': matches.head(5).to_dict()
            }
            logger.info(f"Found {len(matches)} matches for pattern {pattern_name}")
        else:
            results[pattern_name] = {
                'matches': [],
                'count': 0,
                'sample': {}
            }
            logger.info(f"No matches found for pattern {pattern_name}")
            
    return results

def cluster_log_messages(logs, min_samples=5, eps=0.5):
    """Cluster log messages to identify patterns using DBSCAN."""
    logger.info("Clustering log messages")
    
    if logs.empty or 'message' not in logs.columns:
        logger.warning("No messages to cluster")
        return {}
        
    # Extract messages
    messages = logs['message'].fillna('').tolist()
    
    # Create TF-IDF vectors
    vectorizer = TfidfVectorizer(
        max_features=1000,
        stop_words='english',
        min_df=2
    )
    
    # Fit and transform the messages
    try:
        X = vectorizer.fit_transform(messages)
        
        # Cluster the vectors
        clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(X)
        
        # Add cluster labels
        logs_with_clusters = logs.copy()
        logs_with_clusters['cluster'] = clustering.labels_
        
        # Get cluster statistics
        cluster_stats = {}
        for cluster_id in set(clustering.labels_):
            if cluster_id == -1:
                # Noise points
                continue
                
            cluster_logs = logs_with_clusters[logs_with_clusters['cluster'] == cluster_id]
            cluster_stats[f"cluster_{cluster_id}"] = {
                'size': len(cluster_logs),
                'sample_messages': cluster_logs['message'].head(3).tolist(),
                'hosts': cluster_logs['host'].unique().tolist(),
                'log_types': cluster_logs['log_type'].unique().tolist(),
                'time_range': [
                    cluster_logs['timestamp'].min().isoformat() if not pd.isna(cluster_logs['timestamp'].min()) else None,
                    cluster_logs['timestamp'].max().isoformat() if not pd.isna(cluster_logs['timestamp'].max()) else None
                ]
            }
            
        logger.info(f"Found {len(cluster_stats)} log clusters")
        return cluster_stats
        
    except Exception as e:
        logger.error(f"Error clustering log messages: {e}")
        return {}

def detect_anomalies(logs, time_window='1h', threshold=3):
    """Detect anomalies in log frequency."""
    logger.info("Detecting anomalies in log frequency")
    
    if logs.empty or 'timestamp' not in logs.columns:
        logger.warning("No logs with timestamps to analyze")
        return {}
        
    try:
        # Resample logs by time window
        logs_count = logs.set_index('timestamp').resample(time_window).size()
        
        # Calculate mean and standard deviation
        mean_count = logs_count.mean()
        std_count = logs_count.std()
        
        # Identify anomalies (log counts that deviate significantly from the mean)
        anomalies = logs_count[abs(logs_count - mean_count) > threshold * std_count]
        
        anomaly_results = {
            'anomaly_windows': [
                {
                    'timestamp': ts.isoformat(),
                    'log_count': count,
                    'expected_count': mean_count,
                    'deviation': (count - mean_count) / std_count if std_count > 0 else 0
                }
                for ts, count in anomalies.items()
            ],
            'total_anomalies': len(anomalies),
            'mean_log_count': mean_count,
            'std_log_count': std_count
        }
        
        logger.info(f"Detected {len(anomalies)} time windows with anomalous log frequencies")
        return anomaly_results
        
    except Exception as e:
        logger.error(f"Error detecting anomalies in log frequency: {e}")
        return {}

def analyze_auth_logs(logs):
    """Analyze authentication logs for suspicious activities."""
    logger.info("Analyzing authentication logs")
    
    if logs.empty:
        logger.warning("No logs to analyze")
        return {}
        
    # Filter for authentication logs
    auth_logs = logs[logs['log_type'] == 'auth']
    
    if auth_logs.empty:
        logger.warning("No authentication logs found")
        return {}
        
    try:
        # Look for failed login attempts
        failed_login_pattern = re.compile(r'authentication failure|failed password|Failed password')
        failed_logins = auth_logs[auth_logs['message'].str.contains(failed_login_pattern, regex=True, na=False)]
        
        # Look for successful logins
        success_login_pattern = re.compile(r'session opened for user')
        successful_logins = auth_logs[auth_logs['message'].str.contains(success_login_pattern, regex=True, na=False)]
        
        # Extract usernames from successful logins
        username_pattern = re.compile(r'session opened for user (\S+)')
        successful_logins['username'] = successful_logins['message'].str.extract(username_pattern)
        
        # Get counts by username
        user_login_counts = successful_logins['username'].value_counts().to_dict()
        
        # Identify root logins
        root_logins = successful_logins[successful_logins['username'] == 'root']
        
        # Identify SSH logins
        ssh_logins = successful_logins[successful_logins['message'].str.contains('sshd', na=False)]
        
        auth_analysis = {
            'total_auth_logs': len(auth_logs),
            'failed_login_attempts': len(failed_logins),
            'successful_logins': len(successful_logins),
            'root_logins': len(root_logins),
            'ssh_logins': len(ssh_logins),
            'user_login_counts': user_login_counts,
            'auth_source_ip_counts': {},  # Placeholder for extracting IPs
            'suspicious_activities': []
        }
        
        # Identify suspicious activities
        if len(failed_logins) > 10:
            auth_analysis['suspicious_activities'].append(
                f"High number of failed login attempts: {len(failed_logins)}"
            )
            
        if len(root_logins) > 0:
            auth_analysis['suspicious_activities'].append(
                f"Direct root logins detected: {len(root_logins)}"
            )
            
        logger.info(f"Analyzed {len(auth_logs)} authentication logs")
        return auth_analysis
        
    except Exception as e:
        logger.error(f"Error analyzing authentication logs: {e}")
        return {}

def save_analysis_results(results, output_path):
    """Save analysis results to a file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Analysis results saved to {output_path}")

def run_log_analysis(config_path):
    """Run log analysis with the specified configuration."""
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
            
        # Connect to Elasticsearch
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        
        # Load logs
        logs = load_logs_from_elasticsearch(
            es,
            'filebeat-*',  # Use filebeat data
            '1d'  # Use the last day of data
        )
        
        if logs.empty:
            logger.error("No logs available for analysis")
            return
            
        # Define patterns to extract
        patterns = {
            'ssh_login_failure': {
                'regex': r'Failed password for (\S+) from (\S+) port (\d+)'
            },
            'sudo_command': {
                'regex': r'sudo:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)'
            }
        }
        
        # Extract patterns
        pattern_results = extract_patterns(logs, patterns)
        
        # Cluster log messages
        cluster_results = cluster_log_messages(logs)
        
        # Detect anomalies
        anomaly_results = detect_anomalies(logs)
        
        # Analyze authentication logs
        auth_analysis = analyze_auth_logs(logs)
        
        # Combine results
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'log_count': len(logs),
            'log_types': logs['log_type'].value_counts().to_dict(),
            'hosts': logs['host'].value_counts().to_dict(),
            'pattern_analysis': pattern_results,
            'cluster_analysis': cluster_results,
            'anomaly_detection': anomaly_results,
            'auth_analysis': auth_analysis,
            'time_range': [
                logs['timestamp'].min().isoformat() if not logs.empty and not pd.isna(logs['timestamp'].min()) else None,
                logs['timestamp'].max().isoformat() if not logs.empty and not pd.isna(logs['timestamp'].max()) else None
            ]
        }
        
        # Save results
        output_path = os.path.join(
            config.get('output', {}).get('directory', 'results'),
            'log_analysis.json'
        )
        save_analysis_results(analysis_results, output_path)
        
        # Index results to Elasticsearch
        try:
            index_name = config['elk']['elasticsearch']['indices'].get('log_analysis', 'security-log-analysis')
            es.index(index=index_name, document=analysis_results)
            logger.info(f"Analysis results indexed to {index_name}")
        except Exception as e:
            logger.error(f"Error indexing analysis results: {e}")
            
    except Exception as e:
        logger.error(f"Error in log analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analysis")
    parser.add_argument("--config", type=str, default="config/server_config.json",
                      help="Path to the configuration file")
                      
    args = parser.parse_args()
    run_log_analysis(args.config)
=======

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

def analyze_logs(data, config):
    analysis_results = {}
    
    for pattern_name, pattern_config in config['patterns'].items():
        regex = re.compile(pattern_config['regex'])
        matches = data['message'].str.extract(regex)
        
        analysis_results[pattern_name] = {
            'count': len(matches),
            'samples': matches.head(pattern_config['max_samples']).tolist()
        }
    
    return analysis_results

def run_log_analysis(config):
    data = load_data(config['data']['path'])
    analysis_results = analyze_logs(data, config['analysis'])
    
    output_path = config['output']['path']
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(analysis_results, f)
    
    logger.info(f"Log analysis completed. Results saved to {output_path}")
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/log_analysis_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_log_analysis(config)
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
