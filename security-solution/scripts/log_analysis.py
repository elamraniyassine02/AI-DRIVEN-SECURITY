import argparse
import json
import logging
from datetime import datetime, timedelta

import pandas as pd
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def remove_empty_keys(obj):
    """
    Recursively remove keys with empty string from dictionaries.
    """
    if isinstance(obj, dict):
        return {k: remove_empty_keys(v) for k, v in obj.items() if k != ""}
    elif isinstance(obj, list):
        return [remove_empty_keys(i) for i in obj]
    else:
        return obj

def load_logs(es, index_pattern, time_field="@timestamp", days=1):
    now = datetime.utcnow()
    start_time = now - timedelta(days=days)
    query = {
        "query": {
            "range": {
                time_field: {
                    "gte": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "lte": now.strftime("%Y-%m-%dT%H:%M:%SZ")
                }
            }
        },
        "size": 10000
    }
    try:
        result = es.search(index=index_pattern, body=query)
        hits = result.get("hits", {}).get("hits", [])
        logs = [h["_source"] for h in hits]
        logger.info(f"Loaded {len(logs)} logs from Elasticsearch")
        return logs
    except Exception as e:
        logger.error(f"Error loading logs: {e}")
        return []

def extract_patterns(logs):
    patterns = {
        "ssh_login_failure": [],
        "sudo_command": [],
        # add other patterns as needed
    }
    for log in logs:
        msg = log.get("message", "")
        if "Failed password for" in msg:
            patterns["ssh_login_failure"].append(log)
        if "sudo" in msg:
            patterns["sudo_command"].append(log)
    return patterns

def cluster_logs(logs):
    # Dummy implementation (replace with real clustering if needed)
    clusters = {}
    for i, log in enumerate(logs):
        key = f"cluster_{i % 10}"
        if key not in clusters:
            clusters[key] = []
        clusters[key].append(log)
    return clusters

def analyze_log_frequency(logs):
    # Dummy implementation (replace with real frequency analysis)
    time_buckets = {}
    for log in logs:
        ts = log.get("@timestamp", "")[:13]  # Hourly bucket
        if ts not in time_buckets:
            time_buckets[ts] = 0
        time_buckets[ts] += 1
    # Simulate detection: No anomalies for demo
    anomalies = []
    return anomalies

def analyze_authentication(logs):
    # Dummy implementation (replace with real authentication analysis)
    auth_logs = [log for log in logs if "auth" in log.get("source", "")]
    return auth_logs

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, required=True)
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])

    index_pattern = "filebeat-*"
    logs = load_logs(es, index_pattern, days=1)

    logger.info("Extracting patterns from logs")
    patterns = extract_patterns(logs)
    for pname, plogs in patterns.items():
        logger.info(f"Extracting pattern: {pname}")
        if plogs:
            logger.info(f"Found {len(plogs)} matches for pattern {pname}")
        else:
            logger.info(f"No matches found for pattern {pname}")

    logger.info("Clustering log messages")
    clusters = cluster_logs(logs)
    logger.info(f"Found {len(clusters)} log clusters")

    logger.info("Detecting anomalies in log frequency")
    freq_anomalies = analyze_log_frequency(logs)
    logger.info(f"Detected {len(freq_anomalies)} time windows with anomalous log frequencies")

    logger.info("Analyzing authentication logs")
    auth_logs = analyze_authentication(logs)
    if auth_logs:
        logger.info(f"Found {len(auth_logs)} authentication logs")
    else:
        logger.warning("No authentication logs found")

    analysis_results = {
        "timestamp": datetime.utcnow().isoformat(),
        "pattern_matches": {k: len(v) for k, v in patterns.items()},
        "num_clusters": len(clusters),
        "cluster_keys": list(clusters.keys()),
        "freq_anomalies": freq_anomalies,
        "auth_logs_count": len(auth_logs)
    }

    # Clean analysis_results of empty keys
    analysis_results = remove_empty_keys(analysis_results)

    # Save to file
    with open("results/log_analysis.json", "w") as f:
        json.dump(analysis_results, f, indent=2)
    logger.info("Analysis results saved to results/log_analysis.json")

    # Index to Elasticsearch
    try:
        index_name = config['elk']['elasticsearch']['indices'].get('log_analysis', 'security-log-analysis')
        es.index(index=index_name, document=analysis_results)
        logger.info(f"Analysis results indexed to {index_name}")
    except Exception as e:
        logger.error(f"Error indexing analysis results: {e}")

if __name__ == "__main__":
    main()
