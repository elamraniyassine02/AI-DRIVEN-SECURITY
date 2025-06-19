#!/usr/bin/env python3
"""
Efficient real log collector for the AI-Driven Security Solution.
Collects local and remote logs and indexes them in Elasticsearch in batches.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from elasticsearch import Elasticsearch

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/real_log_collector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def collect_local_logs(local_files, batch_size=500, index_fn=None):
    """Collect logs from local files in batches and index/process them."""
    logger.info("Collecting logs from local files")
    total = 0
    for log_info in local_files:
        path = log_info.get('path')
        log_type = log_info.get('type', 'unknown')
        if not path or not os.path.isfile(path):
            logger.warning(f"File not found: {path}")
            continue
        logger.info(f"Collecting logs from {path} of type {log_type}")
        batch = []
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                log_entry = {
                    '@timestamp': datetime.now().isoformat(),
                    'message': line.strip(),
                    'log_type': log_type,
                    'source': path,
                    'host': os.uname().nodename
                }
                batch.append(log_entry)
                if len(batch) >= batch_size:
                    if index_fn:
                        index_fn(batch)
                    total += len(batch)
                    batch = []
            # Index any remaining logs
            if batch:
                if index_fn:
                    index_fn(batch)
                total += len(batch)
        logger.info(f"Collected and indexed {total} log entries from {path}")
    return total

def collect_remote_logs(ssh_remote_list, batch_size=500, index_fn=None):
    """(Stub) Collect logs from remote hosts. Extend as needed."""
    logger.info("Collecting logs from remote hosts")
    # You'd implement SSH/SCP or another protocol here if needed.
    # For now, just skip or mock.
    logger.warning("Remote log collection is not implemented in this stub.")
    return 0

def index_logs_to_elasticsearch(es, index_name, log_entries):
    """Index a batch of logs to Elasticsearch using _bulk."""
    if not log_entries:
        return
    actions = []
    for entry in log_entries:
        actions.append({'index': {'_index': index_name}})
        actions.append(entry)
    try:
        es.bulk(body=actions, refresh=True)
        logger.info(f"Indexed {len(log_entries)} log entries to {index_name}")
    except Exception as e:
        logger.error(f"Error indexing logs: {e}")

def run_log_collection(config_path):
    try:
        # Load configuration
        with open(config_path) as f:
            config = json.load(f)
        es = Elasticsearch(hosts=config['elk']['elasticsearch']['hosts'])
        index_name = config['elk']['elasticsearch']['indices'].get('logs', 'security-logs')
        local_files = config.get('local_files', [])
        ssh_remote = config.get('ssh_remote', [])

        # Prepare the indexer function
        def batch_indexer(batch):
            index_logs_to_elasticsearch(es, index_name, batch)

        # Collect and index local logs in batches
        collect_local_logs(local_files, batch_size=500, index_fn=batch_indexer)

        # Optionally, collect remote logs (stub)
        if ssh_remote:
            collect_remote_logs(ssh_remote, batch_size=500, index_fn=batch_indexer)

    except Exception as e:
        logger.error(f"Error in log collection: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Efficient Real Log Collector")
    parser.add_argument("--config", type=str, default="config/elk_config.json",
                        help="Path to the configuration file")
    args = parser.parse_args()
    run_log_collection(args.config)
