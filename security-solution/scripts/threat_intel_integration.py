import json
import logging
import argparse
import os
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

def load_indicators(indicators_path):
    with open(indicators_path, 'r') as f:
        return json.load(f)

def save_indicators(indicators, path):
    with open(path, 'w') as f:
        json.dump(indicators, f, indent=2)

def index_threat_intel(es, index, indicators):
    actions = []
    for indicator_type, items in indicators.items():
        for ind in items:
            doc = ind.copy()
            doc["@timestamp"] = datetime.utcnow().isoformat()
            doc["type"] = indicator_type
            actions.append({"index": {"_index": index}})
            actions.append(doc)
    if actions:
        bulk_body = "\n".join([json.dumps(act) for act in actions]) + "\n"
        resp = es.bulk(body=bulk_body, refresh=True)
        errors = resp.get('errors', False)
        if not errors:
            logging.info(f"Successfully indexed {len(actions)//2} threat intelligence indicators, errors: {resp.get('items', [])}")
        else:
            logging.error(f"Bulk indexing errors: {resp}")
    else:
        logging.info("No indicators to index.")

def correlate_threat_intel(es, index, indicators):
    # Collect all indicator values as sets of strings (not dicts)
    ip_set = set(ind['indicator'] for ind in indicators.get('ip', []))
    domain_set = set(ind['indicator'] for ind in indicators.get('domain', []))
    url_set = set(ind['indicator'] for ind in indicators.get('url', []))
    hash_set = set(ind['indicator'] for ind in indicators.get('hash', []))

    # Example: search logs for matching indicators (this logic can be adapted)
    query = {
        "size": 4000,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": (datetime.utcnow() - timedelta(days=1)).isoformat(),
                    "lte": datetime.utcnow().isoformat()
                }
            }
        }
    }
    result = es.search(index="filebeat-*", body=query)
    hits = result.get('hits', {}).get('hits', [])
    logging.info(f"Loaded {len(hits)} logs for correlation")
    correlations = 0
    for hit in hits:
        src = hit['_source']
        matched = False
        # Only check if the fields exist
        if 'ip' in src and src['ip'] in ip_set:
            matched = True
        if 'domain' in src and src['domain'] in domain_set:
            matched = True
        if 'url' in src and src['url'] in url_set:
            matched = True
        if 'hash' in src and src['hash'] in hash_set:
            matched = True
        if matched:
            correlations += 1
    logging.info(f"Found {correlations} correlations between logs and threat intelligence")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=True)
    args = parser.parse_args()
    config = load_config(args.config)

    logging.info("Loading threat intelligence")

    # Load threat intelligence sources
    indicators = {"ip": [], "domain": [], "url": [], "hash": []}
    for source in config.get("sources", []):
        try:
            if source['type'] == 'file':
                logging.info(f"Loading threat intelligence from {source['name']}")
                if not os.path.exists(source['path']):
                    logging.warning(f"Threat intelligence source file {source['path']} does not exist")
                    continue
                with open(source['path'], 'r') as f:
                    data = json.load(f)
                # File may be dict or list. Accept both.
                if isinstance(data, dict):
                    for k in indicators.keys():
                        indicators[k].extend(data.get(k, []))
                elif isinstance(data, list):
                    # Assume list of mixed indicators, try to categorize by type
                    for ind in data:
                        t = ind.get('type')
                        if t in indicators:
                            indicators[t].append(ind)
                else:
                    logging.warning(f"Threat intelligence format for {source['name']} not recognized.")
                logging.info(f"Loaded threat intelligence from {source['path']}")
        except Exception as e:
            logging.error(f"Error loading threat intelligence from {source['name']}: {e}")

    # Count indicators by type
    logging.info(
        f"Loaded {sum(len(v) for v in indicators.values())} threat intelligence indicators: "
        f"{len(indicators['ip'])} ip, {len(indicators['domain'])} domain, "
        f"{len(indicators['url'])} url, {len(indicators['hash'])} hash"
    )

    # Save indicators to type-specific files (optional, if needed by your workflow)
    for t in indicators:
        path = config["indicators"].get(t)
        if path:
            save_indicators(indicators[t], path)
            logging.info(f"Saved {len(indicators[t])} {t} indicators to {path}")

    # Connect to Elasticsearch
    es_host = config.get("elk_index", "security-threat-intel")
    es = Elasticsearch(config["elk"].get("elasticsearch", {}).get("hosts", ["http://localhost:9200"]))
    # Index to ES
    logging.info(f"Indexing threat intelligence to {es_host}")
    index_threat_intel(es, es_host, indicators)

    # Correlate with logs
    logging.info("Correlating threat intelligence with logs")
    try:
        correlate_threat_intel(es, es_host, indicators)
    except Exception as e:
        logging.error(f"Error in threat intelligence integration: {e}")

if __name__ == '__main__':
    main()
