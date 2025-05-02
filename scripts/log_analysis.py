import argparse
import json
import logging
import os
import re

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