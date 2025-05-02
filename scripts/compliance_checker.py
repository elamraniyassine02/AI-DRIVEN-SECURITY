import argparse
import json
import logging
import os
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_compliance_check(config):
    results = {}

    for framework, checks in config['frameworks'].items():
        framework_results = []
        
        for check in checks:
            command = check['command'].split()
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                status = 'PASS'
            else:
                status = 'FAIL'
            
            framework_results.append({
                'name': check['name'],
                'command': check['command'],
                'status': status,
                'output': result.stdout
            })
        
        results[framework] = framework_results

    output_path = config['output']['path']  
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Compliance check completed. Results saved to {output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/compliance_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    run_compliance_check(config)