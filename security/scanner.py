import subprocess
import json
import os
import sys

def run_bandit():
    print("Running Bandit SAST...")
    cmd = [sys.executable, "-m", "bandit", "-r", "app/", "-f", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error parsing Bandit output")
        return {}

def run_semgrep():
    print("Running Semgrep SAST...")
    # Using a simple rule set for demonstration
    cmd = ["semgrep", "--config", "auto", "app/", "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error parsing Semgrep output")
        return {}

if __name__ == "__main__":
    bandit_results = run_bandit()
    semgrep_results = run_semgrep()
    
    with open("bandit_report.json", "w") as f:
        json.dump(bandit_results, f, indent=2)
    
    with open("semgrep_report.json", "w") as f:
        json.dump(semgrep_results, f, indent=2)
    
    print("Security scans completed. Reports saved.")
