import subprocess
import os

def run_zap_scan():
    print("Starting OWASP ZAP Baseline Scan...")
    # In a real environment, you'd run this via docker:
    # docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:5000 -r zap_report.html
    
    target = os.getenv("APP_URL", "http://localhost:5000")
    print(f"Targeting: {target}")
    
    # Mocking ZAP output for the demonstration
    with open("zap_report.html", "w") as f:
        f.write("<html><body><h1>OWASP ZAP Scan Results</h1><p>No high vulnerabilities found.</p></body></html>")
    
    print("ZAP scan completed (Mock). Report saved to zap_report.html")

if __name__ == "__main__":
    run_zap_scan()
