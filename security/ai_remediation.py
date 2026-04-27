import json
import os
import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def generate_remediation_report():
    if not OPENAI_API_KEY:
        print("OPENAI_API_KEY not set. Skipping AI remediation.")
        return

    print("Generating AI Remediation Report using GPT-4...")
    
    # Load scan results
    vulnerabilities = []
    
    if os.path.exists("bandit_report.json"):
        with open("bandit_report.json", "r") as f:
            bandit = json.load(f)
            for issue in bandit.get("results", []):
                vulnerabilities.append({
                    "tool": "Bandit",
                    "issue": issue["issue_text"],
                    "file": issue["filename"],
                    "line": issue["line_number"],
                    "code": issue["code"]
                })
                
    if os.path.exists("semgrep_report.json"):
        with open("semgrep_report.json", "r") as f:
            semgrep = json.load(f)
            for issue in semgrep.get("results", []):
                vulnerabilities.append({
                    "tool": "Semgrep",
                    "issue": issue["extra"]["message"],
                    "file": issue["path"],
                    "line": issue["start"]["line"],
                    "code": issue["extra"]["lines"]
                })

    if not vulnerabilities:
        with open("remediation_report.md", "w") as f:
            f.write("# Security Remediation Report\n\nNo vulnerabilities found! Great job.")
        return

    # Prepare prompt
    prompt = "As a security expert, review these vulnerabilities and provide secure code fixes in Markdown format:\n\n"
    for v in vulnerabilities:
        prompt += f"### {v['tool']} Issue in {v['file']}:{v['line']}\n"
        prompt += f"**Description**: {v['issue']}\n"
        prompt += f"**Vulnerable Code**:\n```python\n{v['code']}\n```\n\n"
    
    prompt += "Please provide a 'Recommendation' and a 'Secure Example' for each."

    # Call OpenAI API
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": prompt}]
    }
    
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)
    
    if response.status_code == 200:
        report = response.json()["choices"][0]["message"]["content"]
        with open("remediation_report.md", "w") as f:
            f.write("# AI-Augmented Security Remediation Report\n\n")
            f.write(report)
        print("Remediation report generated: remediation_report.md")
    else:
        print(f"Error calling OpenAI API: {response.text}")

if __name__ == "__main__":
    generate_remediation_report()
