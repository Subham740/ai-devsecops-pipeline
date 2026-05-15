pipeline {
    agent any

    environment {
        OPENAI_API_KEY = credentials('OPENAI_API_KEY')
        GEMINI_API_KEY = credentials('GEMINI_API_KEY')
        AI_PROVIDER = 'gemini'
        GEMINI_MODEL = 'gemini-2.5-flash'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup & Dependencies') {
            steps {
                sh 'python -m pip install -r requirements.txt bandit safety semgrep requests'
            }
        }

        stage('SAST Scanning') {
            steps {
                sh 'python security/scanner.py'
            }
        }

        stage('AI Remediation') {
            steps {
                sh 'python security/ai_remediation.py'
            }
        }

        stage('Docker Build') {
            steps {
                sh 'docker build -t devsecops-app .'
            }
        }

        stage('Trivy Scan') {
            steps {
                sh 'trivy image --format table --exit-code 0 devsecops-app'
            }
        }

        stage('OWASP ZAP Baseline') {
            steps {
                sh '''
                    DATA_BACKEND=sql DATABASE_PATH=/tmp/devsecops-jenkins.db HOST=127.0.0.1 PORT=5000 FLASK_DEBUG=False python run.py > flask_jenkins.log 2>&1 &
                    for attempt in $(seq 1 30); do
                      curl -fsS http://127.0.0.1:5000/health && break
                      sleep 2
                    done
                    APP_URL=http://host.docker.internal:5000 ZAP_ALLOW_FAILURE=true python security/zap_scan.py
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.json, *.md, *.html', fingerprint: true
        }
    }
}
