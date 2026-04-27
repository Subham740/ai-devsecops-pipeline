pipeline {
    agent any

    environment {
        OPENAI_API_KEY = credentials('OPENAI_API_KEY')
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
    }

    post {
        always {
            archiveArtifacts artifacts: '*.json, *.md, *.html', fingerprint: true
        }
    }
}
