pipeline {
    agent any

    environment {
        PYTHON_VERSION = "3.11"
        DOCKER_IMAGE = "devsecops-app"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup') {
            steps {
                sh 'python3 -m venv venv'
                sh '. venv/bin/activate && pip install --upgrade pip'
                sh '. venv/bin/activate && pip install -r requirements.txt'
                sh '. venv/bin/activate && pip install semgrep'
            }
        }

        stage('Test') {
            steps {
                sh '. venv/bin/activate && python -m unittest discover -s tests -v'
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                sh '. venv/bin/activate && semgrep --config=semgrep.yml app/ ai_fix.py'
            }
        }

        stage('Docker Build') {
            steps {
                sh 'docker build -t ${DOCKER_IMAGE} -f app/Dockerfile .'
            }
        }

        stage('Container Scan (Trivy)') {
            steps {
                // Assuming trivy is installed on the Jenkins node
                sh 'trivy image --severity HIGH,CRITICAL --exit-code 1 ${DOCKER_IMAGE}'
            }
        }

        stage('DAST (OWASP ZAP)') {
            steps {
                // Spin up the application container in background
                sh 'docker run -d -p 5000:5000 --name devsecops-dast-target ${DOCKER_IMAGE}'
                
                // Wait for the app to start
                sh 'sleep 15'
                
                // Run ZAP baseline scan
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'docker run -t owasp/zap2docker-stable zap-baseline.py -t http://172.17.0.1:5000 -I'
                }
                
                // Clean up container
                sh 'docker stop devsecops-dast-target && docker rm devsecops-dast-target'
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
    }
}
