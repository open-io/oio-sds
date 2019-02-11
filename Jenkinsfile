pipeline {
    agent any
    stages {
        stage('Test') {
            agent {
                docker {
                    image 'ubuntu:18.04'
                    args '-u root:root'
                }
            }
            steps {
                sh '''
                useradd --create-home openio

                cp -rf . /home/openio/build
                chown -R openio:openio /home/openio/build

                ./jenkins/prepare.sh

                su - openio -c "cd /home/openio/build && ./jenkins/build.sh"
                '''
            }
        }
    }
}
