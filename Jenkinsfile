pipeline {
    agent any
    stages {
        stage('Tests') {
            parallel {
                stage('3copies') {
                    agent {
                        docker {
                            image 'ubuntu:18.04'
                            args '-u root:root'
                        }
                    }
                    steps {
                        sh '''
                        export
                        useradd --create-home openio

                        cp -rf . /home/openio/build
                        chown -R openio:openio /home/openio/build

                        ./ci/jenkins-prepare.sh

                        su - openio -c "export JENKINS_URL=${JENKINS_URL} TEST_SUITE=${STAGE_NAME} && cd /home/openio/build && ./ci/jenkins-build.sh"
                        '''
                    }
                }
                stage('rebuilder') {
                    agent {
                        docker {
                            image 'ubuntu:18.04'
                            args '-u root:root'
                        }
                    }
                    steps {
                        sh '''
                        export
                        useradd --create-home openio

                        cp -rf . /home/openio/build
                        chown -R openio:openio /home/openio/build

                        ./ci/jenkins-prepare.sh

                        su - openio -c "export JENKINS_URL=${JENKINS_URL} TEST_SUITE=${STAGE_NAME} && cd /home/openio/build && ./ci/jenkins-build.sh"
                        '''
                    }
                }
            }
        }
    }
}
