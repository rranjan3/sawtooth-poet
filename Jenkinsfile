#!groovy

// Copyright 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------------

// Discard old builds after 31 days
properties([[$class: 'BuildDiscarderProperty', strategy:
        [$class: 'LogRotator', artifactDaysToKeepStr: '',
        artifactNumToKeepStr: '', daysToKeepStr: '31', numToKeepStr: '']]]);

node ('master') {
    timestamps {
        // Create a unique workspace so Jenkins doesn't reuse an existing one
        ws("workspace/${env.BUILD_TAG}") {
            stage("Clone Repo") {
                checkout scm
                sh 'git fetch --tag'
            }

            if (!(env.BRANCH_NAME == 'poet2-dev' && env.JOB_BASE_NAME == 'poet2-dev')) {
                stage("Check Whitelist") {
                    readTrusted 'bin/whitelist'
                    sh './bin/whitelist "$CHANGE_AUTHOR" /etc/jenkins-authorized-builders'
                }
            }

            stage("Check for Signed-Off Commits") {
                sh '''#!/bin/bash -l
                    if [ -v CHANGE_URL ] ;
                    then
                        temp_url="$(echo $CHANGE_URL |sed s#github.com/#api.github.com/repos/#)/commits"
                        pull_url="$(echo $temp_url |sed s#pull#pulls#)"
                        IFS=$'\n'
                        for m in $(curl -s "$pull_url" | grep "message") ; do
                            if echo "$m" | grep -qi signed-off-by:
                            then
                              continue
                            else
                              echo "FAIL: Missing Signed-Off Field"
                              echo "$m"
                              exit 1
                            fi
                        done
                        unset IFS;
                    fi
                '''
            }

            // Set the ISOLATION_ID environment variable for the whole pipeline
            env.ISOLATION_ID = sh(returnStdout: true, script: 'printf $BUILD_TAG | sha256sum | cut -c1-64').trim()
            env.COMPOSE_PROJECT_NAME = sh(returnStdout: true, script: 'printf $BUILD_TAG | sha256sum | cut -c1-64').trim()

            // Run lint checks
            stage("Run Lint") {
                // Run docker build on simulator and hardware both one at a
                // time, to generate required artifacts and then perform lint
                // checks
                sh 'docker-compose -f docker-poet-build.yaml up'
                sh 'docker-compose -f run-lint.yaml up --abort-on-container-exit --exit-code-from lint-rust lint-rust'
                sh 'docker-compose -f clippy-poet.yaml up --abort-on-container-exit --exit-code-from poet-engine-clippy poet-engine-clippy'
                sh 'docker-compose -f docker-poet-hw-build.yaml up'
                sh 'docker-compose -f run-lint.yaml up --abort-on-container-exit --exit-code-from lint-rust lint-rust'
                sh 'docker-compose -f clippy-poet.yaml up --abort-on-container-exit --exit-code-from poet-engine-clippy poet-engine-clippy'
            }

            // Run the tests
            stage("Run Tests") {
                sh './bin/run_docker_test tests/unit-poet.yaml'
                sh './bin/run_docker_test tests/unit-ias-client.yaml'
                // TODO: Enable this when IAS proxy is made use
                // sh './bin/run_docker_test tests/unit-ias-proxy.yaml'
                sh '''
                  docker rm -f \
                    $(docker ps -f "label=com.sawtooth.isolation_id=${ISOLATION_ID}" \
                    | awk {\'if(NR>1)print $1\'}) &> /dev/null
                '''
            }

            // Build PoET2
            stage("Build PoET2") {
              sh "docker-compose -f docker-compose-installed.yaml build"
            }

            stage("Archive Build Artifacts") {
                sh 'docker-compose -f copy-debs.yaml up'
                sh 'docker-compose -f copy-debs.yaml down'
                archiveArtifacts artifacts: '*_amd64.deb'
            }
        }
    }
}
