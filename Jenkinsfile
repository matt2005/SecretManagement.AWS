// Config
class Globals {
   static String JenkinsChannel = '#jenkins-channel'
}

// Workflow Steps
pipeline {
  agent {node { label ("windows&&internal&&management&&server") }}
  options {
    skipStagesAfterUnstable()
    ansiColor('xterm')
  }
  stages {
    stage('Stage 0: Prepare') {
      steps {
        scmSkip(deleteBuild: true)
        script {
          try {
            notifyBuild()
            posh '"Git Branch is $ENV:GIT_BRANCH"'
            posh '"Local Git Branch is $ENV:GIT_LOCAL_BRANCH"'
            posh 'if (-not(Get-Module -ListAvailable).Where{$_.Name -eq "InvokeBuild"}){throw "InvokeBuild Missing"}'
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
    stage('Stage 1: Clean') {
      steps {
        script {
          try {
            posh 'Import-Module InvokeBuild -force'
            posh 'Invoke-Build Clean'
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
    stage('Stage 2: Analyze') {
      steps {
        script {
          try {
            posh 'Import-Module InvokeBuild -force'
            posh 'Invoke-Build Analyze'
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
    stage('Stage 3: BuildPSM1') {
      steps {
        script {
          try {
            posh 'Import-Module InvokeBuild -force'
            posh 'Invoke-Build BuildPSM1'
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
    stage('Stage 4: Test') {
      steps {
        script {
          try {
            posh 'Import-Module InvokeBuild -force'
            posh 'Invoke-Build RunTests'
            step([$class: 'NUnitPublisher',
            testResultsPattern: 'artifacts\\*.xml',
            debug: false,
            keepJUnitReports: true,
            skipJUnitArchiver:false,
            failIfNoResults: false
            ])
            posh 'Invoke-Build PublishTestResults'
            publishHTML (target: [
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: 'artifacts\\TestReport',
            reportFiles: 'TestReport.htm,PSCodeHealthReport.html',
            reportName: "Coverage"
            ])
            posh 'Invoke-Build ConfirmTestsPassed'
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
    stage('Stage 5: Archive') {
      steps {
        script {
          try {
            posh 'Import-Module InvokeBuild -force'
            posh 'Invoke-Build Archive'
            archiveArtifacts artifacts: "artifacts/*.zip", onlyIfSuccessful: true
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
    stage('Stage 6: Publish') {
      //when {
       //anyOf { branch 'master';branch 'beta' }
       //not { equals expected: 1, actual: currentBuild.number}
      //}
      steps {
        script {
          try {
            timeout(20) {
                posh 'Invoke-Build PublishNuget'
            }
          } catch (e) {
            currentBuild.result = "FAILED"
            throw e
          } finally {
                notifyBuild(currentBuild.result)
          }
        }
      }
      post {
        failure {
          error "This pipeline stops here!"
        }
      }
    }
  }
  post {
    always {
      echo "${env.BUILD_URL}"
    }
    success {
      echo "currentBuild.result"
    }
    unstable {
      notifyBuild(currentBuild.result)
    }
    failure {
      notifyBuild(currentBuild.result)
    }
    changed {
      echo "${env.BUILD_URL}"
    }
  }
}

// Helper function to run PowerShell Commands
def posh(cmd) {
  ansiColor('xterm'){
    powershell(cmd)
  }
}

// Helper function to Broadcast Build to Slack
def notifyBuild(String buildStatus = 'STARTED') {
  buildStatus = buildStatus ?: 'SUCCESSFUL'
  def colorCode = '#FF0000' // Failed : Red
  def status = 'Running'
  if (buildStatus == 'STARTED') {
    colorCode = '#FFFF00'
    status = 'Started'
  } // STARTED: Yellow
  else if (buildStatus == 'SUCCESSFUL') {
    colorCode = '#00FF00'
    status = 'Finished'
  } // SUCCESSFUL: Green
  def message = "${status}: ${env.JOB_NAME} ${env.BUILD_NUMBER} (<${env.BUILD_URL}|Open>)"
  def webhook = "${env.Office365TeamsWebhookURL}"
  office365ConnectorSend(color: colorCode, webhookUrl: webhook, message: message, status: buildStatus)
}





