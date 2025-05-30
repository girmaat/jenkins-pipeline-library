// src/org/yourorg/ci/script/TrivyScanner.groovy
package org.yourorg.ci.script

class TrivyScanner implements Serializable {
    def steps

    TrivyScanner(steps) {
        this.steps = steps
    }

    def runScan(Map config) {
        String imageName     = config.get('image', 'my-app:latest')
        boolean failOnVuln   = config.get('failOnVuln', true)
        boolean archive      = config.get('archiveReport', true)
        boolean sbom         = config.get('sbom', false)

        steps.echo "Starting Trivy Scan..."
        steps.echo " Image: ${imageName}"
        steps.echo "Fail on Vulnerabilities: ${failOnVuln}"
        steps.echo "Archive Report: ${archive}"
        steps.echo "Generate SBOM: ${sbom}"

        String scanCommand = """
            trivy image \
              --severity HIGH,CRITICAL \
              --format json \
              --output trivy-report.json \
              ${failOnVuln ? '--exit-code 1' : '--exit-code 0'} \
              ${imageName}
        """.stripIndent()

        try {
            steps.sh scanCommand
        } catch (Exception e) {
            steps.echo "Trivy scan failed: ${e.message}"
            if (failOnVuln) {
                steps.error("Pipeline aborted due to vulnerabilities in image: ${imageName}")
            } else {
                steps.echo "Ignored failure due to 'failOnVuln = false'"
            }
        }

        if (archive) {
            steps.archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
        }

        if (sbom) {
            steps.sh "trivy image --format cyclonedx -o sbom.xml ${imageName}"
            steps.archiveArtifacts artifacts: 'sbom.xml', fingerprint: true
        }

        steps.echo "Trivy scan completed for: ${imageName}"
    }
}
