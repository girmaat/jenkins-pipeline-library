package org.testorg.ci.script

class TrivyScanner implements Serializable {
    def steps

    TrivyScanner(steps) {
        this.steps = steps
    }

    /**
     * Executes Trivy vulnerability scan and manages report generation/archiving.
     */
    def runScan(Map config) {
        String imageName   = config.get('image', 'my-app:latest')
        boolean failOnVuln = config.get('failOnVuln', true)
        boolean archive    = config.get('archiveReport', true)
        boolean sbom       = config.get('sbom', false)

        steps.echo "Starting Trivy Scan..."
        steps.echo " Image: ${imageName}"
        steps.echo "Fail on Vulnerabilities: ${failOnVuln}"
        steps.echo "Archive Report: ${archive}"
        steps.echo "Generate SBOM: ${sbom}"

        String scanCommand = """
            trivy image \\
            --severity HIGH,CRITICAL \\
            --ignore-unfixed \\
            --ignorefile .trivyignore \\
            --format json \\
            --output trivy-report.json \\
            ${failOnVuln ? '--exit-code 1' : '--exit-code 0'} \\
            ${imageName}
        """.stripIndent()

        boolean scanFailed = false

        try {
            steps.sh scanCommand
        } catch (Exception e) {
            scanFailed = true
            steps.echo "⚠️ Trivy scan failed (non-blocking): ${e.message}"
        }

        if (archive) {
            steps.archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
            steps.echo "📦 JSON report archived."

            try {
                generateTrivyHtmlReport()
                def reportUrl = "${steps.env.BUILD_URL}artifact/trivy-report.html"
                steps.echo scanFailed ? "⚠️ Trivy scan failed. See: ${reportUrl}" :
                                        "✅ Trivy completed. View report: ${reportUrl}"
            } catch (Exception e) {
                steps.echo "⚠️ Failed to generate HTML report: ${e.message}"
            }

            // Gracefully continue if failOnVuln is false
            if (scanFailed && failOnVuln) {
                steps.error("⛔ Pipeline aborted due to Trivy scan failure.")
            } else if (scanFailed && !failOnVuln) {
                steps.echo "⚠️ Trivy scan had issues, but continuing pipeline."
            }
        }

        if (sbom) {
            try {
                steps.sh "trivy image --format cyclonedx -o sbom.xml ${imageName}"
                steps.archiveArtifacts artifacts: 'sbom.xml', fingerprint: true
                steps.echo "✅ SBOM generated and archived."
            } catch (Exception e) {
                steps.echo "⚠️ Failed to generate SBOM: ${e.message}"
            }
        }
    }

    /**
     * Converts trivy-report.json to trivy-report.html for easier viewing.
     */
    def generateTrivyHtmlReport() {
        def htmlGenScript = '''\
        import json
        from pathlib import Path

        json_file = Path("trivy-report.json")
        html_file = Path("trivy-report.html")

        if not json_file.exists():
            print("JSON report missing. Skipping HTML generation.")
            exit(1)

        report = json.loads(json_file.read_text())
        html = ["<html><head><title>Trivy Report</title>",
                "<style>body{font-family:Arial} h2{color:#b30000} .vuln{margin:10px 0;padding:10px;border:1px solid #ccc}</style>",
                "</head><body><h1>Trivy Security Report</h1>"]

        for r in report.get("Results", []):
            html.append(f"<h2>{r.get('Target')}</h2>")
            for vuln in r.get("Vulnerabilities", []):
                html.append("<div class='vuln'>")
                html.append(f"<b>{vuln['VulnerabilityID']}</b> - {vuln['Severity']}<br>")
                html.append(f"{vuln.get('Title','')}<br>")
                html.append(f"<pre>{vuln.get('Description','')}</pre>")
                html.append("</div>")

        html.append("</body></html>")
        html_file.write_text('\\n'.join(html))
        '''.stripIndent()

        steps.writeFile file: 'gen_trivy_html.py', text: htmlGenScript
        steps.sh 'python3 gen_trivy_html.py'
        steps.archiveArtifacts artifacts: 'trivy-report.html', fingerprint: true
    }
}
