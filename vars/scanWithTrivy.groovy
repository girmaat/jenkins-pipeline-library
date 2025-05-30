// vars/scanWithTrivy.groovy
import org.yourorg.ci.script.TrivyScanner

/**
 * Jenkins shared library entrypoint
 * @param config - Map with the following keys:
 *     image (String)           : Docker image name with tag
 *     failOnVuln (Boolean)     : Whether to fail pipeline on findings
 *     archiveReport (Boolean)  : Whether to archive Trivy scan report
 *     sbom (Boolean)           : Whether to generate SBOM in CycloneDX format
 */
def call(Map config = [:]) {
    def scanner = new TrivyScanner(this) // Injects pipeline DSL steps like `sh`, `echo`, etc.
    scanner.runScan(config)
}
