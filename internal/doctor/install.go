package doctor

// Guidance is the static per-tool install table. Doctor prints it; it never
// runs anything.
type Guidance struct {
	Tool    string
	Purpose string
	Brew    string
	Apt     string
	Release string
}

// Tools scnr can orchestrate (adapters land from Phase 2; doctor already
// reports them so users know what would add coverage).
var Tools = []Guidance{
	{Tool: "nmap", Purpose: "service/version detection, full port ranges", Brew: "brew install nmap", Apt: "sudo apt install nmap", Release: "https://nmap.org/download.html"},
	{Tool: "nuclei", Purpose: "9k+ community web/network templates (safe tags only)", Brew: "brew install nuclei", Apt: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", Release: "https://github.com/projectdiscovery/nuclei/releases"},
	{Tool: "trivy", Purpose: "container image, IaC and SCA breadth", Brew: "brew install trivy", Apt: "sudo apt install trivy  # after adding the Aqua repo", Release: "https://github.com/aquasecurity/trivy/releases"},
	{Tool: "grype", Purpose: "second SCA/image opinion for cross-tool dedupe", Brew: "brew install grype", Apt: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin", Release: "https://github.com/anchore/grype/releases"},
	{Tool: "semgrep", Purpose: "dataflow-aware SAST rules", Brew: "brew install semgrep", Apt: "python3 -m pip install semgrep", Release: "https://github.com/semgrep/semgrep/releases"},
	{Tool: "prowler", Purpose: "AWS/Azure/GCP posture checks", Brew: "pipx install prowler", Apt: "python3 -m pip install prowler", Release: "https://github.com/prowler-cloud/prowler/releases"},
	{Tool: "chromium", Purpose: "JS rendering for SPA crawling (Google Chrome also works)", Brew: "brew install chromium", Apt: "sudo apt install chromium", Release: "https://www.chromium.org/getting-involved/download-chromium/"},
}
