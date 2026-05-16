# GitHub Actions Security Rules
## Sources: OWASP CI/CD Top 10, tj-actions incident (March 2025), GitHub Security Advisories

## CRITICAL violations
- Using mutable action tags: uses: actions/checkout@v3 (v3 can change)
  Fix: Pin to commit SHA: uses: actions/checkout@abc123def456
- Printing secrets in logs: run: echo ${{ secrets.API_KEY }}
  Risk: Secret exposed in public workflow logs permanently
- Untrusted input in run steps: run: echo ${{ github.event.issue.title }}
  Risk: Script injection — attacker controls issue title, injects commands
- GITHUB_TOKEN with excessive permissions
  Fix: Set permissions: read-all at top, grant write only where needed

## HIGH violations  
- Third-party actions with suspicious update patterns
  Risk: Supply chain attack (tj-actions hit 23,000 repos)
- pull_request_target trigger with checkout of PR code
  Risk: Malicious PR code runs with write permissions
- Self-hosted runners on shared infrastructure
  Risk: Poisoned pipeline execution
- Secrets accessible to all jobs in workflow
  Fix: Scope secrets to specific jobs only

## Real incident: tj-actions/changed-files (March 2025)
Attack vector: Compromised GitHub token used to push malicious tag
Impact: 23,000+ repositories had CI/CD secrets exfiltrated
Pattern: Workflow used actions/changed-files@v45, attacker changed v45 tag
Detection: Monitor action SHA changes, not tag changes

## Slopsquatting in Actions
AI suggests uses: actions/setup-python@v4.5.0 — this version may not exist
Attacker registers the package name at that version with malicious code
Risk: Build environment silently compromised

## Secure workflow template
permissions:
  contents: read
  
jobs:
  build:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # pin SHA
        with:
          persist-credentials: false  # don't leave token on filesystem
