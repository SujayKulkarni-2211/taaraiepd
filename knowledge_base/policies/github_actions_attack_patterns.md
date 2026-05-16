# GitHub Actions Attack Patterns and Exploitation Techniques

## The tj-actions Supply Chain Attack (March 2025)
On March 14, 2025, the `tj-actions/changed-files` action (used by 23,000+ repositories) was compromised. The attacker pushed a malicious commit that caused the action to dump repository secrets directly into GitHub Actions logs. Any repository using this action in a workflow had its secrets — AWS keys, npm tokens, API keys — exposed in plaintext in public logs.

**Root cause:** The action was pinned to a floating tag (`@v35`) rather than a commit SHA. The attacker compromised the maintainer account, moved the tag to point at malicious code. Every repo using `@v35` silently pulled the malicious version on their next CI run.

**Attack chain:**
1. Compromise maintainer's GitHub account (credential theft or stolen PAT)
2. Overwrite floating tag to point at new commit containing secret-dumping code
3. Every repository running CI pulls the new version without noticing
4. Secrets appear in logs — public repos expose them to anyone

---

## Attack Pattern 1: Malicious Action via Floating Tag
Pin to commit SHA: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`
Never use `@v4` or `@main` — tags can be moved, branches change.

## Attack Pattern 2: Script Injection via Untrusted Input
Never interpolate `${{ github.event.pull_request.title }}` directly in `run:` steps.
Use environment variable intermediary to prevent shell injection.

## Attack Pattern 3: pull_request_target with Checkout of Fork
Never checkout PR head SHA in pull_request_target workflows.
This workflow has write access + secrets — running attacker code here is RCE.

## Attack Pattern 4: Secret Exfiltration via npm postinstall
Malicious npm packages scan process.env during install and exfiltrate all CI secrets.
Real cases: event-stream (2018, 8M downloads), ua-parser-js (2021, 8M downloads).

## Attack Pattern 5: GITHUB_TOKEN Over-Permission
Default token has write access to code, PRs, releases.
Set explicit `permissions:` block limiting to minimum required for each job.

## OWASP CI/CD Top 10
- CICD-SEC-1: Insufficient Flow Control — no required approvals
- CICD-SEC-2: Inadequate Identity and Access Management
- CICD-SEC-3: Dependency Chain Abuse — unpinned actions
- CICD-SEC-4: Poisoned Pipeline Execution — attacker code in CI via PR
- CICD-SEC-5: Insufficient PBAC — pipeline over-permissioned
- CICD-SEC-6: Insufficient Credential Hygiene — secrets in logs
- CICD-SEC-7: Insecure System Configuration
- CICD-SEC-8: Ungoverned Third-Party Services
- CICD-SEC-9: Improper Artifact Integrity Validation
- CICD-SEC-10: Insufficient Logging and Visibility
