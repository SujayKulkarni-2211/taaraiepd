# Vibe Coding Era — Security and Crash Risk Patterns
## Source: Research synthesis from CSA, Checkmarx, IEEE-ISTAS, Infosecurity Magazine (2025-2026)

## Key Statistics
- AI-generated code has 2.74x more security vulnerabilities than human-written code
- XSS vulnerabilities found in 86% of AI-generated code samples (Georgetown CSET)
- AI-assisted commits introduce secrets at 3.2% vs 1.5% baseline (2x increase)
- 20% of AI-recommended packages do not exist — "slopsquatting" attack surface
- CVEs from AI-generated code: 6 (Jan 2026) → 15 (Feb 2026) → 35 (Mar 2026)
- Misconfigurations 75% more frequent in AI-generated code

## Critical Risk Patterns

### 1. Slopsquatting
AI hallucinates package names that don't exist. Attackers register those names with malware.
Risk: Dependency install silently installs malicious package.
Detection: Check every dependency against known registries before install.

### 2. Secret Sprawl
AI-generated code hardcodes credentials "temporarily". They become permanent.
GitHub Actions logs expose secrets when workflows print environment variables.
Risk: Credential theft, full infrastructure compromise.
Detection: Scan all code and workflow logs for credential patterns.

### 3. GitHub Actions Supply Chain
tj-actions/changed-files compromise hit 23,000 repositories (March 2025).
Attacker compromises one widely-used Action, all downstream workflows affected.
Risk: CI/CD secrets exfiltrated, malicious code injected into builds.
Detection: Pin all Actions to specific commit SHA, not mutable tags.

### 4. Cascade from Schema Changes
Single DROP COLUMN triggered cascade across 5 services — 22-minute outage (May 2026).
Schema change broke API contract, which broke dependent service, which caused queue backpressure.
Risk: One migration takes down multiple services with no obvious connection.
Detection: Map all service dependencies on database schema before any migration.

### 5. Dependency Confusion
Internal package names resolved to public registry malicious packages.
Risk: Build environment compromised, backdoors injected silently.
Detection: Explicitly scope all internal packages, audit registry resolution order.

### 6. Circular Service Dependencies
Microservices copied from tutorials create circular call chains.
Works under normal load, deadlocks under high load or when one service slows.
Risk: Single slow service causes full system deadlock.
Detection: Build service dependency graph, check for cycles.

### 7. Zombie Infrastructure
Cloud resources spun up for testing, never shut down.
Risk: Unmonitored attack surface, unnecessary cost, compliance gap.
Detection: Audit all running resources against known active services.

## Real Incidents
- Moltbook (Jan 2026): AI-built app exposed 1.5M tokens, 35k emails in 3 days. Founder wrote zero lines of code.
- tj-actions/changed-files (Mar 2025): 23,000 repositories compromised via GitHub Actions supply chain.
- Cloudflare (Nov 2025): Permission change in bot-detection DB caused file to exceed limits, propagated system-wide outage.
- Spring Boot → Go migration: $2.4M loss, 8 engineers left, 14-month delay.
