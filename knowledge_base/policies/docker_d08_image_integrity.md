# D08 - Container Image Integrity and Origin

## The vibe coding risk
Developers pull base images without verifying source or integrity.
AI coding tools suggest FROM ubuntu:latest — latest changes silently.
A compromised popular base image affects all downstream images.

## Image integrity patterns
- Always pin to specific digest: FROM ubuntu@sha256:... not FROM ubuntu:latest
- Verify image signatures using Docker Content Trust (DCT)
- Use images from official registries only (docker.io/library/*)
- Scan images for CVEs before deployment: trivy, grype, snyk container

## Supply chain attack indicators
- Base image changed without explicit update
- New layers added to image in registry without corresponding Dockerfile change
- Image digest changed between pulls

## Real incident pattern
SolarWinds-style: attacker compromises base image in registry.
All teams pulling that image get compromised build environment.
No code in their repo changed. No alert fired. Build passed all tests.

## Remediation
- Pin all base images to SHA digest
- Implement automated image scanning in CI/CD
- Monitor base image digests for unexpected changes
- Use private registry for production images
