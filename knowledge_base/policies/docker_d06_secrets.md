# D06 - Protect Secrets in Docker

## Never hardcode secrets in Dockerfiles or images
- Use build args only for non-sensitive values
- Use Docker secrets (swarm) or Kubernetes secrets for sensitive values
- Use environment variables injected at runtime, never baked in

## Secret scanning patterns to detect violations
- Hardcoded AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY in Dockerfile
- Hardcoded DATABASE_URL, DATABASE_PASSWORD in any config file
- Hardcoded API keys, tokens in source code copied into image
- .env files copied into Docker image (COPY . . catches everything including .env)

## GitHub Actions secret exposure patterns
- secrets printed in workflow logs via echo or run commands
- secrets passed as plain text arguments to scripts
- third-party Actions with write access to secrets context

## Risk: Exposed secrets in container images
Docker image layers are immutable. A secret added in one layer and deleted in the next
is still present in the earlier layer and retrievable by anyone with image access.

## Remediation
- Use multi-stage builds to ensure secrets never reach final image
- Use .dockerignore to exclude .env, credentials, key files
- Rotate all secrets immediately if exposure is suspected
- Use tools like truffleHog, git-secrets, gitleaks for scanning
