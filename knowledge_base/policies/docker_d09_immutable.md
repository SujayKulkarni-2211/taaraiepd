# D09 - Follow Immutable Paradigm

## What immutable means
Containers should never be modified after deployment.
No SSH into running containers. No package installs at runtime.
If something needs to change, build a new image and redeploy.

## Why this matters for security
Mutable containers hide attack evidence.
An attacker who gains container access can install tools, modify files, exfiltrate data.
If containers are mutable, forensic analysis is impossible.

## Patterns that violate immutability
- RUN apt-get install in entrypoint scripts (installs at runtime)
- Volumes mounted read-write unnecessarily
- Running containers as root (enables modification)
- SSH daemon running inside containers

## Crash risk from mutability
Mutable containers drift from their definition over time.
A container that was patched manually cannot be reproduced exactly.
When it crashes and needs replacement, the new container lacks the manual patches.
This causes intermittent failures that are impossible to reproduce in development.
