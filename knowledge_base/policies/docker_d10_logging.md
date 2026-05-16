# D10 - Docker Logging Best Practices

## What must be logged
- Container start, stop, restart events
- Failed authentication attempts
- Privilege escalation attempts inside containers
- Unexpected outbound connections
- File system modifications outside expected paths

## Centralized logging requirement
Individual container logs are lost when containers restart.
All logs must be forwarded to centralized logging system.
Without centralized logs, post-breach forensics is impossible.

## Log what attackers try to hide
- Commands run as root inside containers
- New processes spawned by application processes
- Unexpected network connections
- Large data transfers

## Common misconfiguration
Docker default logging driver: json-file with no rotation.
Logs fill disk, causing container crashes and service outages.
Always configure log rotation: --log-opt max-size=10m --log-opt max-file=3
