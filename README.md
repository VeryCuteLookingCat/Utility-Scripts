# Utility Tooling (Windows & Linux)

Standalone security operations tooling for unmanaged or incident response environments.
Designed for rapid auditing, hardening, and local policy inspection without reliance on centralized management (AD, Intune, Puppet).

## Windows (PowerShell):
- Programmatic inspection of Local Security Policy and user rights assignments (e.g., SeDebugPrivilege, SeBackupPrivilege)
- Automated application of hardened baseline security configurations with full rollback support
- Local account enumeration and privilege auditing for least-privilege violations
- File hashing utilities for integrity verification during forensic workflows

## Linux (Bash):
- Baseline system hardening for Ubuntu-based hosts
- Comprehensive startup persistence audit (cron, systemd, user autostart)
- Open port and service inspection mapped to owning processes
- Security posture dashboard (users, sudo access, services, firewall, updates)
