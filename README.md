# Utility Scripts
Cross-platform administrative tooling for Windows and Linux environments. Designed for small and medium organizations that need fast, repeatable, and secure local machine configuration.

These scripts were built with real world IT workflows in mind: Onboard/Offboarding users, Auditing local policy, Verifying system integrity and applying basline hardening without requiring management tools lime Intune, Puppet or AD Group Policy.

## Utility.ps1
A modular Powershell toolset focused on local security posture, user management, and administrative QOL tasks.

Features:
Feature | Information
--- | --- 
Baseline security policy (auto) | Applies a curated set of recommended Local Security Options to harden standalone Windows systems. Fully script-driven, repeatable, and reversible.
Manage user accounts | Enumerates, creates, disables, and audits local accounts with strict validation and error handling.
User rights assignments | Retrieves and displays privilege assignments (e.g., SeBackupPrivilege, SeDebugPrivilege) using programmatic inspection of local policy. Useful for auditing principle-of-least-privilege violations.
Hashing Utility | Provides rapid hashing of any file using multiple algorithms for integrity checks during incident response or forensic analysis.


## Utility.sh
A simplified but highly portable administrative helper for Ubuntu based systems.
Features:
Feature | Information
--- | --- 
Manage user accounts | Automates user creation, removal, privilege adjustments, and group assignment with built-in validation for safe system changes.


