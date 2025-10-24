# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [2.0.1] - 2025-10-24

### Fixed
- Manage Shares menu: numeric selection and Edit/Remove lists now work reliably when only one share exists.
- Ensured all CLI share lists are treated as arrays to avoid null `.Count` on single-item results.
- Minor robustness improvements for CLI flows across different PowerShell environments.

### Housekeeping
- Bumped version to 2.0.1.

## [2.0.0] - 2025-10-24

Major upgrade from the 1.x line (e.g., v1.1.2 in `Old_Share_Manager.ps1`) to a modern, multi-share architecture with stronger security and improved UX.

### Breaking Changes
- Configuration format changed from single-share `config.json` to multi-share `shares.json`.
- Credential storage changed from AES-encrypted `cred.txt` + `key.bin` to DPAPI-protected `creds.json` (per-user, no key files).
- Some CLI/GUI menu items were renamed or reorganized. Notably, "Reset All" is now "Reconnect All".
- Legacy single-share functions and flows have been replaced with multi-share equivalents (for example, Preferences and Credentials menus now operate on multiple entries).

### Added
- Multi-share management: manage multiple network shares with separate credentials and batch operations (Connect All, Disconnect All, Reconnect All).
- Import/Export with Replace and Merge modes, including duplicate detection.
  - Duplicate rules: a share is considered a duplicate if either DriveLetter or SharePath matches an existing entry.
- Automatic credential prompt: if a referenced username does not exist yet, you will be prompted to create it (CLI and GUI).
- First-time setup improvements: offer to auto-connect shares after saving configuration.
- GUI keyboard and dialog UX improvements:
  - Ctrl+A selects all text in textboxes
  - Enter navigates to next field or triggers the default action (AcceptButton in Preferences)
  - Add/Edit Share dialogs include descriptive hints and examples
- Comprehensive validation script at `Debug/test_syntax.ps1`:
  - Legacy parser (syntax), AST parser (structure), function verb checks, PSScriptAnalyzer, and file encoding
  - Clear pass/fail summary, colorized output, and exit codes for CI use
- Repository PSScriptAnalyzer settings at `Debug/PSScriptAnalyzerSettings.psd1` with documented rule exclusions.

### Changed
- Security: moved from custom AES key files to Windows DPAPI; no separate key files required and encryption is bound to the user account.
- CLI: improved alignment and spacing; reduced redundant pauses; clearer menu labels.
- GUI: improved list and dialogs, real-time status feedback, and fewer redundant popups in backup/restore and credential saves.
- Development workflow: added analyzer settings and consolidated dev assets under `Debug/`.

### Fixed
- Credentials window "Shares Using" column now shows correct counts.
- Removed double pause prompts in backup/restore flow.
- Event handler closures explicitly capture variables (GetNewClosure) to avoid unexpected behavior.
- Variable interpolation corrected in strings (for example, using `${username}:` to avoid scope parsing issues).

### Migration Notes (from 1.x)
- On first run of v2.0.0, credentials are migrated from AES (`cred.txt`/`key.bin`) to DPAPI (`creds.json`) where applicable.
- Configuration moves from `config.json` (single-share) to `shares.json` (multi-share). Import your existing share into the new format, then use Import & Merge/Replace as needed.
- Exports never include credentials. You will be prompted to add missing credentials when they are referenced.
- If you had scripts relying on legacy function names or single-share assumptions, update them to use the new multi-share behavior.

### File Locations (v2)
- Configuration: `%APPDATA%\Share_Manager\shares.json`
- Credentials: `%APPDATA%\Share_Manager\creds.json` (DPAPI-encrypted)
- Logs: `%APPDATA%\Share_Manager\Share_Manager.log` (with rotation)
- Logon script (if persistent mapping enabled): `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Share_Manager_AutoMap.ps1`

### Housekeeping
- Replaced Unicode symbols in developer test output with ASCII for broader console compatibility.
- Documentation refresh: updated `README.md` and `CONTRIBUTING.md` to reflect new workflows and testing.
