# Share Manager 2.5.0

This maintenance release adds an optional updater and fixes credential refresh, stale mapping cleanup, and Windows PowerShell 5.1 job handling. Share Manager remains a single script.

## Highlights

- Check for updates with **U** in the CLI or **Help > Check for Updates** in the GUI. Updates use stable GitHub releases and require confirmation before installation.
- Downloads are checked against the release asset's SHA-256 digest, size, version, and PowerShell syntax. Script replacement is atomic and keeps a timestamped backup beside the script.
- Credential Manager receives separate target, username, and password arguments. Persistent connections refresh passwords even when the username is unchanged, without deleting the stored entry first.
- Mapping continues to use the supplied credentials when Credential Manager cannot store them.
- CLI Disconnect All now attempts stale/red-X mappings even when no share appears connected. Connect All counts only enabled shares, and the menu groups update/log actions above navigation and Quit.
- Corrected unsupported `Stop-Job -Force` calls and isolated regression tests from the user's application data.
- GUI startup shows a helpful console message instead of a stray `True`, explaining where to find the app and to keep the console open.
- Updated CLI and GUI screenshots for version 2.5.0.

## Upgrading

Download `Share_Manager.ps1` and replace your existing script. Version 2.4.0 does not have the updater, so this first upgrade is manual. Existing configuration and saved credentials remain in `%APPDATA%\Share_Manager`.

Close and reopen Share Manager after replacing the file. With persistent mapping enabled, normal startup refreshes the generated AutoMap scripts.

## Update Privacy and Recovery

Update checks are manual. Requests to GitHub include ordinary connection metadata but no share configuration, passwords, or local logs. No background update checks are scheduled.

Future in-app updates retain a `.bak` copy beside the script. Close Share Manager and restore that copy under the original `.ps1` filename to roll back. The script directory must be writable.

## Validation

- 52 regression tests pass under Windows PowerShell 5.1.
- Syntax and structural checks pass; PSScriptAnalyzer reports 17 outstanding warnings.
- Offline GUI updater smoke tests cover worker results and failures. The GitHub release metadata check was also verified against the live API.
- Automated SMB and credential tests use mocks. Real server password changes and red-X mapping cleanup were not retested in a VM during release preparation.
