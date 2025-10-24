# GDPR Compliance Overview

This document explains how Share Manager (CLI/GUI, v2.x) handles personal data in a GDPR-compliant way and how you can exercise your data rights.

## What data is processed

- **Multi-Share Configuration** (shares.json)
  - Share name, UNC path, drive letter, enabled flag, description
  - Username per share (required to authenticate on remote host)
  - Last connected timestamp for each share
  - Preferences (startup mode, persistent mapping, unmap old mappings)
- **Legacy Configuration** (config.json)
  - Single-share settings from v1.x (auto-migrated to shares.json on first run)
  - Backed up as config.json.v1.backup and removed after migration
- **Multi-User Credentials** (creds.json)
  - Multiple entries keyed by Username; each contains a DPAPI-encrypted password
  - Passwords are never stored in plaintext
  - Supports different credentials for different shares
- **Logs** (Share_Manager.log)
  - Operational messages (e.g., mapping success/failure, function calls)
  - No passwords are logged; usernames minimized where possible
  - Automatic rotation when logs become large

## Where data is stored (local only)

All data is stored locally under the current Windows user profile:

**Active Files (v2.0.0+)**:
- `%APPDATA%\Share_Manager\shares.json` - Multi-share configuration
- `%APPDATA%\Share_Manager\creds.json` - Multi-user credentials (DPAPI-encrypted)
- `%APPDATA%\Share_Manager\Share_Manager.log` - Application log with auto-rotation
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Share_Manager_AutoMap.ps1` - Logon script (if persistent mapping enabled)

**Legacy Files (auto-migrated)**:
- `%APPDATA%\Share_Manager\config.json` - Legacy single-share config (backed up to .v1.backup and removed)
- `%APPDATA%\Share_Manager\cred.txt` - Legacy single-credential file (backed up to .v1.backup and removed)
- `%APPDATA%\Share_Manager\key.bin` - Legacy AES key (kept for backward compatibility)

**No data is transmitted to third parties or over the network by this tool.** All operations are local to your machine.

## Legal basis and data minimization

- Purpose: mapping network shares for the signed-in Windows user.
- Legal basis: legitimate interest and/or contract (tool operation you voluntarily invoke).
- Minimization: stores only the data necessary to map the shares. Logs omit sensitive data and minimize personal data.

## Security and encryption

- Passwords are encrypted at rest using Windows DPAPI (Data Protection API), which ties encryption keys to your Windows user account and machine. Only you (on this machine) can decrypt them.
- Legacy AES-encrypted credentials (key.bin) are automatically migrated to DPAPI on first use and remain backward-compatible during migration.
- The startup (logon) script decrypts credentials only in the same user context (your account).
- Passwords are never logged or transmitted.
- You can delete all credentials at any time via the credentials menu.

## Data retention

- Data persists until you delete it. There is no background collection.
- Log rotation may automatically archive or reset Share_Manager.log when it becomes old/large.

## Your rights and how to exercise them

- Access: You can open the files in %APPDATA%\Share_Manager to view what is stored (except passwords which remain encrypted).
- Rectification: Edit entries via the UI/CLI (e.g., Edit Share, change Username) or by updating the files.
- Erasure (Right to be forgotten): Use the Credentials menu to remove credentials, and delete configuration files to remove all data. The tool provides a removal function that clears credential entries and logon scripts.
- Restriction/Objection: Disable persistent mapping and/or remove shares. The tool operates only on demand and does not send data externally.
- Portability: Use the Backup & Restore (Export Configuration) to export shares.json. Credentials are not exported in plaintext.

## Operational controls in the app

- **Backup & Restore** (CLI: B, GUI: Backup button): Export/import multi-share configuration. Credentials are never exported in plaintext for security.
- **Credentials Menu** (CLI: K, GUI: Credentials button): Save/Update or Remove credentials per username or all at once. Passwords remain encrypted and can be fully deleted at any time.
- **Share Management** (CLI: 2, GUI: context menu): Add, edit, remove, enable/disable individual shares. Each share can use different credentials.
- **Batch Operations**: Connect All, Disconnect All, Reconnect All shares with one action.
- **Persistent Mapping** (Settings/Preferences): Enables automatic reconnection at Windows logon. The startup script reads only your local encrypted credentials.
- **First-Time Setup Wizard**: Guided configuration for new users with clear explanations of each setting.

## Developer notes (hardening implemented in v2.0.0)

**Security Enhancements**:
- DPAPI encryption is now the default for all new credentials (Windows Data Protection API)
- Legacy AES-encrypted credentials (key.bin) automatically migrated to DPAPI on first use
- key.bin retained only for backward compatibility during migration period
- Credentials stored per-username in structured JSON (creds.json) supporting multiple users

**Privacy Improvements**:
- Logs minimize usernames where possible to reduce personal data exposure
- Share paths retained for diagnostics but never include credentials
- No passwords or encryption keys ever logged
- Silent mode operations prevent credential exposure in GUI popups

**Data Minimization**:
- Multi-share architecture eliminates redundant data storage
- Automatic cleanup of legacy files after migration (with backups created first)
- Log rotation prevents unbounded data accumulation
- Export function excludes credentials to prevent accidental exposure

**User Control**:
- First-time setup wizard with clear privacy explanations
- Granular credential management (per-username or bulk deletion)
- Easy export/import for data portability (minus credentials)
- Clear indicators of what data is stored and where

## Contact

This tool stores data only locally for the current Windows user. For issues or data requests, open an issue in the repository and include "GDPR" in the title. Do not include any secrets in tickets.
