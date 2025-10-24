# Share Manager
![GUI Screenshot](GUI.png)
![CLI Screenshot](CLI.png)

## Description
Easily manage and map network shares using this PowerShell script with support for both CLI and GUI interfaces. Share Manager is designed for end users who frequently access shared folders on a NAS or file server, providing a simple interface with persistent settings.

## Features
- **Multi-share support** - Manage multiple network shares with different credentials (v2.0.0+)
- **Configure and store NAS/share settings** including hostname, path, drive letter, and credentials per share
- **Toggle between CLI and GUI mode** with persistent startup preference
- **Securely save credentials** using Windows DPAPI encryption - tied to your user account
- **Map or unmap shares** individually or all at once with batch operations
- **Test connectivity** before attempting to map shares
- **Review and modify preferences** at any time via Settings menu
- **Log file with automatic rotation** for troubleshooting and activity tracking
- **First-time setup wizard** for guided configuration (CLI and GUI)
- **No administrator permissions required**
- **Persistent mapping** - Automatic reconnection at Windows logon
- **Real-time status indicators** showing connection state for all shares
- **Import/Export configuration** for backup and portability (credentials excluded)
- **Duplicate-safe imports** with Merge or Replace modes and built-in duplicate detection
- **Keyboard shortcuts** in GUI (Ctrl+A to select all, Enter to navigate/submit)
- **Automatic credential prompts** when referencing a non-existent username
- **Reconnect All** operation for quick bulk remapping

## Prerequisites
- Windows OS with PowerShell 5.1 or higher.
- A reachable NAS or network share location.
- Script execution policy must allow running scripts:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
  ```

## Usage
### Method 1: Download and Run the Script Locally

1. **Download the Script**
   - Visit the [releases tab](https://github.com/Dantdmnl/Share_Manager/releases) on the GitHub repository.
   - Download the latest version of the `Share_Manager.ps1` file.

2. **Run the Script**
   - Locate the downloaded file on your computer.
   - Right-click the file and select **Run with PowerShell**.

3. **Follow the Prompts**
   - The script will provide a menu to guide you through mapping your share, saving preferences, or switching modes.

### Method 2: Create a Desktop Shortcut

1. **Create a Shortcut**
   - Right-click on your Desktop > New > Shortcut.
   - Enter the following as the location:
     ```
     C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -STA -File "C:\YourFolder\Share_Manager.ps1"
     ```
     (be sure to replace YourFolder with your path)

2. **Customize the Shortcut (Optional)**
   - Name it something like `Share Manager`.
   - Set a custom icon if desired.

3. **Run the Shortcut**
   - Double-click the shortcut to launch the script in your preferred mode (CLI or GUI).

## Security & Privacy

- **DPAPI Encryption**: Credentials are encrypted using Windows Data Protection API (DPAPI), which ties encryption to your user account and machine. Only you can decrypt them.
- **Automatic Migration**: Legacy AES-encrypted credentials (if you're upgrading from an older version) are automatically migrated to DPAPI on first use.
- **GDPR Compliant**: See [GDPR-COMPLIANCE.md](GDPR-COMPLIANCE.md) for details on data handling, your rights, and how to export or delete your data.
- **Local Storage Only**: All data (config, credentials, logs) is stored locally under `%APPDATA%\Share_Manager`. Nothing is transmitted to third parties.

## What's New in v2.0.0

### Multi-Share Architecture
- Manage unlimited network shares from one interface
- Each share can use different credentials
- Batch operations: Connect All, Disconnect All, Reconnect All
- Individual and bulk share management

### Enhanced Security
- **DPAPI Encryption**: Credentials encrypted using Windows Data Protection API
- **Automatic Migration**: Legacy AES credentials auto-upgraded on first use
- **Per-user Protection**: Only you (on this machine) can decrypt your credentials
- **No Key Files**: Windows manages encryption keys internally

### Improved Interface
- **CLI**: Compact menu with smart status graying, inline prompts, minimal "press enter" interruptions
- **GUI**: Modern ListView with context menus, double-click actions, real-time status bar
- **First-Time Setup**: Welcome wizard guides new users through configuration
- **Silent Mode**: Batch operations run without popup interruptions
  
   Additional recent UX improvements:
   - Keyboard shortcuts: Ctrl+A selects all in textboxes; Enter moves to next field or activates default action
   - Preferences dialog supports Enter via AcceptButton behavior
   - Add/Edit Share dialogs include descriptive hints/examples for each field
   - Reduced redundant confirmations during backup/restore and credential saves

### Data Management
- **Import/Export**: Backup and restore share configurations
- **Automatic Cleanup**: Legacy files (config.json, cred.txt) backed up and removed after migration
- **Log Rotation**: Automatic archival of old log files

   Enhanced import behavior:
   - Import & Replace: Fully replaces existing configuration
   - Import & Merge: Merges with existing configuration using duplicate detection
   - Duplicate detection rules: A share is considered a duplicate if either the DriveLetter OR the SharePath matches an existing entry
   - Credentials are not included in exports; you'll be prompted to add any missing credentials when needed

### Credential Workflow
- Credentials are stored per-username and securely encrypted with DPAPI
- If a username is referenced that doesn't exist yet, the app will prompt you to create it (CLI and GUI)
- Variable interpolation is safe in prompts (no accidental scope parsing)

### Duplicate Prevention
- When importing or merging configurations, duplicates are detected by either:
   - Matching DriveLetter (e.g., X:), or
   - Matching SharePath (e.g., \\server\share)
- Duplicates are skipped during Merge to keep your configuration clean

## Keyboard Shortcuts (GUI)
- Ctrl+A: Select all text in the current textbox
- Enter: Move to the next input field; when on buttons, Enter activates the default action
- In Add/Edit/Preferences dialogs: Enter will trigger the primary action (e.g., Save/OK)

## Validation and Testing
This repository includes a comprehensive validation script to ensure the project remains production-ready.

Run all checks locally:

```powershell
pwsh -NoProfile -File .\Debug\test_syntax.ps1
```

What it checks:
- PowerShell legacy parser (syntax)
- AST parser (structure)
- Function analysis (approved verbs)
- PSScriptAnalyzer (uses `Debug/PSScriptAnalyzerSettings.psd1` if present)
- File encoding and size

If PSScriptAnalyzer isn't installed, the script will skip that step and show how to install it.

## Development Notes
- PowerShell 5.1+ on Windows is required (GUI uses Windows Forms)
- Linting uses PSScriptAnalyzer with a custom settings file at `Debug/PSScriptAnalyzerSettings.psd1`
- See `CONTRIBUTING.md` for developer setup, coding style, and PR guidelines

## Storage Locations
- **Configuration**: `%APPDATA%\Share_Manager\shares.json` (multi-share)
- **Credentials**: `%APPDATA%\Share_Manager\creds.json` (DPAPI-encrypted, multi-user)
- **Logs**: `%APPDATA%\Share_Manager\Share_Manager.log` (auto-rotation enabled)
- **Logon Script**: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Share_Manager_AutoMap.ps1` (if persistent mapping enabled)
- **Legacy Files**: `config.json` and `cred.txt` (auto-migrated to v2 format with backups)

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author
Developed by **Dantdmnl**.
