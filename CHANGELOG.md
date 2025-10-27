# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [2.1.1] - 2025-10-27

### Added
- **Drive label sync preference**: new SyncShareNameToDriveLabel (default: on). When enabled, mapped drive labels in Explorer are set to the share Name via MountPoints2 registry (_LabelFromReg). Safe, user-scope only, non-blocking on errors.
  - Available in CLI Preferences menu (option 4) and GUI Preferences dialog
- **Enhanced CLI edit share**: Edit-ShareCli now allows modifying all share properties:
  - Name, SharePath, DriveLetter, Username, Description, and Enabled status
  - Uses Update-ShareConfiguration for proper validation and auto-unmap logic
  - Prevents drive letter conflicts and validates input
- **CLI share filtering/search**: Filter shares by name, path, or drive letter in Manage Shares menu
  - Press 'F' to access filter with helpful examples (name, path, drive letter)
  - Shows "X of Y shares" when filter is active
  - Filter persists across operations until cleared
  - Improved prompts show current filter and clear instructions
- **CLI batch operations menu**: New 'X' option in Manage Shares for bulk operations:
  - Enable/Disable selected shares (interactive multi-select with checkboxes)
  - Enable/Disable all shares (with confirmation prompts)
  - Works with active filters for targeted batch operations
  - Interactive toggle interface with clear instructions and visual feedback
  - Shows bullet-list of affected shares after completion
  - **First-time setup**: Drive label sync preference is now included in CLI initial setup wizard

### Changed
- CLI Preferences menu now includes option 4 for drive label sync preference (menu option "Back" moved to 5)
- CLI share editing now provides full property access instead of limited name/description/enabled only
- Manage Shares menu now shows [DISABLED] indicator for disabled shares
- Batch operations respect active filters for scoped operations
- **Improved CLI menu clarity**: Better organized action lists with color coding (Cyan for common, Yellow for batch ops)
- **Enhanced interactive selection UX**: 
  - Step-by-step instructions displayed at top ("How to use")
  - Visual distinction between selected (green) and unselected (gray) items
  - Prevents accidental empty selection with validation message
  - Better error messages with specific guidance
- **Bulk operations cache handling**: Connect All, Disconnect All, and Reconnect All now force reload config to guarantee fresh data (eliminates potential timing issues when performing bulk operations immediately after adding shares)

### Fixed
- Add Share dialog now honors Enabled=false selection (no longer forcibly enabled on save)
- Auto-unmap previous drive when changing a share's drive letter (when UnmapOldMapping preference is enabled)
- CLI Preferences menu ensures SyncShareNameToDriveLabel exists on first run (backfills for older configs)

## [2.1.0] - 2025-10-26

### Added
- **Config caching system** for performance optimization:
  - Intelligent 5-second cache reduces disk I/O by 80-95%
  - `Get-CachedConfig` function with automatic expiration and force reload
  - `Clear-ConfigCache` function invalidates cache after saves
  - Detailed cache logging at DEBUG level (hits, misses, age tracking)
- **Preference helper functions** for cleaner code:
  - `Get-PreferenceValue` with null-safe access, type conversion, and default values
  - Eliminates 200+ lines of repetitive preference retrieval logic
- **Easy debug configuration**: `$MANUAL_LOG_LEVEL` variable at top of script (line 56) for quick DEBUG/INFO/WARN/ERROR switching
- **Enhanced bulk operation logging**:
  - Connect All and Disconnect All now log share names and counts
  - Detailed progress tracking for troubleshooting
  - Consistent message format between GUI operations
- **Structured logging system** with dual-output architecture:
  - Human-readable text logs (Share_Manager.log, LogonScript.log)
  - Machine-readable JSONL events (Share_Manager.events.jsonl, LogonScript.events.jsonl)
  - Log levels: DEBUG, INFO, WARN, ERROR with environment variable filtering (SM_LOG_LEVEL)
  - Categories: Config, Credentials, BackupRestore, Migration, Mapping, Log, Startup, AutoMap, Connection, GUI, ConfigCache
  - Session IDs and correlation IDs for tracking related operations
  - Automatic log rotation (30 days or 5MB threshold) for both text and JSONL logs
  - Message throttling to prevent log spam from repetitive operations
- **Enhanced log access**: "Open Log File" now offers three options (text log, JSONL events, logs folder) in both CLI and GUI
- **Log analysis tool (Get-LogEvents)**: Query and filter JSONL events by category, level, time range, or session ID
  - CLI: "L" menu option now includes "Query Events" submenu with interactive filtering
  - PowerShell: Use `Get-LogEvents -Category Mapping -Level ERROR -Last 10` for advanced queries
- **Credential backup/restore**:
  - Export credentials to timestamped backup files (DPAPI-encrypted, machine/user-specific)
  - Import credentials with Merge or Replace modes
  - CLI: New options in Credentials menu (K → 4/5)
  - GUI: Context menu on Credentials button with Export/Import options
- **Enhanced connection retry with exponential backoff**:
  - 3 attempts with 2s, 4s delays (previously fixed 5s delays)
  - Intelligent error classification: Authentication, PathNotFound, InvalidPath, MultipleConnections, DriveInUse, NetworkTimeout
  - Detailed error messages guide users to specific fixes
  - Applied to both main script and AutoMap startup script
- **Improved CLI prompts**: UNC path input now displays clear examples with multiple format options

### Changed
- **GDPR compliance enhancements**:
  - Usernames removed from INFO/WARN/ERROR logs (GDPR-compliant by default)
  - Usernames only appear in DEBUG logs (opt-in for troubleshooting)
  - Session IDs and correlation IDs enable diagnostics without exposing user identity
  - Updated GDPR-COMPLIANCE.md to document structured logging and privacy improvements
  - Script header includes GDPR compliance statement
- **Null-safe logging**: All count and name interpolations protected from empty values
- **GUI message consistency**: Connect All and Disconnect All now show matching detailed summaries with share names
- **Credential removal messages**: Single confirmation and success message (removed duplicate dialogs)
- **Persistent mapping optimizations** (performance):
  - Logon scripts only update when content changes (avoids unnecessary file writes)
  - Windows Credential Manager (cmdkey) only updates when username changes
  - Smart detection logs decisions at DEBUG level for transparency
  - Significantly reduces I/O operations during repeated map/unmap cycles
- All Write-ActionLog calls migrated to structured format with proper levels and categories
- AutoMap startup script enhanced with structured logging, rotation, and retry attempt tracking
- Config saves now skip writes when data is unchanged (reduces log noise)
- Credentials menu expanded from 4 to 6 options (added export/import)
- Regex pattern fix in cmdkey command for server extraction (now correctly handles \\\\server paths)
- **GUI/UX improvements**:
  - Theme preference: Classic (authentic v2.0.2 look) and Modern (pure native visual styles)
  - ListView headers clickable with bi-directional sorting (A–Z/Z–A; Yes/No; Connected/Disconnected)
  - Removed sort arrows to avoid cramped headers on short columns; behavior remains bi-directional
  - Fixed header text visibility on right-click via TextRenderer
  - Dynamic column sizing to eliminate horizontal scrollbar while filling available width
  - Restart flow on theme change now cleanly closes old window
  - Manual refresh button now explicitly clears cache for guaranteed fresh data

### Fixed
- Missing share names in Connect/Disconnect All logs (now properly displays all share names)
- Missing share counts in bulk operation start messages (now shows "2 enabled shares", "5 total shares")
- Duplicate credential removal success messages (consolidated to single message)
- Update-ShareList missing share count in DEBUG logs
- String interpolation issues with `${variable}` syntax replaced with explicit null-safe assignments
- Null reference error when SM_LOG_LEVEL environment variable is unset
- PSScriptAnalyzer warning about assigning to automatic variable $matches in test harness
- Cache invalidation timing for GUI operations (refresh button, bulk operations)

### Performance Improvements
- **80-95% reduction in configuration file reads** via intelligent caching
- Eliminated redundant Import-AllShares calls (17+ locations optimized)
- Cache serves data in sub-second timeframes during rapid operations
- Automatic cache expiration prevents stale data (5-second default)

### Documentation
- Added factory reset instructions to README.md (one-liner to remove all data)
- Enhanced validation test descriptions in README.md (now lists all 10 checks)
- Updated Security & Privacy section with GDPR compliance details
- Added "What's New" section highlighting performance improvements
- Updated CONTRIBUTING.md with cache system and GDPR guidelines

- **GUI/UX improvements**:
  - Theme preference: Classic (authentic v2.0.2 look) and Modern (pure native visual styles)
  - ListView headers clickable with bi-directional sorting (A–Z/Z–A; Yes/No; Connected/Disconnected)
  - Removed sort arrows to avoid cramped headers on short columns; behavior remains bi-directional
  - Fixed header text visibility on right-click via TextRenderer
  - Dynamic column sizing to eliminate horizontal scrollbar while filling available width
  - Restart flow on theme change now cleanly closes old window

### Fixed
- Null reference error when SM_LOG_LEVEL environment variable is unset
- PSScriptAnalyzer warning about assigning to automatic variable $matches in test harness

## [2.0.2] - 2025-10-24

### Added
- Smart defaults for Y/N prompts throughout CLI to improve workflow efficiency:
  - Credential save prompts default to `[Y]` (save by default)
  - Connection prompts default to `[Y]` (connect after adding/configuring)
  - Auto-unmap preference defaults to `[Y]` (recommended setting)
  - Persistent mapping defaults to `[N]` (conservative/safe default)
  - Reconnect All defaults to `[Y]` (typical action)
  - Disconnect All defaults to `[N]` (safety measure)
- Enhanced visual feedback with summary counters in status displays
- Contextual tip displayed on main menu when no shares are configured

### Improved
- Menu navigation: Preferences option 4 now returns directly to main menu
- Batch operation feedback: clearer result messages ("reconnected" vs "reset", "already connected" vs "skipped")
- Consistent "Press any key to continue..." prompts across all operations
- Visual separators and formatting for better readability in CLI
- Menu labels improved: "Backup/Restore" and "View Log" for clarity

### Fixed
- Eliminated duplicate "Press any key..." prompts after batch operations
- Status display now shows proper summary line with connected/total counts

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

## Migration Notes

**v2.1.1:**
- Config files from older versions (2.0.0, 2.1.0) are automatically upgraded in-memory to add new properties (e.g., Enabled, SyncShareNameToDriveLabel) on every load. No manual migration needed.

**v2.0.0:**
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
