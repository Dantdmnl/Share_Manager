# Contributing to Share Manager

Thank you for your interest in contributing to Share Manager. Contributions are welcome, and the guidelines below help keep the project high-quality.

## How to Contribute

1. **Fork the repository**
   - Click **Fork** in the top-right of the repository page.

2. **Clone your fork**

   ```bash
   git clone https://github.com/your-username/Share_Manager.git
   ```

3. **Create a branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make changes**
   - Follow the coding standards in this document.

5. **Test your changes**
   - Run validation and regression checks before opening a PR.

6. **Commit your changes**

   ```bash
   git commit -m "Add feature: your feature description"
   ```

7. **Push to your fork**

   ```bash
   git push origin feature/your-feature-name
   ```

8. **Submit a pull request**
   - Open a PR against the main repository and describe what changed and why.

## Developer Setup

- Windows with PowerShell 5.1 or later (GUI uses Windows Forms)
- Recommended: VS Code with the PowerShell extension
- Set execution policy for your user if needed:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
```

## Running Validation and Linting

Run the comprehensive validation script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_syntax.ps1
```

Run regression tests:

Direct invocation of `Debug/test_regression.ps1` from PowerShell 7 automatically launches Windows PowerShell 5.1 with no profile. The runner displays the tested host and propagates its exit code. This avoids Pester 3.4 exception-assertion incompatibilities in modern PowerShell; it validates the 5.1 baseline, not PowerShell 7 runtime compatibility.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_regression.ps1
```

Run isolated AutoMap startup and CMD launcher tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_automap.ps1
```

These tests use temporary configuration and synthetic credentials, with Windows mapping operations replaced by test doubles. They do not connect to shares or change Credential Manager. Real sign-in acceptance checks are documented in [AutoMap validation](Debug/AUTOMAP-VALIDATION.md).

The validation script checks:

1. Legacy parser syntax
2. AST parse structure
3. Function analysis (approved verbs and definitions)
4. Script complexity and metrics
5. Security patterns (hardcoded secret scan)
6. PSScriptAnalyzer warnings and errors
7. Documentation quality checks
8. File encoding and size
9. Unicode/ASCII checks
10. Function-call existence

If PSScriptAnalyzer is missing, install it:

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
```

The repository provides custom analyzer settings:

- `Debug/PSScriptAnalyzerSettings.psd1`
  - Excluded rules are documented and intentional (for example, `PSAvoidUsingWriteHost` for interactive scripts).

## Release Validation

In addition to the syntax and regression checks above, run the offline GUI updater smoke test:

```powershell
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Debug\test_update_gui.ps1
```

It briefly displays two progress dialogs and verifies success/error handling without downloading or installing anything.

Before publishing, test GUI update progress and prompts, read-only script folders, reconnect after a server password change, and Disconnect All with only red-X mappings on Windows 10/11. Automated credential tests use synthetic arguments and mocks; they do not modify Windows Credential Manager or connect to a real SMB server.

Updater design references: [GitHub release API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release), [release asset digests](https://docs.github.com/en/rest/releases/assets#get-a-release-asset), and [go-selfupdate's release filtering and checksum validation](https://github.com/creativeprojects/go-selfupdate). The Network Configuration script provided the backup/atomic replacement pattern.

## Factory Reset (Testing)

To completely reset Share Manager during development/testing:

```powershell
# Remove all data except the script itself
Remove-Item -Path "$env:APPDATA\Share_Manager" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Share_Manager_AutoMap.*" -Force -ErrorAction SilentlyContinue
```

This removes configuration, credentials, logs, and logon scripts for a clean test environment.

## Coding Guidelines

### General Principles

- Target PowerShell 5.1+
- Prefer single, focused functions with approved verbs (`Get`, `Set`, `Add`, `Remove`, `Export`, `Import`, etc.)
- Use `Write-Host` for interactive CLI/GUI messaging (as per analyzer exclusions)
- Preserve user experience with minimal blocking prompts and sensible defaults

### Configuration Caching (v2.1.0+)

- Always use `Get-CachedConfig` instead of calling `Import-AllShares` directly
- Use `-Force` when you need fresh data (for example, after add/edit)
- Call `Clear-ConfigCache` after saving changes with `Save-AllShares`
- Cache expires automatically after 5 seconds (configurable with `-MaxAge`)
- Cache improves performance in bulk operations

Example:

```powershell
# Reading config (uses cache if fresh)
$config = Get-CachedConfig

# After modifications, force reload
$config = Get-CachedConfig -Force
Save-AllShares -ConfigData $config
Clear-ConfigCache  # Invalidate cache after save
```

### Preference Helpers (v2.1.0+)

- Use `Get-PreferenceValue` for safe preference access with null checking
- Supports type conversion with `-AsBoolean` and `-AsInteger`
- Always provide default values for robustness

Example:

```powershell
$autoConnect = Get-PreferenceValue -Config $config -PreferenceName "AutoConnectAtStartup" -DefaultValue $false -AsBoolean
$reconnectDelay = Get-PreferenceValue -Config $config -PreferenceName "ReconnectDelay" -DefaultValue 5 -AsInteger
```

### GDPR Compliance

- Never log usernames or personal data at `INFO`, `WARN`, or `ERROR` levels
- Use `DEBUG` level for troubleshooting that includes usernames
- Follow dual logging for sensitive operations:

```powershell
Write-Log -Level "INFO" -Message "Credentials removed for share."
Write-Log -Level "DEBUG" -Message "Credentials removed for: $username"
```

- Always document why personal data appears in logs.

### Performance Considerations

- Minimize disk I/O by leveraging `Get-CachedConfig`
- Avoid repeated `Import-AllShares` calls in loops
- For bulk operations, cache once and process all items
- Log cache hits/misses at `DEBUG` level for monitoring

### GUI Dialogs

- Support `Ctrl+A` in text boxes
- Support `Enter` to navigate/submit (AcceptButton pattern where possible)
- Use consistent message formatting with counts and item names
- Use null-safe string handling (for example, fallback names)

### Imports and Merges

- Duplicate detection uses `DriveLetter` or `SharePath`
- Merge mode must not create duplicates

## Pull Request Checklist

- [ ] Ran `.\Debug\test_syntax.ps1` and confirmed critical tests pass
- [ ] Verified no new PSScriptAnalyzer errors/warnings under repo settings
- [ ] Updated docs (README/CONTRIBUTING/CHANGELOG) when behavior or UX changed
- [ ] Considered backward compatibility and migration for storage changes
- [ ] Updated `Import-AllShares` backfill logic for new config/preference properties
- [ ] Tested both CLI and GUI flows when affected
- [ ] Used `Get-CachedConfig` instead of direct `Import-AllShares` reads
- [ ] Used `Get-PreferenceValue` for preference access
- [ ] Followed GDPR logging constraints
- [ ] Added logging at appropriate levels
- [ ] Used null-safe string handling in user-facing messages

## Reporting Issues

If you find a bug or have a feature request, open an issue in the repository with reproduction steps and relevant screenshots.

## Code of Conduct

Please adhere to our [Code of Conduct](https://github.com/Dantdmnl/Share_Manager/blob/main/CODE_OF_CONDUCT.md) in all interactions.

Thank you for contributing to Share Manager.
