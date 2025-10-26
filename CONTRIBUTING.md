# Contributing to Share Manager

Thank you for your interest in contributing to Share Manager! We welcome contributions from the community. Please follow the guidelines below to help us maintain a high-quality project.

## How to Contribute

1. **Fork the Repository**: Click the "Fork" button at the top right of the repository page to create your own copy of the project.

2. **Clone Your Fork**: Use the following command to clone your fork to your local machine:
   git clone https://github.com/your-username/Share_Manager.git

3. **Create a Branch**: Create a new branch for your feature or bug fix:
   git checkout -b feature/your-feature-name

4. **Make Changes**: Make your changes in the codebase. Ensure that your code adheres to the project's coding standards (see below).

5. **Test Your Changes**: Run the validation script and lint checks to ensure your changes do not break the application.

6. **Commit Your Changes**: Commit your changes with a descriptive message:
   git commit -m "Add feature: your feature description"

7. **Push to Your Fork**: Push your changes to your fork:
   git push origin feature/your-feature-name

8. **Submit a Pull Request**: Go to the original repository and submit a pull request. Provide a clear description of your changes and why they should be merged.

## Developer Setup

- Windows with PowerShell 5.1 or later (GUI uses Windows Forms)
- Recommended: VS Code with PowerShell extension
- Set execution policy for your user if needed:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
   ```

## Running Validation and Linting

Run the comprehensive validation script:

```powershell
pwsh -NoProfile -File .\Debug\test_syntax.ps1
```

This runs 10 checks:
1. Legacy parser syntax check
2. AST parse check
3. Function analysis (approved verbs, count: 73 functions)
4. Script complexity & metrics (lines, functions, error handling)
5. Security check (hardcoded secrets detection)
6. PSScriptAnalyzer (Warnings/Errors)
7. Documentation quality check (34.2% of functions documented)
8. File encoding & size check (UTF-8 without BOM or ASCII, ~244 KB)
9. Unicode character check (pure ASCII compliance)
10. Function call existence (all called functions are defined)

If PSScriptAnalyzer is missing, install it:

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
```

The repo provides custom analyzer settings:
- `Debug/PSScriptAnalyzerSettings.psd1`
   - Excluded rules are documented and intentional (e.g., PSAvoidUsingWriteHost for interactive scripts)

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
- Prefer single, focused functions with approved verbs (Get/Set/Add/Remove/Export/Import/etc.)
- Use `Write-Host` for interactive CLI/GUI messaging (as per analyzer exclusions)
- Preserve user experience: minimal blocking prompts, sensible defaults

### Configuration Caching (v2.1.0+)
- **Always use `Get-CachedConfig`** instead of calling `Import-AllShares` directly
- Use `-Force` flag when you need fresh data (e.g., after user adds/edits shares)
- Call `Clear-ConfigCache` after saving changes with `Save-AllShares`
- Cache automatically expires after 5 seconds (configurable via `-MaxAge`)
- Cache improves performance by 80-95% during bulk operations

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
- **Use `Get-PreferenceValue`** for safe preference access with null-checking
- Supports type conversion: `-AsBoolean`, `-AsInteger`
- Always provide a default value for robustness

Example:
```powershell
$autoConnect = Get-PreferenceValue -Config $config -PreferenceName "AutoConnectAtStartup" -DefaultValue $false -AsBoolean
$reconnectDelay = Get-PreferenceValue -Config $config -PreferenceName "ReconnectDelay" -DefaultValue 5 -AsInteger
```

### GDPR Compliance
- **Never log usernames or personal data at INFO/WARN/ERROR levels**
- Use DEBUG level for troubleshooting that includes usernames
- Dual logging pattern for sensitive operations:
  ```powershell
  Write-Log -Level "INFO" -Message "Credentials removed for share."
  Write-Log -Level "DEBUG" -Message "Credentials removed for: $username"
  ```
- Always document why personal data is logged (troubleshooting, diagnostics)

### Performance Considerations
- Minimize disk I/O by leveraging `Get-CachedConfig`
- Avoid repeated Import-AllShares calls in loops
- For bulk operations, cache config once, then process all items
- Log cache hits/misses at DEBUG level for monitoring

### GUI Dialogs
- Support Ctrl+A in textboxes
- Support Enter to navigate/submit (use AcceptButton pattern where possible)
- Consistent message formatting: show both counts and item names in bulk operations
- Use null-safe string handling: `$shareName = if ($share.Name) { $share.Name } else { "Unknown" }`

### Imports/Merges
- Duplicate detection: duplicates are identified by DriveLetter OR SharePath
- Merge mode must not create duplicates

## Pull Request Checklist

- [ ] Ran `.\Debug\test_syntax.ps1` and confirmed ALL CRITICAL TESTS PASSED
- [ ] Verified PSScriptAnalyzer shows no new Errors/Warnings under repo settings
- [ ] Updated documentation (README/CONTRIBUTING/CHANGELOG) when changing behavior or UX
- [ ] Considered backward compatibility and migration when changing storage format
- [ ] Tested both CLI and GUI flows if affected
- [ ] Used `Get-CachedConfig` instead of direct `Import-AllShares` calls
- [ ] Used `Get-PreferenceValue` for safe preference access
- [ ] Followed GDPR compliance (no usernames in INFO/WARN/ERROR logs)
- [ ] Added appropriate logging at correct levels (DEBUG for diagnostics, INFO for user actions)
- [ ] Null-safe string handling in all user-facing messages

## Reporting Issues

If you find a bug or have a feature request, please open an issue in the repository. Provide as much detail as possible, including steps to reproduce the issue and any relevant screenshots.

## Code of Conduct

Please adhere to our [Code of Conduct](https://github.com/Dantdmnl/Share_Manager/blob/main/CODE_OF_CONDUCT.md) in all interactions with the community.

Thank you for contributing to Share Manager! Your help is greatly appreciated.
