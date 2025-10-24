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

This runs:
- Legacy parser syntax check
- AST parse check
- Function analysis (approved verbs)
- PSScriptAnalyzer (Warnings/Errors)
- File encoding check

If PSScriptAnalyzer is missing, install it:

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
```

The repo provides custom analyzer settings:
- `Debug/PSScriptAnalyzerSettings.psd1`
   - Excluded rules are documented and intentional (e.g., PSAvoidUsingWriteHost for interactive scripts)

## Coding Guidelines

- Target PowerShell 5.1+
- Prefer single, focused functions with approved verbs (Get/Set/Add/Remove/Export/Import/etc.)
- Use `Write-Host` for interactive CLI/GUI messaging (as per analyzer exclusions)
- Preserve user experience: minimal blocking prompts, sensible defaults
- For GUI dialogs:
   - Support Ctrl+A in textboxes
   - Support Enter to navigate/submit (use AcceptButton pattern where possible)
- For imports/merges:
   - Duplicate detection: duplicates are identified by DriveLetter OR SharePath
   - Merge mode must not create duplicates

## Pull Request Checklist

- [ ] Ran `.\\Debug\\test_syntax.ps1` and confirmed ALL CRITICAL TESTS PASSED
- [ ] Verified PSScriptAnalyzer shows no new Errors/Warnings under repo settings
- [ ] Updated documentation (README/CONTRIBUTING) when changing behavior or UX
- [ ] Considered backward compatibility and migration when changing storage format
- [ ] Tested both CLI and GUI flows if affected

## Reporting Issues

If you find a bug or have a feature request, please open an issue in the repository. Provide as much detail as possible, including steps to reproduce the issue and any relevant screenshots.

## Code of Conduct

Please adhere to our [Code of Conduct](https://github.com/Dantdmnl/Share_Manager/blob/main/CODE_OF_CONDUCT.md) in all interactions with the community.

Thank you for contributing to Share Manager! Your help is greatly appreciated.
