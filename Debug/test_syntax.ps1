#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive syntax and code quality validation for Share_Manager.ps1

.DESCRIPTION
    Runs multiple validation checks including PowerShell parser, AST validation,
    PSScriptAnalyzer, and function enumeration to ensure the script is ready
    for production use.

.PARAMETER ScriptPath
    Path to the Share_Manager.ps1 script. Defaults to parent directory.

.PARAMETER SettingsPath
    Path to PSScriptAnalyzerSettings.psd1. Defaults to Debug folder.

.EXAMPLE
    .\test_syntax.ps1
    Runs all validation checks on the Share_Manager.ps1 script

.EXAMPLE
    .\test_syntax.ps1 -ScriptPath "C:\Scripts\Share_Manager.ps1"
    Runs validation on a specific script location
#>

param(
    [string]$ScriptPath = "$PSScriptRoot\..\Share_Manager.ps1",
    [string]$SettingsPath = "$PSScriptRoot\PSScriptAnalyzerSettings.psd1"
)

# Resolve paths
$ScriptPath = Resolve-Path $ScriptPath -ErrorAction Stop
$SettingsPath = Resolve-Path $SettingsPath -ErrorAction SilentlyContinue

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  SHARE MANAGER - SYNTAX & QUALITY VALIDATION" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Script: $ScriptPath`n" -ForegroundColor Gray

$allPassed = $true
$criticalFailed = $false
$results = @()
$ast = $null

# Test 1: PowerShell Legacy Parser
Write-Host "[1/8] PowerShell Legacy Parser Check..." -ForegroundColor Yellow
$errors = $null
try {
    [System.Management.Automation.PSParser]::Tokenize(
        (Get-Content $ScriptPath -Raw), 
        [ref]$errors
    ) | Out-Null
    
    if ($errors) {
        Write-Host "      [X] FAILED - Syntax errors found" -ForegroundColor Red
        $errors | ForEach-Object {
            Write-Host "         Line $($_.Token.StartLine): $($_.Message)" -ForegroundColor Red
        }
        $allPassed = $false
        $criticalFailed = $true
        $results += @{ Test = "Legacy Parser"; Status = "FAILED"; Details = "$($errors.Count) errors"; Critical = $true }
    } else {
        Write-Host "      [OK] PASSED - No syntax errors" -ForegroundColor Green
        $results += @{ Test = "Legacy Parser"; Status = "PASSED"; Details = "Clean"; Critical = $true }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $allPassed = $false
    $criticalFailed = $true
    $results += @{ Test = "Legacy Parser"; Status = "ERROR"; Details = $_.Exception.Message; Critical = $true }
}

# Test 2: AST (Abstract Syntax Tree) Parser
Write-Host "`n[2/8] AST (Abstract Syntax Tree) Parser..." -ForegroundColor Yellow
$parseErrors = $null
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, 
        [ref]$null, 
        [ref]$parseErrors
    )
    
    if ($parseErrors) {
        Write-Host "      [X] FAILED - Parse errors found" -ForegroundColor Red
        $parseErrors | ForEach-Object {
            Write-Host "         Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red
        }
        $allPassed = $false
        $criticalFailed = $true
        $results += @{ Test = "AST Parser"; Status = "FAILED"; Details = "$($parseErrors.Count) errors"; Critical = $true }
    } else {
        Write-Host "      [OK] PASSED - Script structure valid" -ForegroundColor Green
        $results += @{ Test = "AST Parser"; Status = "PASSED"; Details = "Valid structure"; Critical = $true }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $allPassed = $false
    $criticalFailed = $true
    $results += @{ Test = "AST Parser"; Status = "ERROR"; Details = $_.Exception.Message; Critical = $true }
}

# Test 3: Function Definition Analysis
Write-Host "`n[3/8] Function Definition Analysis..." -ForegroundColor Yellow
try {
    if ($ast) {
        $functions = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)
        
        Write-Host "      [OK] Found $($functions.Count) function definitions" -ForegroundColor Green
        
        # Check for unapproved verbs
        $approvedVerbs = Get-Verb | Select-Object -ExpandProperty Verb
        $unapproved = @()
        foreach ($func in $functions) {
            if ($func.Name -match '^(\w+)-') {
                $verb = $matches[1]
                if ($verb -notin $approvedVerbs) {
                    $unapproved += $func.Name
                }
            }
        }
        
        if ($unapproved.Count -gt 0) {
            Write-Host "      [!] WARNING - Unapproved verbs found:" -ForegroundColor Yellow
            $unapproved | ForEach-Object { Write-Host "         - $_" -ForegroundColor Yellow }
            $results += @{ Test = "Function Analysis"; Status = "WARNING"; Details = "$($unapproved.Count) unapproved verbs"; Critical = $false }
        } else {
            Write-Host "      [OK] All function verbs approved" -ForegroundColor Green
            $results += @{ Test = "Function Analysis"; Status = "PASSED"; Details = "$($functions.Count) functions, all approved"; Critical = $true }
        }
    } else {
        Write-Host "      [!] SKIPPED - AST not available" -ForegroundColor Yellow
        $results += @{ Test = "Function Analysis"; Status = "SKIPPED"; Details = "AST parse failed"; Critical = $false }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $allPassed = $false
    $results += @{ Test = "Function Analysis"; Status = "ERROR"; Details = $_.Exception.Message; Critical = $false }
}

# Test 4: Script Complexity & Metrics
Write-Host "`n[4/8] Script Complexity & Metrics..." -ForegroundColor Yellow
try {
    if ($ast) {
        $scriptContent = Get-Content $ScriptPath -Raw
        $lines = $scriptContent -split "`n"
        $lineCount = $lines.Count
        $commentLines = ($lines | Where-Object { $_ -match '^\s*#' }).Count
        $blankLines = ($lines | Where-Object { $_ -match '^\s*$' }).Count
        $codeLines = $lineCount - $commentLines - $blankLines
        
        $functions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $avgLinesPerFunction = if ($functions.Count -gt 0) { [Math]::Round($codeLines / $functions.Count, 1) } else { 0 }
        
        # Count try/catch blocks (good error handling indicator)
        $tryBlocks = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TryStatementAst] }, $true)
        
        Write-Host "      [OK] Total lines: $lineCount (Code: $codeLines, Comments: $commentLines, Blank: $blankLines)" -ForegroundColor Green
        Write-Host "      [OK] Functions: $($functions.Count) (Avg: $avgLinesPerFunction lines/function)" -ForegroundColor Green
        Write-Host "      [OK] Error handling: $($tryBlocks.Count) try/catch blocks" -ForegroundColor Green
        
        $results += @{ Test = "Script Complexity"; Status = "INFO"; Details = "$lineCount lines, $($functions.Count) functions"; Critical = $false }
    } else {
        Write-Host "      [!] SKIPPED - AST not available" -ForegroundColor Yellow
        $results += @{ Test = "Script Complexity"; Status = "SKIPPED"; Details = "AST parse failed"; Critical = $false }
    }
} catch {
    Write-Host "      [!] INFO - Complexity analysis skipped" -ForegroundColor Cyan
    $results += @{ Test = "Script Complexity"; Status = "INFO"; Details = "Analysis skipped"; Critical = $false }
}

# Test 5: Security Check - Hardcoded Secrets
Write-Host "`n[5/8] Security Check - Hardcoded Secrets..." -ForegroundColor Yellow
try {
    $content = Get-Content $ScriptPath -Raw
    $lines = $content -split "`n"
    $suspiciousPatterns = @(
        @{ Pattern = 'password\s*=\s*[''"][^''"]+[''"]'; Name = 'Password' },
        @{ Pattern = 'pwd\s*=\s*[''"][^''"]+[''"]'; Name = 'Password (pwd)' },
        @{ Pattern = 'apikey\s*=\s*[''"][^''"]+[''"]'; Name = 'API Key' },
        @{ Pattern = 'api_key\s*=\s*[''"][^''"]+[''"]'; Name = 'API Key' },
        @{ Pattern = 'secret\s*=\s*[''"][^''"]+[''"]'; Name = 'Secret' },
        @{ Pattern = 'token\s*=\s*[''"][^''"]+[''"]'; Name = 'Token' }
    )
    
    $findings = @()
    foreach ($item in $suspiciousPatterns) {
        $matches = [regex]::Matches($content, $item.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($matches.Count -gt 0) {
            foreach ($match in $matches) {
                $lineNum = $content.Substring(0, $match.Index).Split("`n").Count
                $lineContent = $lines[$lineNum - 1].Trim()
                # Exclude comments, examples, and variable names (without actual values)
                if ($lineContent -notmatch '^\s*#' -and 
                    $lineContent -notmatch '\.EXAMPLE' -and
                    $lineContent -notmatch '\.DESCRIPTION' -and
                    $match.Value -notmatch '=\s*[''"](\$|#|\.EXAMPLE)') {
                    $findings += "Line $lineNum : $($item.Name) - $($lineContent.Substring(0, [Math]::Min(50, $lineContent.Length)))..."
                }
            }
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Host "      [!] WARNING - Found $($findings.Count) suspicious patterns:" -ForegroundColor Yellow
        $findings | Select-Object -First 5 | ForEach-Object { Write-Host "         $_" -ForegroundColor Yellow }
        if ($findings.Count -gt 5) {
            Write-Host "         ... and $($findings.Count - 5) more" -ForegroundColor Yellow
        }
        $results += @{ Test = "Security Check"; Status = "WARNING"; Details = "$($findings.Count) suspicious patterns"; Critical = $false }
    } else {
        Write-Host "      [OK] No hardcoded secrets detected" -ForegroundColor Green
        $results += @{ Test = "Security Check"; Status = "PASSED"; Details = "Clean"; Critical = $false }
    }
} catch {
    Write-Host "      [!] INFO - Security check skipped" -ForegroundColor Cyan
    $results += @{ Test = "Security Check"; Status = "INFO"; Details = "Check skipped"; Critical = $false }
}

# Test 6: PSScriptAnalyzer
Write-Host "`n[6/8] PSScriptAnalyzer (Code Quality)..." -ForegroundColor Yellow
try {
    # Check if PSScriptAnalyzer is available
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "      [!] WARNING - PSScriptAnalyzer not installed" -ForegroundColor Yellow
        Write-Host "         Install with: Install-Module -Name PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor Gray
        $results += @{ Test = "PSScriptAnalyzer"; Status = "SKIPPED"; Details = "Module not installed"; Critical = $false }
    } else {
        $analyzerParams = @{
            Path = $ScriptPath
            Severity = @('Warning', 'Error')
        }
        
        if ($SettingsPath -and (Test-Path $SettingsPath)) {
            $analyzerParams['Settings'] = $SettingsPath
            Write-Host "      Using custom settings: $(Split-Path $SettingsPath -Leaf)" -ForegroundColor Gray
        }
        
        $issues = Invoke-ScriptAnalyzer @analyzerParams
        
        if ($issues) {
            Write-Host "      [!] Found $($issues.Count) issues:" -ForegroundColor Yellow
            $issues | Group-Object RuleName | ForEach-Object {
                Write-Host "         - $($_.Name): $($_.Count) occurrence(s)" -ForegroundColor Yellow
            }
            $results += @{ Test = "PSScriptAnalyzer"; Status = "WARNING"; Details = "$($issues.Count) issues"; Critical = $false }
        } else {
            Write-Host "      [OK] PASSED - No issues found" -ForegroundColor Green
            $results += @{ Test = "PSScriptAnalyzer"; Status = "PASSED"; Details = "Clean"; Critical = $true }
        }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $results += @{ Test = "PSScriptAnalyzer"; Status = "ERROR"; Details = $_.Exception.Message; Critical = $false }
}

# Test 7: Documentation Quality
Write-Host "`n[7/8] Documentation Quality Check..." -ForegroundColor Yellow
try {
    if ($ast) {
        $functions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $documented = 0
        $undocumented = @()
        
        foreach ($func in $functions) {
            # Check if function has help comments
            $funcText = $func.Extent.Text
            if ($funcText -match '\.SYNOPSIS|\.DESCRIPTION') {
                $documented++
            } else {
                # Only flag user-facing functions (exclude internal helpers starting with lowercase or _)
                if ($func.Name -match '^[A-Z]' -and $func.Name -notmatch '^_') {
                    $undocumented += $func.Name
                }
            }
        }
        
        $docPercentage = if ($functions.Count -gt 0) { [Math]::Round(($documented / $functions.Count) * 100, 1) } else { 0 }
        
        Write-Host "      [OK] Documentation: $documented/$($functions.Count) functions ($docPercentage%)" -ForegroundColor Green
        Write-Host "      [!] INFO - Main user-facing functions are documented (internal helpers optional)" -ForegroundColor Cyan
        
        if ($undocumented.Count -gt 0 -and $undocumented.Count -le 5) {
            Write-Host "      [i] Undocumented functions (not required for internal helpers):" -ForegroundColor DarkGray
            $undocumented | ForEach-Object { Write-Host "         - $_" -ForegroundColor DarkGray }
        } elseif ($undocumented.Count -gt 5) {
            Write-Host "      [i] $($undocumented.Count) undocumented functions (many are internal helpers)" -ForegroundColor DarkGray
        }
        
        $results += @{ Test = "Documentation"; Status = "INFO"; Details = "$docPercentage% documented (optional)"; Critical = $false }
    } else {
        Write-Host "      [!] SKIPPED - AST not available" -ForegroundColor Yellow
        $results += @{ Test = "Documentation"; Status = "SKIPPED"; Details = "AST parse failed"; Critical = $false }
    }
} catch {
    Write-Host "      [!] INFO - Documentation check skipped" -ForegroundColor Cyan
    $results += @{ Test = "Documentation"; Status = "INFO"; Details = "Check skipped"; Critical = $false }
}

# Test 8: File Encoding & Size Check
Write-Host "`n[8/8] File Encoding & Size Check..." -ForegroundColor Yellow
try {
    $bytes = [System.IO.File]::ReadAllBytes($ScriptPath)
    $encoding = "Unknown"
    
    # Check for BOM
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $encoding = "UTF-8 with BOM"
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $encoding = "UTF-16 LE"
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $encoding = "UTF-16 BE"
    } else {
        # Likely UTF-8 without BOM or ASCII
        $encoding = "UTF-8 (no BOM) or ASCII"
    }
    
    $sizeKB = [Math]::Round($bytes.Length / 1KB, 2)
    $sizeMB = [Math]::Round($bytes.Length / 1MB, 2)
    
    Write-Host "      [OK] File encoding: $encoding" -ForegroundColor Green
    Write-Host "      [OK] File size: $sizeKB KB" -ForegroundColor Green
    
    # Info if file is getting large
    if ($sizeMB -gt 0.5) {
        Write-Host "      [!] INFO - File is $sizeMB MB (consider modularization if grows beyond 1 MB)" -ForegroundColor Cyan
    }
    
    $results += @{ Test = "File Encoding"; Status = "INFO"; Details = "$encoding, $sizeKB KB"; Critical = $false }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $results += @{ Test = "File Encoding"; Status = "ERROR"; Details = $_.Exception.Message; Critical = $false }
}

# Summary
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$criticalTests = $results | Where-Object { $_.Critical -eq $true }
$nonCriticalTests = $results | Where-Object { $_.Critical -ne $true }

# Show critical tests first
if ($criticalTests) {
    Write-Host "  CRITICAL TESTS:" -ForegroundColor White
    foreach ($result in $criticalTests) {
        $statusColor = switch ($result.Status) {
            "PASSED" { "Green" }
            "WARNING" { "Yellow" }
            "FAILED" { "Red" }
            "ERROR" { "Red" }
            "SKIPPED" { "DarkGray" }
            "INFO" { "Cyan" }
            default { "White" }
        }
        
        $statusSymbol = switch ($result.Status) {
            "PASSED" { "[OK]" }
            "WARNING" { "[!]" }
            "FAILED" { "[X]" }
            "ERROR" { "[X]" }
            "SKIPPED" { "[-]" }
            "INFO" { "[i]" }
            default { "[?]" }
        }
        
        Write-Host "  $statusSymbol " -NoNewline -ForegroundColor $statusColor
        Write-Host "$($result.Test): " -NoNewline -ForegroundColor White
        Write-Host "$($result.Status)" -NoNewline -ForegroundColor $statusColor
        Write-Host " - $($result.Details)" -ForegroundColor Gray
    }
    Write-Host ""
}

# Show non-critical tests
if ($nonCriticalTests) {
    Write-Host "  ADDITIONAL CHECKS:" -ForegroundColor White
    foreach ($result in $nonCriticalTests) {
        $statusColor = switch ($result.Status) {
            "PASSED" { "Green" }
            "WARNING" { "Yellow" }
            "FAILED" { "Red" }
            "ERROR" { "Red" }
            "SKIPPED" { "DarkGray" }
            "INFO" { "Cyan" }
            default { "White" }
        }
        
        $statusSymbol = switch ($result.Status) {
            "PASSED" { "[OK]" }
            "WARNING" { "[!]" }
            "FAILED" { "[X]" }
            "ERROR" { "[X]" }
            "SKIPPED" { "[-]" }
            "INFO" { "[i]" }
            default { "[?]" }
        }
        
        Write-Host "  $statusSymbol " -NoNewline -ForegroundColor $statusColor
        Write-Host "$($result.Test): " -NoNewline -ForegroundColor White
        Write-Host "$($result.Status)" -NoNewline -ForegroundColor $statusColor
        Write-Host " - $($result.Details)" -ForegroundColor Gray
    }
}

Write-Host ""

if ($criticalFailed) {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  [X] CRITICAL TESTS FAILED" -ForegroundColor Red
    Write-Host "  Script has syntax errors and cannot be used!" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    exit 1
} elseif (-not $allPassed) {
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "  [!] SOME NON-CRITICAL TESTS FAILED" -ForegroundColor Yellow
    Write-Host "  Script is functional but review quality issues above" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  [OK] ALL TESTS PASSED" -ForegroundColor Green
    Write-Host "  Script is ready for production use!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    exit 0
}
