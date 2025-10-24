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
$results = @()

# Test 1: PowerShell Legacy Parser
Write-Host "[1/5] PowerShell Legacy Parser Check..." -ForegroundColor Yellow
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
        $results += @{ Test = "Legacy Parser"; Status = "FAILED"; Details = "$($errors.Count) errors" }
    } else {
        Write-Host "      [OK] PASSED - No syntax errors" -ForegroundColor Green
        $results += @{ Test = "Legacy Parser"; Status = "PASSED"; Details = "Clean" }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $allPassed = $false
    $results += @{ Test = "Legacy Parser"; Status = "ERROR"; Details = $_.Exception.Message }
}

# Test 2: AST Parser
Write-Host "`n[2/5] AST (Abstract Syntax Tree) Parser..." -ForegroundColor Yellow
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
        $results += @{ Test = "AST Parser"; Status = "FAILED"; Details = "$($parseErrors.Count) errors" }
    } else {
        Write-Host "      [OK] PASSED - Script structure valid" -ForegroundColor Green
        $results += @{ Test = "AST Parser"; Status = "PASSED"; Details = "Valid structure" }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $allPassed = $false
    $results += @{ Test = "AST Parser"; Status = "ERROR"; Details = $_.Exception.Message }
}

# Test 3: Function Definitions
Write-Host "`n[3/5] Function Definition Analysis..." -ForegroundColor Yellow
try {
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
        $results += @{ Test = "Function Analysis"; Status = "WARNING"; Details = "$($unapproved.Count) unapproved verbs" }
    } else {
        Write-Host "      [OK] All function verbs approved" -ForegroundColor Green
        $results += @{ Test = "Function Analysis"; Status = "PASSED"; Details = "$($functions.Count) functions, all approved" }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $allPassed = $false
    $results += @{ Test = "Function Analysis"; Status = "ERROR"; Details = $_.Exception.Message }
}

# Test 4: PSScriptAnalyzer
Write-Host "`n[4/5] PSScriptAnalyzer (Code Quality)..." -ForegroundColor Yellow
try {
    # Check if PSScriptAnalyzer is available
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "      [!] WARNING - PSScriptAnalyzer not installed" -ForegroundColor Yellow
        Write-Host "         Install with: Install-Module -Name PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor Gray
        $results += @{ Test = "PSScriptAnalyzer"; Status = "SKIPPED"; Details = "Module not installed" }
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
            $results += @{ Test = "PSScriptAnalyzer"; Status = "WARNING"; Details = "$($issues.Count) issues" }
        } else {
            Write-Host "      [OK] PASSED - No issues found" -ForegroundColor Green
            $results += @{ Test = "PSScriptAnalyzer"; Status = "PASSED"; Details = "Clean" }
        }
    }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $results += @{ Test = "PSScriptAnalyzer"; Status = "ERROR"; Details = $_.Exception.Message }
}

# Test 5: File Encoding Check
Write-Host "`n[5/5] File Encoding Check..." -ForegroundColor Yellow
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
    
    Write-Host "      [OK] File encoding: $encoding" -ForegroundColor Green
    Write-Host "      [OK] File size: $([Math]::Round($bytes.Length / 1KB, 2)) KB" -ForegroundColor Green
    $results += @{ Test = "File Encoding"; Status = "INFO"; Details = $encoding }
} catch {
    Write-Host "      [X] ERROR - $_" -ForegroundColor Red
    $results += @{ Test = "File Encoding"; Status = "ERROR"; Details = $_.Exception.Message }
}

# Summary
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

foreach ($result in $results) {
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

if ($allPassed) {
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  [OK] ALL CRITICAL TESTS PASSED" -ForegroundColor Green
    Write-Host "  Script is ready for production use!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  [X] SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "  Please review and fix the issues above" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    exit 1
}
