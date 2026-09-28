#Requires -Version 5.1
<#
.SYNOPSIS
    Runs Share Manager regression tests (Pester).

.DESCRIPTION
    Executes Debug/Share_Manager.Tests.ps1 and returns a non-zero exit code
    if any tests fail. Uses Pester 3.4 or 4.x (the suite uses legacy assertion syntax).

.PARAMETER TestsPath
    Optional path to the Pester test file.
#>

param(
    [string]$TestsPath = "$PSScriptRoot\Share_Manager.Tests.ps1"
)

# Pester 3.4 exception assertions misbehave in modern PowerShell. Always test
# the application's compatibility baseline, including when invoked from pwsh.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $windowsPowerShell = if ($env:SystemRoot) {
        Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    } else { $null }
    if (-not $windowsPowerShell -or -not (Test-Path -LiteralPath $windowsPowerShell)) {
        Write-Host '[X] These compatibility tests require Windows PowerShell 5.1.' -ForegroundColor Red
        exit 1
    }
    Write-Host "Running compatibility tests in Windows PowerShell 5.1 (invoked from PowerShell $($PSVersionTable.PSVersion))." -ForegroundColor Cyan
    & $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -TestsPath $TestsPath
    exit $LASTEXITCODE
}

try {
    $resolvedTests = Resolve-Path -LiteralPath $TestsPath -ErrorAction Stop
}
catch {
    Write-Host "[X] Test file not found: $TestsPath" -ForegroundColor Red
    exit 1
}

$pesterModule = Get-Module -ListAvailable -Name Pester | Where-Object {
    $_.Version -ge [version]'3.4' -and $_.Version.Major -lt 5
} | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pesterModule) {
    Write-Host "[X] Compatible Pester (3.4 or 4.x) is not installed." -ForegroundColor Red
    Write-Host "Install with: Install-Module -Name Pester -RequiredVersion 4.10.1 -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

Import-Module -Name $pesterModule.Path -Force -ErrorAction Stop | Out-Null

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  SHARE MANAGER - REGRESSION TESTS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Pester: $($pesterModule.Version)" -ForegroundColor Gray
Write-Host "  Host  : PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor Gray
Write-Host "  Tests : $resolvedTests`n" -ForegroundColor Gray

$results = Invoke-Pester -Script $resolvedTests -PassThru

if (-not $results -or $results.TotalCount -eq 0) {
    Write-Host "[X] No regression tests ran." -ForegroundColor Red
    exit 1
}

if ($results.FailedCount -gt 0) {
    Write-Host "`n[X] Regression tests failed: $($results.FailedCount) failure(s)" -ForegroundColor Red
    exit 1
}

Write-Host "`n[OK] All regression tests passed" -ForegroundColor Green
exit 0
