#Requires -Version 5.1
<#
.SYNOPSIS
    Runs Share Manager regression tests (Pester).

.DESCRIPTION
    Executes Debug/Share_Manager.Tests.ps1 and returns a non-zero exit code
    if any tests fail. Compatible with Pester 3.x and newer.

.PARAMETER TestsPath
    Optional path to the Pester test file.
#>

param(
    [string]$TestsPath = "$PSScriptRoot\Share_Manager.Tests.ps1"
)

try {
    $resolvedTests = Resolve-Path -Path $TestsPath -ErrorAction Stop
}
catch {
    Write-Host "[X] Test file not found: $TestsPath" -ForegroundColor Red
    exit 1
}

$pesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pesterModule) {
    Write-Host "[X] Pester is not installed." -ForegroundColor Red
    Write-Host "Install with: Install-Module -Name Pester -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

Import-Module Pester -ErrorAction Stop | Out-Null

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  SHARE MANAGER - REGRESSION TESTS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Pester: $($pesterModule.Version)" -ForegroundColor Gray
Write-Host "  Tests : $resolvedTests`n" -ForegroundColor Gray

$results = Invoke-Pester -Script $resolvedTests -PassThru

if ($results.FailedCount -gt 0) {
    Write-Host "`n[X] Regression tests failed: $($results.FailedCount) failure(s)" -ForegroundColor Red
    exit 1
}

Write-Host "`n[OK] All regression tests passed" -ForegroundColor Green
exit 0
