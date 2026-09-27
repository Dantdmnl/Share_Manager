#Requires -Version 5.1
<#
.SYNOPSIS
    Offline smoke test for updater GUI progress and worker error propagation.
.DESCRIPTION
    Run with powershell.exe -NoProfile -STA -File .\Debug\test_update_gui.ps1.
    Briefly displays two progress dialogs. Does not access GitHub or install files.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$scriptPath = Join-Path $PSScriptRoot '..\Share_Manager.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
foreach ($name in @('ConvertTo-ShareManagerReleaseInfo', 'Get-ShareManagerScriptVersion', 'Install-ShareManagerUpdate', 'Invoke-ShareManagerUpdateTask')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Get-ShareManagerRelease {
    Start-Sleep -Milliseconds 250
    return [PSCustomObject]@{ Version = '2.4.1' }
}
$result = Invoke-ShareManagerUpdateTask -Operation Check -UseGUI
if ($result.Version -ne '2.4.1') { throw 'GUI worker did not return its result.' }
Write-Host '[OK] GUI worker returns results and closes its progress dialog.'

function Get-ShareManagerRelease {
    Start-Sleep -Milliseconds 250
    throw 'Synthetic offline error'
}
$caught = $false
try {
    Invoke-ShareManagerUpdateTask -Operation Check -UseGUI | Out-Null
} catch {
    if ($_.Exception.Message -notlike '*Synthetic offline error*') { throw }
    $caught = $true
}
if (-not $caught) { throw 'GUI worker swallowed an update failure.' }
Write-Host '[OK] GUI worker closes its progress dialog and propagates failures.'
