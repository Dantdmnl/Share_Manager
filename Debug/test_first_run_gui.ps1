#Requires -Version 5.1
<#
.SYNOPSIS
    Offline smoke test for the first-run GUI choice dialog.
.DESCRIPTION
    Run with powershell.exe -NoProfile -STA -File .\Debug\test_first_run_gui.ps1.
    Briefly opens the setup choice window and clicks Finish Setup. No configuration is saved.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$scriptPath = Join-Path $PSScriptRoot '..\Share_Manager.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
$definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Show-FirstRunChoiceGUI' }, $true)
if (-not $definition) { throw 'First-run GUI choice function was not found.' }
. ([scriptblock]::Create($definition.Extent.Text))
$themeDefinition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-GuiVisualStyle' }, $true)
if (-not $themeDefinition) { throw 'GUI theme helper was not found.' }
. ([scriptblock]::Create($themeDefinition.Extent.Text))
Set-GuiVisualStyle -Theme 'Modern'
if ([System.Windows.Forms.Application]::VisualStyleState -ne [System.Windows.Forms.VisualStyles.VisualStyleState]::ClientAndNonClientAreasEnabled) {
    throw 'Modern visual style was not applied.'
}
Set-GuiVisualStyle -Theme 'Classic'
if ([System.Windows.Forms.Application]::VisualStyleState -ne [System.Windows.Forms.VisualStyles.VisualStyleState]::NoneEnabled) {
    throw 'Classic visual style was not applied.'
}
Set-GuiVisualStyle -Theme 'Modern'

$version = 'smoke test'
$script:SmokeShares = @()
$script:SmokeAction = 'Finish'
function Get-ShareConfiguration { return $script:SmokeShares }
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 100
$attempts = 0
$timer.Add_Tick({
    $attempts++
    $form = @([System.Windows.Forms.Application]::OpenForms | Where-Object { $_.Text -like '*First Setup' }) | Select-Object -First 1
    if ($form) {
        $button = @($form.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -eq 'Finish Setup' }) | Select-Object -First 1
        if (-not $button) { throw 'Finish Setup button was not visible.' }
        $addButton = @($form.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] -and $_.Text -eq 'Add Share' }) | Select-Object -First 1
        $list = @($form.Controls | Where-Object { $_ -is [System.Windows.Forms.ListView] })
        if ($script:SmokeShares.Count -eq 0) {
            if ($form.AcceptButton -ne $addButton -or $list.Count -ne 0) { throw 'Empty setup should focus Add Share and avoid an empty list.' }
        } else {
            if ($form.AcceptButton -ne $button -or $list.Count -ne 1 -or $list[0].Items.Count -ne 1 -or $list[0].SelectedItems.Count -ne 1) {
                throw 'Populated setup should list shares and focus Finish Setup.'
            }
        }
        $actionButton = @($form.Controls | Where-Object {
            $_ -is [System.Windows.Forms.Button] -and $_.Text -eq $(switch ($script:SmokeAction) {
                'Edit' { 'Edit selected' }
                'Remove' { 'Remove selected' }
                default { 'Finish Setup' }
            })
        }) | Select-Object -First 1
        if (-not $actionButton) { throw "Setup action button '$script:SmokeAction' was not visible." }
        $actionButton.PerformClick()
        $timer.Stop()
    } elseif ($attempts -gt 50) {
        $timer.Stop()
        throw 'First-run GUI choice window did not appear.'
    }
})
try {
    $timer.Start()
    $choice = Show-FirstRunChoiceGUI
    if (-not $choice -or $choice.Action -ne 'Finish') {
        throw 'Finish Setup did not return the expected setup choice.'
    }
    $script:SmokeShares = @([PSCustomObject]@{ Id = 'share-1'; Name = 'Example'; DriveLetter = 'Z'; SharePath = '\\server\share' })
    $attempts = 0
    $timer.Start()
    $choice = Show-FirstRunChoiceGUI
    if (-not $choice -or $choice.Action -ne 'Finish') { throw 'Populated setup did not finish.' }
    foreach ($action in @('Edit', 'Remove')) {
        $script:SmokeAction = $action
        $attempts = 0
        $timer.Start()
        $choice = Show-FirstRunChoiceGUI
        if (-not $choice -or $choice.Action -ne $action -or $choice.ShareId -ne 'share-1') {
            throw "$action did not return the selected share ID."
        }
    }
    Write-Host '[OK] Empty and populated first-run GUI states expose the expected actions.'
} finally {
    $timer.Stop()
    $timer.Dispose()
}
