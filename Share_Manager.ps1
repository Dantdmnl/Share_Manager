﻿<#
.SYNOPSIS
    Share Manager Script (v1.1.1) – Map and unmap network shares via CLI or GUI,
    with robust credential persistence using AES-encrypted SecureString.

.DESCRIPTION
    - Interactive management of network shares (SMB) with both CLI and GUI interfaces.
    - Credentials stored securely via ConvertFrom-SecureString with a generated AES key at
      `%APPDATA%\Share_Manager\cred.txt` and key at `%APPDATA%\Share_Manager\key.bin`.
    - CLI password entry shows asterisks as you type.
    - Users can switch between CLI and GUI without losing configuration.
    - Logs actions to `%APPDATA%\Share_Manager\Share_Manager.log`, with automatic rotation.
    - Preferences pane to toggle auto-unmapping on drive-letter change and select startup mode.
    - Version number displayed in title bars and menus.
    - Author: Dantdmnl.

.PARAMETER StartupMode
    Optional. Pass "CLI" or "GUI" to force that mode on launch, bypassing saved preference.

.VERSION
    1.1.1

.NOTES
    - No administrator permissions are required.
    - GUI mode requires `-STA` when launching PowerShell:
      ```text
      powershell.exe -ExecutionPolicy Bypass -STA -File "C:\Scripts\Share_Manager.ps1"
      ```
#>

param(
    [string]$StartupMode
)

#region Global Variables (Version, Paths, Defaults)

$version        = '1.1.1'
$author         = 'Dantdmnl'
$baseFolder     = Join-Path $env:APPDATA "Share_Manager"
if (-not (Test-Path $baseFolder)) {
    New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
}
$configPath       = Join-Path $baseFolder "config.json"
$credentialPath   = Join-Path $baseFolder "cred.txt"
$keyPath          = Join-Path $baseFolder "key.bin"
$logPath          = Join-Path $baseFolder "Share_Manager.log"

$defaultConfigTemplate = [PSCustomObject]@{
    SharePath   = $null
    DriveLetter = $null
    Username    = $null
    Preferences = [PSCustomObject]@{
        UnmapOldMapping = $true
        PreferredMode   = "Prompt"
    }
}

$script:UseGUI = $false

#endregion

#region Helper Functions: InputBox, Logging, Config & Credential Key

function Show-InputBox {
    param (
        [string]$Prompt,
        [string]$Title,
        [string]$DefaultValue = ""
    )
    Add-Type -AssemblyName Microsoft.VisualBasic
    return [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, $Title, $DefaultValue)
}

function Rotate-LogIfNeeded {
    if (-not (Test-Path $logPath)) { return }
    $fileInfo = Get-Item $logPath
    $ageDays  = (Get-Date) - $fileInfo.LastWriteTime
    $sizeMB   = [math]::Round($fileInfo.Length / 1MB, 2)
    if ($ageDays.TotalDays -ge 30 -or $sizeMB -ge 5) {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
        $archived  = Join-Path $baseFolder "Share_Manager_$timestamp.log"
        try {
            Rename-Item -Path $logPath -NewName (Split-Path $archived -Leaf) -ErrorAction Stop
            New-Item -Path $logPath -ItemType File -Force | Out-Null
            if (-not $UseGUI) {
                Write-Host "Log rotated to $(Split-Path $archived -Leaf)" -ForegroundColor Cyan
            }
        }
        catch {
            if (-not $UseGUI) {
                Write-Host "Warning: Failed to rotate log: $_" -ForegroundColor Yellow
            }
        }
    }
}

function Log-Action {
    param ([string]$Message)
    try {
        if (-not (Test-Path $baseFolder)) {
            New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
        }
        if (-not (Test-Path $logPath)) {
            New-Item -Path $logPath -ItemType File -Force | Out-Null
        }
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        "$timestamp`t$Message" | Out-File -FilePath $logPath -Encoding UTF8 -Append
    }
    catch {
        if (-not $UseGUI) {
            Write-Host "Warning: Failed to write to log: $_" -ForegroundColor Yellow
        }
    }
}

Rotate-LogIfNeeded

function Load-Config {
    if (Test-Path $configPath) {
        try {
            $json = Get-Content -Path $configPath -Raw
            $cfg  = ConvertFrom-Json $json
            if (-not $cfg.PSObject.Properties['Preferences']) {
                $cfg | Add-Member -MemberType NoteProperty -Name Preferences -Value $defaultConfigTemplate.Preferences
            }
            return $cfg
        }
        catch {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Config is invalid and will be recreated.",
                    "Config Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
            else {
                Write-Host "Warning: Config invalid; recreating." -ForegroundColor Yellow
            }
            Remove-Item $configPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $null
}

function Save-Config {
    param (
        [string]$SharePath,
        [string]$DriveLetter,
        [string]$Username,
        [bool]  $UnmapOldMapping,
        [string]$PreferredMode
    )
    $obj = [PSCustomObject]@{
        SharePath   = $SharePath
        DriveLetter = $DriveLetter
        Username    = $Username
        Preferences = [PSCustomObject]@{
            UnmapOldMapping = $UnmapOldMapping
            PreferredMode   = $PreferredMode
        }
    }
    try {
        $obj | ConvertTo-Json -Depth 4 | Set-Content -Path $configPath -Encoding UTF8 -Force
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Configuration saved.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        else {
            Write-Host "Configuration saved to $configPath" -ForegroundColor Green
        }
        Log-Action "Saved config: SharePath=$SharePath, DriveLetter=$DriveLetter, Username=$Username, UnmapOldMapping=$UnmapOldMapping, PreferredMode=$PreferredMode"
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Error: Failed to save config.`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        else {
            Write-Host "Error: Failed to save config: $_" -ForegroundColor Red
        }
        Log-Action "Failed to save config: $_"
    }
}

#endregion

#region Credential Storage: AES-Encrypted SecureString

function Ensure-Key {
    if (-not (Test-Path $keyPath)) {
        # Generate 256-bit AES key
        $aesKey = New-Object byte[] 32
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)
        [System.IO.File]::WriteAllBytes($keyPath, $aesKey)
        Log-Action "Generated new AES key at $keyPath"
    }
}

function Get-Key {
    Ensure-Key
    return [System.IO.File]::ReadAllBytes($keyPath)
}

function Save-Credential {
    param ([System.Management.Automation.PSCredential]$Credential)

    # Caller must ensure $Credential is non-null
    try {
        $user        = $Credential.UserName
        $securePW    = $Credential.Password
        $aesKey      = Get-Key
        $encryptedPW = $securePW | ConvertFrom-SecureString -Key $aesKey

        # Store as two lines: username and encrypted string
        @($user, $encryptedPW) | Set-Content -Path $credentialPath -Force -Encoding UTF8

        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Credentials saved securely.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        else {
            Write-Host "Credentials saved to $credentialPath" -ForegroundColor Green
        }
        Log-Action "Saved credential for $user"
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Error: Failed to save credentials.`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        else {
            Write-Host "Error: Failed to save credentials: $_" -ForegroundColor Red
        }
        Log-Action "Failed to save credential: $_"
    }
}

function Load-Credential {
    if (Test-Path $credentialPath) {
        try {
            $lines       = Get-Content -Path $credentialPath -Encoding UTF8
            if ($lines.Count -lt 2) { return $null }
            $user        = $lines[0]
            $encryptedPW = $lines[1]
            $aesKey      = Get-Key
            $securePW    = $encryptedPW | ConvertTo-SecureString -Key $aesKey
            return New-Object System.Management.Automation.PSCredential($user, $securePW)
        }
        catch {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Stored credentials invalid or cannot be decrypted.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
            else {
                Write-Host "Warning: Stored credentials invalid or cannot be decrypted." -ForegroundColor Yellow
            }
            return $null
        }
    }
    return $null
}

function Remove-Credential {
    if (Test-Path $credentialPath) {
        Remove-Item -Path $credentialPath -Force
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Credentials removed.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        else {
            Write-Host "Credentials removed." -ForegroundColor Yellow
        }
        Log-Action "Removed stored credentials"
    }
    else {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "No credentials found.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        else {
            Write-Host "No credentials to remove." -ForegroundColor Yellow
        }
        Log-Action "No credentials to remove"
    }
}

#endregion

#region Read-Password (CLI, masked with asterisks)

function Read-Password {
    param (
        [string]$Prompt = "Password: "
    )
    Write-Host -NoNewline $Prompt
    $secureString = New-Object Security.SecureString
    while ($true) {
        $key = [System.Console]::ReadKey($true)
        if ($key.Key -eq 'Enter') {
            break
        }
        elseif ($key.Key -eq 'Backspace') {
            if ($secureString.Length -gt 0) {
                $secureString.RemoveAt($secureString.Length - 1)
                $cursorLeft = [System.Console]::CursorLeft
                if ($cursorLeft -gt ($Prompt.Length)) {
                    [System.Console]::SetCursorPosition($cursorLeft - 1, [System.Console]::CursorTop)
                    Write-Host -NoNewline ' '
                    [System.Console]::SetCursorPosition($cursorLeft - 1, [System.Console]::CursorTop)
                }
            }
        }
        else {
            $secureString.AppendChar($key.KeyChar)
            Write-Host -NoNewline '*'
        }
    }
    Write-Host ""
    $secureString.MakeReadOnly()
    return $secureString
}

#endregion

#region Network Check & Mapping Functions

function Test-ShareOnline {
    param ([string]$SharePath)
    if ($SharePath -notmatch '^\\\\([^\\]+)\\') {
        return $false
    }
    if ($SharePath -match '^\\\\([^\\]+)\\') {
        $shareHost = $Matches[1]
    }
    else {
        return $false
    }
    try {
        return Test-Connection -ComputerName $shareHost -Count 1 -Quiet -ErrorAction SilentlyContinue
    }
    catch {
        return $false
    }
}

function Map-Share {
    param (
        [string]$SharePath,
        [string]$DriveLetter,
        [System.Management.Automation.PSCredential]$Credential
    )

    if (Test-Path "$DriveLetter`:") {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Drive $DriveLetter is already in use.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        }
        else {
            Write-Host "Drive $DriveLetter is already mapped. Unmap it first." -ForegroundColor Yellow
        }
        return
    }

    if (-not (Test-ShareOnline -SharePath $SharePath)) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Share host not reachable. Skipping mapping.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        }
        else {
            Write-Host "Share host not reachable. Skipping mapping." -ForegroundColor Yellow
        }
        Log-Action "Skipped mapping $DriveLetter → $SharePath (offline)"
        return
    }

    try {
        $user          = $Credential.UserName
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        )
        net use "$DriveLetter`:" $SharePath /USER:$user $plainPassword /PERSISTENT:NO | Out-Null

        if ($LASTEXITCODE -eq 0) {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Mapped $DriveLetter → $SharePath",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
            else {
                Write-Host "Drive $DriveLetter mapped to $SharePath." -ForegroundColor Green
            }
            Log-Action "Mapped $DriveLetter → $SharePath as $user"
        }
        else {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Mapping failed. Check path/credentials.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
            else {
                Write-Host "Failed to map drive. Check details." -ForegroundColor Red
            }
            Log-Action "Failed mapping $DriveLetter → $SharePath"
        }
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Error during mapping:`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        else {
            Write-Host "Error during mapping: $_" -ForegroundColor Red
        }
        Log-Action "Error during mapping: $_"
    }
}

function Unmap-Share {
    param ([string]$DriveLetter)
    try {
        if (Test-Path "$DriveLetter`:") {
            net use "$DriveLetter`:" /DELETE /Y | Out-Null
            if ($LASTEXITCODE -eq 0) {
                if ($UseGUI) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Unmapped $DriveLetter.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                }
                else {
                    Write-Host "Drive $DriveLetter unmapped." -ForegroundColor Green
                }
                Log-Action "Unmapped $DriveLetter"
            }
            else {
                if ($UseGUI) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Unmapping failed.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
                else {
                    Write-Host "Failed to unmap drive." -ForegroundColor Red
                }
                Log-Action "Failed unmapping $DriveLetter"
            }
        }
        else {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Drive $DriveLetter not mapped.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
            else {
                Write-Host "Drive $DriveLetter not mapped." -ForegroundColor Yellow
            }
        }
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Error during unmapping:`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        else {
            Write-Host "Error during unmapping: $_" -ForegroundColor Red
        }
        Log-Action "Error during unmapping: $_"
    }
}

function Open-LogFile {
    if (-not (Test-Path $logPath)) {
        try {
            New-Item -Path $logPath -ItemType File -Force | Out-Null
        }
        catch {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to create log file:`n$_",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
            else {
                Write-Host "Failed to create log file: $_" -ForegroundColor Red
            }
            return
        }
    }
    try {
        Start-Process -FilePath $logPath -ErrorAction Stop
        Log-Action "Opened log file"
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to open log file:`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        else {
            Write-Host "Unable to open log file: $_" -ForegroundColor Red
        }
        Log-Action "Failed to open log file: $_"
    }
}

#endregion

#region First-Run Configuration

function Initialize-Config-CLI {
    Clear-Host
    Write-Host "=== Share Manager v$version Configuration ===" -ForegroundColor Cyan
    Write-Host ""
    do {
        $sharePath = Read-Host "Enter network share (UNC), e.g. \\server\share"
        if ($sharePath -match '^\\\\[^\\]+\\') { break }
        Write-Host "Invalid UNC; try again." -ForegroundColor Yellow
    } while ($true)

    do {
        $driveLetter = Read-Host "Enter drive letter (A–Z)"
        if ($driveLetter -match '^[A-Za-z]$') { $driveLetter = $driveLetter.ToUpper(); break }
        Write-Host "Enter a single letter A–Z." -ForegroundColor Yellow
    } while ($true)

    do {
        $username = Read-Host "Enter username (DOMAIN\\User or local)"
        if (-not [string]::IsNullOrWhiteSpace($username)) { break }
        Write-Host "Cannot be blank." -ForegroundColor Yellow
    } while ($true)

    # Prompt for password (masked) using Read-Password
    $password = Read-Password ("Enter password for $($username): ")
    if ($password.Length -gt 0) {
        $cred = New-Object System.Management.Automation.PSCredential($username, $password)
        Save-Credential -Credential $cred
    }
    else {
        Write-Host "No password entered; credentials skipped." -ForegroundColor Yellow
    }

    $dummyPrefs = [PSCustomObject]@{
        UnmapOldMapping = $true
        PreferredMode   = "Prompt"
    }
    $prefValues = Show-PreferencesForm -CurrentPrefs $dummyPrefs -IsInitial $true

    Save-Config -SharePath       $sharePath `
                -DriveLetter     $driveLetter `
                -Username        $username `
                -UnmapOldMapping $prefValues.UnmapOldMapping `
                -PreferredMode   $prefValues.PreferredMode
}

function Initialize-Config-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic

    do {
        $sharePath = Show-InputBox -Prompt "Enter network share (UNC), e.g. \\server\share" `
                                   -Title  "Initial Share Path" `
                                   -DefaultValue ""
        if ($sharePath -match '^\\\\[^\\]+\\') { break }
        [System.Windows.Forms.MessageBox]::Show(
            "Invalid UNC; try again.",
            "Share Manager v$version",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
    } while ($true)

    do {
        $driveLetter = Show-InputBox -Prompt "Enter drive letter (A–Z)" `
                                      -Title  "Initial Drive Letter" `
                                      -DefaultValue ""
        if ($driveLetter -match '^[A-Za-z]$') { $driveLetter = $driveLetter.ToUpper(); break }
        [System.Windows.Forms.MessageBox]::Show(
            "Enter single letter A–Z.",
            "Share Manager v$version",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
    } while ($true)

    do {
        $username = Show-InputBox -Prompt "Enter username (DOMAIN\\User or local)" `
                                 -Title  "Initial Username" `
                                 -DefaultValue ""
        if (-not [string]::IsNullOrWhiteSpace($username)) { break }
        [System.Windows.Forms.MessageBox]::Show(
            "Cannot be blank.",
            "Share Manager v$version",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
    } while ($true)

    # Prompt for credentials in GUI, defaulting to provided username
    $cred = Get-Credential -Message "Enter password for $username" -UserName $username
    if ($cred) {
        Save-Credential -Credential $cred
    } else {
        [System.Windows.Forms.MessageBox]::Show(
            "No credentials entered; skipping.",
            "Share Manager v$version",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }

    $dummyPrefs = [PSCustomObject]@{
        UnmapOldMapping = $true
        PreferredMode   = "Prompt"
    }
    $prefValues = Show-PreferencesForm -CurrentPrefs $dummyPrefs -IsInitial $true

    Save-Config -SharePath       $sharePath `
                -DriveLetter     $driveLetter `
                -Username        $username `
                -UnmapOldMapping $prefValues.UnmapOldMapping `
                -PreferredMode   $prefValues.PreferredMode
}

#endregion

#region CLI Interface

function Show-CLI-Menu {
    Clear-Host
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "  Share Manager v$version" -ForegroundColor Cyan
    Write-Host "  Author: $author" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "1. Map Share"
    Write-Host "2. Unmap Share"
    Write-Host "3. Configure Settings"
    Write-Host "4. Preferences"
    Write-Host "5. Update/Remove Credentials"
    Write-Host "6. Open Log File"
    Write-Host "7. Test Connectivity"
    Write-Host "8. Switch to GUI"
    Write-Host "9. Exit"
    Write-Host "==============================" -ForegroundColor Cyan
}

function Configure-Settings-CLI {
    $cfg = Load-Config
    if (-not $cfg) { return }

    $oldDrive = $cfg.DriveLetter
    $prefs    = $cfg.Preferences

    Write-Host "Current Share Path : $($cfg.SharePath)"
    Write-Host "Current DriveLetter: $($cfg.DriveLetter)"
    Write-Host "Current Username   : $($cfg.Username)"
    Write-Host ""

    do {
        $newSharePath = Read-Host "New share (UNC), or Enter to keep"
        if ($newSharePath -eq "") { break }
        if ($newSharePath -match '^\\\\[^\\]+\\') {
            $cfg.SharePath = $newSharePath
            break
        }
        else {
            Write-Host "Invalid UNC; or leave blank." -ForegroundColor Yellow
        }
    } while ($true)

    do {
        $newDriveLetter = Read-Host "New drive letter (A–Z), or Enter"
        if ($newDriveLetter -eq "") { break }
        if ($newDriveLetter -match '^[A-Za-z]$') {
            $cfg.DriveLetter = $newDriveLetter.ToUpper()
            break
        }
        else {
            Write-Host "Enter single letter A–Z, or blank." -ForegroundColor Yellow
        }
    } while ($true)

    $newUsername = Read-Host "New username, or Enter"
    if ($newUsername -ne "") {
        $cfg.Username = $newUsername
    }

    Save-Config -SharePath       $cfg.SharePath `
                -DriveLetter     $cfg.DriveLetter `
                -Username        $cfg.Username `
                -UnmapOldMapping $prefs.UnmapOldMapping `
                -PreferredMode   $prefs.PreferredMode

    if ($prefs.UnmapOldMapping -and $oldDrive -ne $cfg.DriveLetter -and (Test-Path "$oldDrive`:")) {
        Unmap-Share -DriveLetter $oldDrive
        Write-Host "Old drive $oldDrive unmapped due to letter change." -ForegroundColor Yellow
        Log-Action "Unmapped old drive $oldDrive"
    }
}

function Preferences-CLI {
    $cfg   = Load-Config
    if (-not $cfg) { return }
    $prefs = $cfg.Preferences

    Clear-Host
    Write-Host "=== Preferences v$version ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Auto-unmap on drive change: $($prefs.UnmapOldMapping)"
    Write-Host "2. Preferred startup mode    : $($prefs.PreferredMode)"
    Write-Host "3. Back"
    Write-Host ""

    $choice = Read-Host "Select (1-3)"
    switch ($choice) {
        "1" {
            do {
                $yn = Read-Host "Auto-unmap on letter change? (Y/N)"
                if ($yn -match '^[YyNn]$') { break }
                Write-Host "Enter Y or N." -ForegroundColor Yellow
            } while ($true)
            $newUnmap = $yn -match '^[Yy]$'
            Save-Config -SharePath       $cfg.SharePath `
                        -DriveLetter     $cfg.DriveLetter `
                        -Username        $cfg.Username `
                        -UnmapOldMapping $newUnmap `
                        -PreferredMode   $prefs.PreferredMode
            Write-Host "Updated." -ForegroundColor Green
        }
        "2" {
            Write-Host "Mode: 1) CLI  2) GUI  3) Prompt"
            do {
                $m = Read-Host "Enter 1, 2, or 3"
                if ($m -match '^[123]$') { break }
                Write-Host "Enter 1-3." -ForegroundColor Yellow
            } while ($true)
            switch ($m) {
                "1" { $nm = "CLI" }
                "2" { $nm = "GUI" }
                "3" { $nm = "Prompt" }
            }
            Save-Config -SharePath       $cfg.SharePath `
                        -DriveLetter     $cfg.DriveLetter `
                        -Username        $cfg.Username `
                        -UnmapOldMapping $prefs.UnmapOldMapping `
                        -PreferredMode   $nm
            Write-Host "Updated." -ForegroundColor Green
        }
        default { return }
    }
}

function Update-CredentialsMenu-CLI {
    Write-Host "=== Credentials Menu v$version ===" -ForegroundColor Cyan
    Write-Host "1. Save/Update Credentials"
    Write-Host "2. Remove Stored Credentials"
    Write-Host "3. Back"
    Write-Host ""
    $sub = Read-Host "Select (1-3)"
    switch ($sub) {
        "1" {
            $cc = Load-Config
            if (-not $cc) {
                Write-Host "No configuration found. Please configure first." -ForegroundColor Yellow
                return
            }
            $username = $cc.Username
            $password = Read-Password ("Enter password for $($username): ")
            if ($password.Length -gt 0) {
                $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                Save-Credential -Credential $cred
            }
            else {
                Write-Host "Credential prompt cancelled; nothing saved." -ForegroundColor Yellow
            }
        }
        "2" {
            Remove-Credential
        }
        default { return }
    }
}

function Run-CLI {
    do {
        Show-CLI-Menu
        $choice = Read-Host "Choice (1-9)"
        switch ($choice) {
            "1" {
                $cfg  = Load-Config
                if (-not $cfg) {
                    Write-Host "No configuration found. Please run 'Configure Settings' first." -ForegroundColor Yellow
                    break
                }
                $cred = Load-Credential
                if (-not $cred) {
                    Write-Host "No saved credentials. Please enter now." -ForegroundColor Yellow
                    $username = $cfg.Username
                    $password = Read-Password ("Enter password for $($username): ")
                    if ($password.Length -gt 0) {
                        $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                        Save-Credential -Credential $cred
                    }
                    else {
                        Write-Host "Credential prompt cancelled; mapping skipped." -ForegroundColor Yellow
                        break
                    }
                }
                Map-Share -SharePath   $cfg.SharePath `
                          -DriveLetter $cfg.DriveLetter `
                          -Credential  $cred
            }
            "2" {
                $cfg = Load-Config
                if ($cfg) {
                    Unmap-Share -DriveLetter $cfg.DriveLetter
                }
                else {
                    Write-Host "No configuration found." -ForegroundColor Yellow
                }
            }
            "3" { Configure-Settings-CLI }
            "4" { Preferences-CLI }
            "5" { Update-CredentialsMenu-CLI }
            "6" { Open-LogFile }
            "7" {
                $cfg = Load-Config
                if ($cfg) {
                    if (Test-ShareOnline -SharePath $cfg.SharePath) {
                        Write-Host "Share '$($cfg.SharePath)' is ONLINE." -ForegroundColor Green
                    } else {
                        Write-Host "Share '$($cfg.SharePath)' is OFFLINE." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "No configuration found." -ForegroundColor Yellow
                }
            }
            "8" {
                Write-Host "Switching to GUI mode..."
                Start-Process -FilePath "powershell.exe" `
                    -ArgumentList "-ExecutionPolicy Bypass -STA -File `"$PSCommandPath`" -StartupMode GUI" `
                    -WindowStyle Normal
                exit
            }
            "9" { exit }
            default { Write-Host "Invalid." -ForegroundColor Red }
        }
        if ($choice -ne "9" -and $choice -ne "8") { Write-Host ""; Pause }
    } while ($true)
}

#endregion

#region GUI Mode

function Show-PreferencesForm {
    param (
        [PSCustomObject]$CurrentPrefs,
        [bool]$IsInitial
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $prefs = [PSCustomObject]@{
        UnmapOldMapping = [bool]$CurrentPrefs.UnmapOldMapping
        PreferredMode   = $CurrentPrefs.PreferredMode
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "Preferences v$version"
    $form.Width           = 350
    $form.Height          = 260
    $form.StartPosition   = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox     = $false

    # Checkbox
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text     = "Auto-unmap on letter change"
    $chk.AutoSize = $true
    $chk.Top      = 20
    $chk.Left     = 20
    $chk.Checked  = $prefs.UnmapOldMapping
    $form.Controls.Add($chk)

    # Label
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text     = "Startup mode:"
    $lbl.AutoSize = $true
    $lbl.Top      = 60
    $lbl.Left     = 20
    $form.Controls.Add($lbl)

    # Radio buttons
    $rdoCLI    = New-Object System.Windows.Forms.RadioButton
    $rdoCLI.Text     = "CLI"
    $rdoCLI.AutoSize = $true
    $rdoCLI.Top      = 90
    $rdoCLI.Left     = 40
    $rdoGUI    = New-Object System.Windows.Forms.RadioButton
    $rdoGUI.Text     = "GUI"
    $rdoGUI.AutoSize = $true
    $rdoGUI.Top      = 120
    $rdoGUI.Left     = 40
    $rdoPrompt = New-Object System.Windows.Forms.RadioButton
    $rdoPrompt.Text     = "Prompt"
    $rdoPrompt.AutoSize = $true
    $rdoPrompt.Top      = 150
    $rdoPrompt.Left     = 40

    switch ($prefs.PreferredMode) {
        "CLI"    { $rdoCLI.Checked    = $true }
        "GUI"    { $rdoGUI.Checked    = $true }
        "Prompt" { $rdoPrompt.Checked = $true }
    }
    $form.Controls.Add($rdoCLI)
    $form.Controls.Add($rdoGUI)
    $form.Controls.Add($rdoPrompt)

    # Save button
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text   = "Save"
    $btnSave.Width  = 100
    $btnSave.Height = 30
    $btnSave.Top    = 190
    $btnSave.Left   = 50
    $btnSave.Add_Click({
        $prefs.UnmapOldMapping = $chk.Checked
        if ($rdoCLI.Checked)    { $prefs.PreferredMode = "CLI" }
        elseif ($rdoGUI.Checked) { $prefs.PreferredMode = "GUI" }
        else                     { $prefs.PreferredMode = "Prompt" }

        $form.Tag = $prefs
        $form.Close()
    })
    $form.Controls.Add($btnSave)

    # Cancel (if not initial)
    if (-not $IsInitial) {
        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text   = "Cancel"
        $btnCancel.Width  = 100
        $btnCancel.Height = 30
        $btnCancel.Top    = 190
        $btnCancel.Left   = 180
        $btnCancel.Add_Click({ $form.Close() })
        $form.Controls.Add($btnCancel)
    }

    [void]$form.ShowDialog()
    return $form.Tag
}

function Minimize-Console {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
    $hWnd = [Win]::GetConsoleWindow()
    [Win]::ShowWindow($hWnd, 2)
}

function Show-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic

    Minimize-Console

    $cfg   = Load-Config
    
    $loaded = Load-Credential
    if ($loaded) { $script:cred = $loaded }
    else { $script:cred = $null }
    
    $prefs = $cfg.Preferences

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "Share Manager v$version"
    $form.Width           = 400
    $form.Height          = 560
    $form.StartPosition   = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox     = $false

    # Title
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = "Share Manager v$version"
    $lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI",14,[System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize = $true
    $lblTitle.Top      = 15
    $lblTitle.Left     = 80
    $form.Controls.Add($lblTitle)

    # Map
    $btnMap = New-Object System.Windows.Forms.Button
    $btnMap.Text   = "Map Share"
    $btnMap.Width  = 140
    $btnMap.Height = 35
    $btnMap.Top    = 60
    $btnMap.Left   = 20
    $btnMap.Add_Click({
        if (-not $script:cred) {
            [System.Windows.Forms.MessageBox]::Show(
                "No credentials saved. You will be prompted.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            $newCred = Get-Credential -Message "Enter credentials for $($cfg.Username) at $($cfg.SharePath)" -UserName $cfg.Username
            if ($newCred) {
                Save-Credential -Credential $newCred
                $script:cred = $newCred
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Credential prompt cancelled; mapping skipped.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
        }
        Map-Share -SharePath   $cfg.SharePath `
                  -DriveLetter $cfg.DriveLetter `
                  -Credential  $script:cred
    })
    $form.Controls.Add($btnMap)

    # Unmap
    $btnUnmap = New-Object System.Windows.Forms.Button
    $btnUnmap.Text   = "Unmap Share"
    $btnUnmap.Width  = 140
    $btnUnmap.Height = 35
    $btnUnmap.Top    = 60
    $btnUnmap.Left   = 180
    $btnUnmap.Add_Click({
        Unmap-Share -DriveLetter $cfg.DriveLetter
    })
    $form.Controls.Add($btnUnmap)

    # Test Connectivity
    $btnTest = New-Object System.Windows.Forms.Button
    $btnTest.Text   = "Test Connectivity"
    $btnTest.Width  = 350
    $btnTest.Height = 35
    $btnTest.Top    = 120
    $btnTest.Left   = 20
    $btnTest.Add_Click({
        if (Test-ShareOnline -SharePath $cfg.SharePath) {
            [System.Windows.Forms.MessageBox]::Show(
                "Share $($cfg.SharePath) is online.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            Log-Action "Tested share connectivity: ONLINE"
        } else {
            [System.Windows.Forms.MessageBox]::Show(
                "Share $($cfg.SharePath) is unreachable.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            Log-Action "Tested share connectivity: OFFLINE"
        }
    })
    $form.Controls.Add($btnTest)

    # Configure Settings
    $btnConfig = New-Object System.Windows.Forms.Button
    $btnConfig.Text   = "Configure Settings"
    $btnConfig.Width  = 350
    $btnConfig.Height = 35
    $btnConfig.Top    = 180
    $btnConfig.Left   = 20
    $btnConfig.Add_Click({
        $oldDrive = $cfg.DriveLetter

        do {
            $newShare = Show-InputBox -Prompt "Enter share (\\server\share)" `
                                      -Title  "Update Share" `
                                      -DefaultValue $cfg.SharePath
            if ($newShare -eq "") { break }
            if ($newShare -match '^\\\\[^\\]+\\') {
                $cfg.SharePath = $newShare
                break
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Invalid UNC; try again or Cancel.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
        } while ($true)

        do {
            $newDrive = Show-InputBox -Prompt "Enter drive letter (A–Z)" `
                                      -Title  "Update Drive Letter" `
                                      -DefaultValue $cfg.DriveLetter
            if ($newDrive -eq "") { break }
            if ($newDrive -match '^[A-Za-z]$') {
                $cfg.DriveLetter = $newDrive.ToUpper()
                break
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Invalid letter; try A–Z or Cancel.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
        } while ($true)

        $newUser = Show-InputBox -Prompt "Enter username" `
                                 -Title  "Update Username" `
                                 -DefaultValue $cfg.Username
        if ($newUser -ne "") {
            $cfg.Username = $newUser
        }

        Save-Config -SharePath       $cfg.SharePath `
                    -DriveLetter     $cfg.DriveLetter `
                    -Username        $cfg.Username `
                    -UnmapOldMapping $prefs.UnmapOldMapping `
                    -PreferredMode   $prefs.PreferredMode

        $cfg   = Load-Config
        $prefs = $cfg.Preferences

        if ($prefs.UnmapOldMapping -and $oldDrive -ne $cfg.DriveLetter -and (Test-Path "$oldDrive`:")) {
            Unmap-Share -DriveLetter $oldDrive
            [System.Windows.Forms.MessageBox]::Show(
                "Old drive $oldDrive unmapped.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            Log-Action "Unmapped old drive $oldDrive"
        }
    })
    $form.Controls.Add($btnConfig)

    # Preferences
    $btnPrefs = New-Object System.Windows.Forms.Button
    $btnPrefs.Text   = "Preferences"
    $btnPrefs.Width  = 350
    $btnPrefs.Height = 35
    $btnPrefs.Top    = 240
    $btnPrefs.Left   = 20
    $btnPrefs.Add_Click({
        $newPrefs = Show-PreferencesForm -CurrentPrefs $prefs -IsInitial $false
        if ($null -ne $newPrefs) {
            Save-Config -SharePath       $cfg.SharePath `
                        -DriveLetter     $cfg.DriveLetter `
                        -Username        $cfg.Username `
                        -UnmapOldMapping $newPrefs.UnmapOldMapping `
                        -PreferredMode   $newPrefs.PreferredMode
            $cfg   = Load-Config
            $prefs = $cfg.Preferences
        }
    })
    $form.Controls.Add($btnPrefs)

    # Credentials
    $btnCred = New-Object System.Windows.Forms.Button
    $btnCred.Text   = "Update/Remove Credentials"
    $btnCred.Width  = 350
    $btnCred.Height = 35
    $btnCred.Top    = 300
    $btnCred.Left   = 20
    $btnCred.Add_Click({
        $choice = [System.Windows.Forms.MessageBox]::Show(
            "Yes → Save/Update.  No → Remove.",
            "Credentials Menu",
            [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        switch ($choice) {
            'Yes' {
                $prompt = "Enter credentials for $($cfg.Username) at $($cfg.SharePath)"
                $newCred = Get-Credential -Message $prompt -UserName $cfg.Username
                if ($newCred) {
                    Save-Credential -Credential $newCred
                    $script:cred = $newCred
                } else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Credential prompt cancelled; nothing saved.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                }
            }
            'No' {
                Remove-Credential
                $script:cred = $null
            }
            default { }
        }
    })
    $form.Controls.Add($btnCred)

    # Open Log
    $btnLog = New-Object System.Windows.Forms.Button
    $btnLog.Text   = "Open Log File"
    $btnLog.Width  = 140
    $btnLog.Height = 35
    $btnLog.Top    = 360
    $btnLog.Left   = 20
    $btnLog.Add_Click({
        Open-LogFile
    })
    $form.Controls.Add($btnLog)

    # Rotate Log
    $btnRotate = New-Object System.Windows.Forms.Button
    $btnRotate.Text   = "Rotate Log Now"
    $btnRotate.Width  = 140
    $btnRotate.Height = 35
    $btnRotate.Top    = 360
    $btnRotate.Left   = 180
    $btnRotate.Add_Click({
        Rotate-LogIfNeeded
        [System.Windows.Forms.MessageBox]::Show(
            "Log rotation done.",
            "Share Manager v$version",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    })
    $form.Controls.Add($btnRotate)

    # Switch to CLI Button
    $btnSwitchCLI = New-Object System.Windows.Forms.Button
    $btnSwitchCLI.Text   = "Switch to CLI"
    $btnSwitchCLI.Width  = 350
    $btnSwitchCLI.Height = 35
    $btnSwitchCLI.Top    = 420
    $btnSwitchCLI.Left   = 20
    $btnSwitchCLI.Add_Click({
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -StartupMode CLI" `
            -WindowStyle Normal
        $form.Close()
    })
    $form.Controls.Add($btnSwitchCLI)

    # Exit
    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text   = "Exit"
    $btnExit.Width  = 350
    $btnExit.Height = 35
    $btnExit.Top    = 480
    $btnExit.Left   = 20
    $btnExit.Add_Click({
        $form.Close()
    })
    $form.Controls.Add($btnExit)

    [void]$form.ShowDialog()
}

#endregion

#region Mode Selection (Entry Point)

$cfg = Load-Config

# If StartupMode parameter is provided, override preference
if ($StartupMode -eq "CLI" -or $StartupMode -eq "GUI") {
    if ($StartupMode -eq "CLI") {
        $script:UseGUI = $false
        Run-CLI
        return
    }
    elseif ($StartupMode -eq "GUI") {
        $script:UseGUI = $true
        Show-GUI
        return
    }
}

# Otherwise, use saved preference if present
if ($cfg) {
    switch ($cfg.Preferences.PreferredMode) {
        "CLI" {
            $script:UseGUI = $false
            Run-CLI
            return
        }
        "GUI" {
            $script:UseGUI = $true
            Show-GUI
            return
        }
        default { }  # Prompt if "Prompt"
    }
}

# If no saved config or preference is "Prompt", ask user
Write-Host ""
Write-Host "Choose startup mode for Share Manager v${version}:" -ForegroundColor Cyan
Write-Host "1. CLI Mode"
Write-Host "2. GUI Mode"
$mode = Read-Host "Enter 1 or 2"

switch ($mode) {
    "1" {
        $script:UseGUI = $false
        if (-not $cfg) { Initialize-Config-CLI }
        Run-CLI
    }
    "2" {
        $script:UseGUI = $true
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName Microsoft.VisualBasic
        if (-not $cfg) { Initialize-Config-GUI }
        Show-GUI
    }
    default {
        Write-Host "Invalid. Defaulting to CLI v${version}." -ForegroundColor Yellow
        $script:UseGUI = $false
        if (-not $cfg) { Initialize-Config-CLI }
        Run-CLI
    }
}

#endregion
