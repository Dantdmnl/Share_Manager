<#
.SYNOPSIS
    Share Manager Script (v2.0.0) - Manage multiple network shares via CLI or GUI,
    with robust credential persistence using Windows DPAPI (per-user, per-machine).

.DESCRIPTION
    - Interactive management of multiple network shares (SMB) with both CLI and GUI interfaces.
    - Support for multiple share configurations with profiles
    - Quick connect/disconnect/reset functionality for shares
    - Detailed status monitoring and error diagnostics
    - Import/Export configuration backup
        - Credentials stored securely using Windows DPAPI in '%APPDATA%\Share_Manager\creds.json'.
            Legacy AES files (cred.txt/key.bin) are automatically migrated on first use; backups are created.
    - CLI password entry shows asterisks as you type.
    - Users can switch between CLI and GUI without losing configuration.
    - Logs actions to '%APPDATA%\Share_Manager\Share_Manager.log', with automatic rotation.
    - Preferences pane to toggle auto-unmapping on drive-letter change, select startup mode and persistent mapping.
    - Version number displayed in title bars and menus.
    - Author: Dantdmnl.

.PARAMETER StartupMode
    Optional. Pass "CLI" or "GUI" to force that mode on launch, bypassing saved preference.

.VERSION
    2.0.0

.NOTES
    - No administrator permissions are required.
    - GUI mode requires '-STA' when launching PowerShell:
      powershell.exe -ExecutionPolicy Bypass -STA -File "C:\Scripts\Share_Manager.ps1"
#>

param(
    [string]$StartupMode
)

#region Global Variables (Version, Paths, Defaults)

$version        = '2.0.0'
$author         = 'Dantdmnl'
$baseFolder     = Join-Path $env:APPDATA "Share_Manager"
if (-not (Test-Path $baseFolder)) {
    New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
}
$configPath       = Join-Path $baseFolder "config.json"
$sharesPath       = Join-Path $baseFolder "shares.json"
$credentialPath   = Join-Path $baseFolder "cred.txt"
$credentialsStorePath = Join-Path $baseFolder "creds.json"
$keyPath          = Join-Path $baseFolder "key.bin"
$logPath          = Join-Path $baseFolder "Share_Manager.log"

# Legacy support - old single-share config
$defaultConfigTemplate = [PSCustomObject]@{
    SharePath   = $null
    DriveLetter = $null
    Username    = $null
    Preferences = [PSCustomObject]@{
        UnmapOldMapping = $true
        PreferredMode   = "Prompt"
    }
}

# New multi-share configuration template
$defaultSharesConfig = [PSCustomObject]@{
    Shares = @()
    Preferences = [PSCustomObject]@{
        UnmapOldMapping   = $true
        PreferredMode     = "Prompt"
        PersistentMapping = $false
        AutoReconnect     = $true
        ReconnectInterval = 300  # seconds
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

function Invoke-LogRotation {
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

function Write-ActionLog {
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

Invoke-LogRotation

#region New Multi-Share Functions

function New-ShareEntry {
    <#
    .SYNOPSIS
        Creates a new share configuration entry
    #>
    param (
        [string]$Name,
        [string]$SharePath,
        [string]$DriveLetter,
        [string]$Username,
        [string]$Description = "",
        [bool]$Enabled = $true
    )
    
    return [PSCustomObject]@{
        Id          = [guid]::NewGuid().ToString()
        Name        = $Name
        SharePath   = $SharePath
        DriveLetter = $DriveLetter
        Username    = $Username
        Description = $Description
        Enabled     = $Enabled
        LastConnected = $null
        CredentialId = $Username  # Links to credential storage
    }
}

function Import-AllShares {
    <#
    .SYNOPSIS
        Imports all share configurations from shares.json
    #>
    if (Test-Path $sharesPath) {
        try {
            $json = Get-Content -Path $sharesPath -Raw
            $config = ConvertFrom-Json $json
            
            # Ensure Shares is an array
            if (-not $config.PSObject.Properties['Shares']) {
                $config | Add-Member -MemberType NoteProperty -Name Shares -Value @()
            }
            
            # Ensure Preferences exist
            if (-not $config.PSObject.Properties['Preferences']) {
                $config | Add-Member -MemberType NoteProperty -Name Preferences -Value $defaultSharesConfig.Preferences
            } else {
                # Add missing preference properties
                if (-not $config.Preferences.PSObject.Properties['AutoReconnect']) {
                    $config.Preferences | Add-Member -MemberType NoteProperty -Name AutoReconnect -Value $true
                }
                if (-not $config.Preferences.PSObject.Properties['ReconnectInterval']) {
                    $config.Preferences | Add-Member -MemberType NoteProperty -Name ReconnectInterval -Value 300
                }
            }
            
            return $config
        }
        catch {
            Write-ActionLog "Failed to import shares config: $_"
            return $defaultSharesConfig
        }
    }
    
    return $defaultSharesConfig
}

function Save-AllShares {
    <#
    .SYNOPSIS
        Saves all share configurations to shares.json
    #>
    param (
        [PSCustomObject]$Config
    )
    
    try {
        $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $sharesPath -Encoding UTF8 -Force
        Write-ActionLog "Saved all shares configuration"
        return $true
    }
    catch {
        Write-ActionLog "Failed to save shares config: $_"
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to save configuration: $_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        return $false
    }
}

function Add-ShareConfiguration {
    <#
    .SYNOPSIS
        Adds a new share to the configuration
    #>
    param (
        [string]$Name,
        [string]$SharePath,
        [string]$DriveLetter,
        [string]$Username,
        [string]$Description = ""
    )
    
    $config = Import-AllShares
    $newShare = New-ShareEntry -Name $Name -SharePath $SharePath -DriveLetter $DriveLetter -Username $Username -Description $Description
    
    # Check for duplicate drive letters
    $existing = $config.Shares | Where-Object { $_.DriveLetter -eq $DriveLetter -and $_.Enabled }
    if ($existing) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Drive letter $DriveLetter is already assigned to share '$($existing.Name)'",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        } else {
            Write-Host "Warning: Drive $DriveLetter already assigned to '$($existing.Name)'" -ForegroundColor Yellow
        }
        return $null
    }
    
    $config.Shares += $newShare
    if (Save-AllShares -Config $config) {
        Write-ActionLog "Added new share: $Name ($SharePath -> $DriveLetter)"
        return $newShare
    }
    return $null
}

function Update-ShareConfiguration {
    <#
    .SYNOPSIS
        Updates an existing share by ID
    #>
    param (
        [string]$ShareId,
        [string]$Name,
        [string]$SharePath,
        [string]$DriveLetter,
        [string]$Username,
        [string]$Description = "",
        [bool]$Enabled
    )
    $config = Import-AllShares
    $share = $config.Shares | Where-Object { $_.Id -eq $ShareId }
    if (-not $share) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Share not found.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        } else {
            Write-Host "Share not found." -ForegroundColor Yellow
        }
        return $false
    }

    # If drive letter is changing, ensure no conflict with other enabled shares
    if ($DriveLetter -and $DriveLetter -ne $share.DriveLetter) {
        $conflict = $config.Shares | Where-Object { $_.Id -ne $ShareId -and $_.Enabled -and $_.DriveLetter -eq $DriveLetter }
        if ($conflict) {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Drive letter $DriveLetter is already assigned to share '$($conflict.Name)'.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            } else {
                Write-Host "Warning: Drive $DriveLetter already assigned to '$($conflict.Name)'" -ForegroundColor Yellow
            }
            return $false
        }
    }

    # Apply updates
    if ($null -ne $Name)        { $share.Name        = $Name }
    if ($null -ne $SharePath)   { $share.SharePath   = $SharePath }
    if ($null -ne $DriveLetter) { $share.DriveLetter = $DriveLetter }
    if ($null -ne $Username)    { $share.Username    = $Username }
    if ($null -ne $Description) { $share.Description = $Description }
    if ($PSBoundParameters.ContainsKey('Enabled')) { $share.Enabled = [bool]$Enabled }

    if (Save-AllShares -Config $config) {
        Write-ActionLog "Updated share: $($share.Name) ($ShareId)"
        return $true
    }
    return $false
}

function Remove-ShareConfiguration {
    <#
    .SYNOPSIS
        Removes a share from configuration by ID
    #>
    param (
        [string]$ShareId
    )
    
    $config = Import-AllShares
    $share = $config.Shares | Where-Object { $_.Id -eq $ShareId }
    
    if (-not $share) {
        Write-Host "Share not found." -ForegroundColor Yellow
        return $false
    }
    
    $config.Shares = @($config.Shares | Where-Object { $_.Id -ne $ShareId })
    
    if (Save-AllShares -Config $config) {
        Write-ActionLog "Removed share: $($share.Name)"
        return $true
    }
    return $false
}

function Get-ShareConfiguration {
    <#
    .SYNOPSIS
        Gets a specific share by ID or all shares
    #>
    param (
        [string]$ShareId = $null
    )
    
    $config = Import-AllShares
    
    if ($ShareId) {
        return $config.Shares | Where-Object { $_.Id -eq $ShareId }
    }
    
    return $config.Shares
}

function Test-ShareConnection {
    <#
    .SYNOPSIS
        Tests if a share is currently connected
    #>
    param (
        [string]$DriveLetter
    )
    
    if (Test-Path "${DriveLetter}:") {
        try {
            # Verify it's actually our network share
            $drive = Get-PSDrive -Name $DriveLetter -PSProvider FileSystem -ErrorAction Stop
            return ($drive.DisplayRoot -match '^\\\\')
        }
        catch {
            return $false
        }
    }
    return $false
}

function Get-CredentialForShare {
    <#
    .SYNOPSIS
        Gets credential for a specific username with automatic migration from legacy AES to DPAPI
    #>
    param (
        [string]$Username
    )
    
    if ([string]::IsNullOrWhiteSpace($Username)) { return $null }

    # Prefer JSON multi-credential store
    $store = Import-CredentialStore
    if ($store -and $store.Entries) {
        $entry = $store.Entries | Where-Object { $_.Username -eq $Username }
        if ($entry) {
            try {
                $securePW = $null
                
                # Check encryption type and decrypt accordingly
                if ($entry.EncryptionType -eq "DPAPI") {
                    # Modern DPAPI encryption
                    $securePW = $entry.Encrypted | ConvertTo-SecureString
                } else {
                    # Legacy AES encryption - migrate to DPAPI
                    $aesKey = Get-Key
                    if ($aesKey) {
                        $securePW = $entry.Encrypted | ConvertTo-SecureString -Key $aesKey
                        
                        # Migrate to DPAPI and save
                        $entry.Encrypted = $securePW | ConvertFrom-SecureString
                        $entry.EncryptionType = "DPAPI"
                        $store | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialsStorePath -Encoding UTF8 -Force
                        Write-ActionLog "Migrated credential to DPAPI encryption"
                    } else {
                        # Try DPAPI anyway (might be legacy DPAPI without marker)
                        $securePW = $entry.Encrypted | ConvertTo-SecureString
                    }
                }
                
                if ($securePW) {
                    return New-Object System.Management.Automation.PSCredential($Username, $securePW)
                }
            } catch { 
                Write-ActionLog "Failed to decrypt credential for username: $_"
            }
        }
    }
    
    # Fallback to legacy single cred file (auto-migrate if found)
    $legacy = Import-SavedCredential
    if ($legacy -and $legacy.UserName -eq $Username) { 
        # Auto-migrate to modern store
        try {
            Save-Credential -Credential $legacy
            Write-ActionLog "Auto-migrated legacy credential to modern store"
        } catch {
            Write-ActionLog "Failed to auto-migrate legacy credential: $_"
        }
        return $legacy
    }

    return $null
}

function Export-ShareConfiguration {
    <#
    .SYNOPSIS
        Exports configuration to a backup file
    #>
    param (
        [string]$ExportPath
    )
    
    try {
        $config = Import-AllShares
        $exportData = @{
            Version = $version
            ExportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Shares = $config.Shares
            Preferences = $config.Preferences
        }
        
        $exportData | ConvertTo-Json -Depth 10 | Set-Content -Path $ExportPath -Encoding UTF8 -Force
        Write-ActionLog "Exported configuration to $ExportPath"
        return $true
    }
    catch {
        Write-ActionLog "Failed to export configuration: $_"
        return $false
    }
}

function Import-ShareConfiguration {
    <#
    .SYNOPSIS
        Imports configuration from a backup file
    .OUTPUTS
        Returns hashtable with Success, Added, Skipped properties for merge operations
    #>
    param (
        [string]$ImportPath,
        [bool]$Merge = $false
    )
    
    if (-not (Test-Path $ImportPath)) {
        Write-Host "Import file not found: $ImportPath" -ForegroundColor Red
        return @{ Success = $false; Added = 0; Skipped = 0 }
    }
    
    try {
        $json = Get-Content -Path $ImportPath -Raw
        $importData = ConvertFrom-Json $json
        
        $added = 0
        $skipped = 0
        
        if ($Merge) {
            # Merge with existing (skip duplicates)
            $config = Import-AllShares
            
            foreach ($share in $importData.Shares) {
                # Check if duplicate exists (same SharePath OR same DriveLetter)
                $isDuplicate = $config.Shares | Where-Object {
                    $_.SharePath -eq $share.SharePath -or $_.DriveLetter -eq $share.DriveLetter
                }
                
                if (-not $isDuplicate) {
                    # Generate new ID to avoid conflicts
                    $share.Id = [guid]::NewGuid().ToString()
                    $config.Shares += $share
                    $added++
                } else {
                    $skipped++
                }
            }
            
            Write-ActionLog "Merged configuration: $added added, $skipped duplicates skipped"
        } else {
            # Replace existing
            $config = [PSCustomObject]@{
                Shares = $importData.Shares
                Preferences = $importData.Preferences
            }
            $added = $importData.Shares.Count
        }
        
        if (Save-AllShares -Config $config) {
            Write-ActionLog "Imported configuration from $ImportPath (Merge: $Merge)"
            return @{ Success = $true; Added = $added; Skipped = $skipped }
        }
    }
    catch {
        Write-ActionLog "Failed to import configuration: $_"
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to import: $_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        return @{ Success = $false; Added = 0; Skipped = 0 }
    }
    
    return @{ Success = $false; Added = 0; Skipped = 0 }
}

function Get-DetailedShareStatus {
    <#
    .SYNOPSIS
        Gets detailed status information for a share
    #>
    param (
        [string]$ShareId
    )
    
    $share = Get-ShareConfiguration -ShareId $ShareId
    if (-not $share) { return $null }
    
    $status = [PSCustomObject]@{
        Share = $share
        IsConnected = Test-ShareConnection -DriveLetter $share.DriveLetter
        HostOnline = Test-ShareOnline -SharePath $share.SharePath
        HasCredentials = $null -ne (Get-CredentialForShare -Username $share.Username)
        DriveAvailable = -not (Test-Path "$($share.DriveLetter):")
    }
    
    # Determine issue if not connected
    if (-not $status.IsConnected) {
        if (-not $status.HostOnline) {
            $status | Add-Member -NotePropertyName Issue -NotePropertyValue "Host offline or unreachable"
        } elseif (-not $status.HasCredentials) {
            $status | Add-Member -NotePropertyName Issue -NotePropertyValue "No credentials available"
        } elseif (-not $status.DriveAvailable) {
            $status | Add-Member -NotePropertyName Issue -NotePropertyValue "Drive letter in use by another resource"
        } else {
            $status | Add-Member -NotePropertyName Issue -NotePropertyValue "Unknown - may need to reconnect"
        }
    } else {
        $status | Add-Member -NotePropertyName Issue -NotePropertyValue "None"
    }
    
    return $status
}

#endregion

function Convert-LegacyConfig {
    <#
    .SYNOPSIS
        Migrates old single-share config to new multi-share format
    #>
    $oldConfig = Import-ShareConfig
    if (-not $oldConfig) { return }
    
    # Check if already migrated
    $newConfig = Import-AllShares
    if ($newConfig.Shares.Count -gt 0) { return }
    
    Write-ActionLog "Migrating legacy configuration to v2.0 format"
    
    # Create share entry from old config
    if ($oldConfig.SharePath -and $oldConfig.DriveLetter) {
        $share = New-ShareEntry `
            -Name "Primary Share" `
            -SharePath $oldConfig.SharePath `
            -DriveLetter $oldConfig.DriveLetter `
            -Username $oldConfig.Username `
            -Description "Migrated from v1.x"
        
        $newConfig.Shares += $share
        
        # Migrate preferences
        if ($oldConfig.Preferences) {
            $newConfig.Preferences.UnmapOldMapping = $oldConfig.Preferences.UnmapOldMapping
            $newConfig.Preferences.PreferredMode = $oldConfig.Preferences.PreferredMode
            if ($oldConfig.Preferences.PSObject.Properties['PersistentMapping']) {
                $newConfig.Preferences.PersistentMapping = $oldConfig.Preferences.PersistentMapping
            }
        }
        
        Save-AllShares -Config $newConfig | Out-Null
        
        # Backup and remove old config
        $backupPath = "$configPath.v1.backup"
        Copy-Item $configPath $backupPath -Force
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
        Write-ActionLog "Legacy config backed up to $backupPath and removed"
        
        # Clean up old single-credential file if it exists
        $oldCredPath = Join-Path $baseFolder "cred.txt"
        if (Test-Path $oldCredPath) {
            $oldCredBackup = "$oldCredPath.v1.backup"
            Copy-Item $oldCredPath $oldCredBackup -Force
            Remove-Item $oldCredPath -Force -ErrorAction SilentlyContinue
            Write-ActionLog "Legacy cred.txt backed up and removed"
        }
        
        # Note: key.bin is kept for legacy credential decryption compatibility
        
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Your configuration has been upgraded to v2.0 format.`n`nYou can now manage multiple network shares!`n`nOld files backed up to *.v1.backup and removed.",
                "Share Manager v$version - Upgraded",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } else {
            Write-Host "`nConfiguration upgraded to v2.0 format!" -ForegroundColor Green
            Write-Host "You can now manage multiple shares." -ForegroundColor Cyan
            Write-Host "Old files backed up to *.v1.backup and removed`n" -ForegroundColor Gray
        }
    }
}

function Import-ShareConfig {
    if (Test-Path $configPath) {
        try {
            $json = Get-Content -Path $configPath -Raw
            $cfg  = ConvertFrom-Json $json
            if (-not $cfg.PSObject.Properties['Preferences']) {
                $cfg | Add-Member -MemberType NoteProperty -Name Preferences -Value $defaultConfigTemplate.Preferences
            }
            # Add PersistentMapping if missing
            if (-not $cfg.Preferences.PSObject.Properties['PersistentMapping']) {
                $cfg.Preferences | Add-Member -MemberType NoteProperty -Name PersistentMapping -Value $false
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
        [string]$PreferredMode,
        [bool]  $PersistentMapping = $false
    )
    $obj = [PSCustomObject]@{
        SharePath   = $SharePath
        DriveLetter = $DriveLetter
        Username    = $Username
        Preferences = [PSCustomObject]@{
            UnmapOldMapping   = $UnmapOldMapping
            PreferredMode     = $PreferredMode
            PersistentMapping = $PersistentMapping
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
        Write-ActionLog "Saved config: SharePath=$SharePath, DriveLetter=$DriveLetter, UnmapOldMapping=$UnmapOldMapping, PreferredMode=$PreferredMode, PersistentMapping=$PersistentMapping"
        # Automate logon script management
        if ($PersistentMapping) {
            Install-LogonScript
        } else {
            Remove-LogonScript
        }
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
        Write-ActionLog "Failed to save config: $_"
    }
}

#endregion

#region Credential Storage: DPAPI-Protected SecureString

function Initialize-AesKey {
    # Legacy compatibility: keep AES key if it exists for migration
    if (-not (Test-Path $keyPath)) {
        # Generate 256-bit AES key (only for legacy migration)
        $aesKey = New-Object byte[] 32
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)
        [System.IO.File]::WriteAllBytes($keyPath, $aesKey)
        Write-ActionLog "Generated new AES key at $keyPath (legacy compatibility)"
    }
}

function Get-Key {
    # Legacy compatibility only
    if (Test-Path $keyPath) {
        return [System.IO.File]::ReadAllBytes($keyPath)
    }
    return $null
}

function Save-Credential {
    param ([System.Management.Automation.PSCredential]$Credential)

    # Save credential by username in JSON store using DPAPI encryption
    try {
        $user        = $Credential.UserName
        $securePW    = $Credential.Password
        # Use DPAPI encryption (no key needed - Windows manages it per-user)
        $encryptedPW = $securePW | ConvertFrom-SecureString

        # Load store (migrate legacy if needed)
        $store = Import-CredentialStore
        if (-not $store) { $store = [PSCustomObject]@{ Entries = @() } }
        
        # Replace or add
        $existing = $store.Entries | Where-Object { $_.Username -eq $user }
        if ($existing) {
            $existing.Encrypted = $encryptedPW
            $existing.EncryptionType = "DPAPI"
        } else {
            $store.Entries += [PSCustomObject]@{ 
                Username = $user
                Encrypted = $encryptedPW
                EncryptionType = "DPAPI"
            }
        }
        
        # Persist JSON
        $store | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialsStorePath -Encoding UTF8 -Force

        if (-not $UseGUI) {
            Write-Host "Credentials saved securely for $user" -ForegroundColor Green
        }
        Write-ActionLog "Saved credential for $user"
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
        Write-ActionLog "Failed to save credential: $_"
    }
}

# Utility: Get-StartupFolder (returns user's Startup folder)
function Get-StartupFolder {
    $shell = New-Object -ComObject WScript.Shell
    return $shell.SpecialFolders.Item('Startup')
}

# Utility: Add Ctrl+A support to textbox for select all
function Add-CtrlASupport {
    param(
        [System.Windows.Forms.TextBox]$TextBox,
        [System.Windows.Forms.Control]$NextControl = $null
    )
    
    # Capture the NextControl in a local variable for the closure
    $next = $NextControl
    
    $TextBox.Add_KeyDown({
        param($s, $e)
        if ($e.Control -and $e.KeyCode -eq 'A') {
            $s.SelectAll()
            $e.SuppressKeyPress = $true
            $e.Handled = $true
        }
        elseif ($e.KeyCode -eq 'Enter') {
            if ($next) {
                # If the next control is a button, click it instead of just focusing
                if ($next -is [System.Windows.Forms.Button]) {
                    $next.PerformClick()
                } else {
                    $next.Focus()
                }
            }
            $e.SuppressKeyPress = $true
            $e.Handled = $true
        }
    }.GetNewClosure())
}

function Import-SavedCredential {
    # Legacy single credential import (backward compatibility)
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
            if (-not $UseGUI) {
                Write-Host "Warning: Legacy credential invalid or cannot be decrypted." -ForegroundColor Yellow
            }
            return $null
        }
    }
    return $null
}

function Import-CredentialStore {
    # Prefer JSON store; migrate from legacy file if needed
    if (Test-Path $credentialsStorePath) {
        try {
            $json = Get-Content -Path $credentialsStorePath -Raw -Encoding UTF8
            $obj  = $json | ConvertFrom-Json
            if (-not $obj) { return [PSCustomObject]@{ Entries = @() } }
            if (-not $obj.PSObject.Properties['Entries']) {
                $obj | Add-Member -MemberType NoteProperty -Name Entries -Value @()
            }
            return $obj
        } catch {
            Write-ActionLog "Failed to read creds store: $_"
            return [PSCustomObject]@{ Entries = @() }
        }
    }
    # Migrate single cred if exists
    $legacy = Import-SavedCredential
    if ($legacy) {
        try {
            # Migrate to DPAPI encryption
            $encryptedPW = $legacy.Password | ConvertFrom-SecureString
            $store = [PSCustomObject]@{ 
                Entries = @([PSCustomObject]@{ 
                    Username = $legacy.UserName
                    Encrypted = $encryptedPW
                    EncryptionType = "DPAPI"
                })
            }
            $store | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialsStorePath -Encoding UTF8 -Force
            Write-ActionLog "Migrated legacy credential to DPAPI store"
            
            # Clean up old credential file after successful migration
            if (Test-Path $credentialPath) {
                $backupPath = "$credentialPath.v1.backup"
                Copy-Item $credentialPath $backupPath -Force -ErrorAction SilentlyContinue
                Remove-Item $credentialPath -Force -ErrorAction SilentlyContinue
                Write-ActionLog "Legacy cred.txt backed up and removed"
            }
            
            return $store
        } catch {
            Write-ActionLog "Failed to migrate legacy cred to store: $_"
        }
    }
    return [PSCustomObject]@{ Entries = @() }
}

function Remove-Credential {
    param([string]$Username)

    $removed = $false

    # Prefer removing from JSON store
    if (Test-Path $credentialsStorePath) {
        try {
            $store = Import-CredentialStore
            if ($store -and $store.Entries) {
                if ([string]::IsNullOrWhiteSpace($Username)) {
                    # Prompt for username selection in CLI mode
                    if (-not $UseGUI) {
                        $names = ($store.Entries | Select-Object -ExpandProperty Username) | Sort-Object -Unique
                        if ($names.Count -eq 0) { }
                        elseif ($names.Count -eq 1) { $Username = $names[0] }
                        else {
                            Write-Host "Available usernames:" -ForegroundColor Cyan
                            $i = 1; foreach ($n in $names) { Write-Host "  $i. $n"; $i++ }
                            $sel = Read-Host "Remove which username (number), or 'ALL'"
                            if ($sel -match '^(all|ALL)$') { $Username = '__ALL__' }
                            else {
                                $num = 0
                                if ([int]::TryParse($sel, [ref]$num) -and $num -ge 1 -and $num -le $names.Count) { $Username = $names[$num-1] }
                            }
                        }
                    }
                }
                if ($Username -eq '__ALL__') {
                    $store.Entries = @()
                    $removed = $true
                }
                elseif ($Username) {
                    $before = $store.Entries.Count
                    $store.Entries = @($store.Entries | Where-Object { $_.Username -ne $Username })
                    $removed = ($store.Entries.Count -lt $before)
                }
                else {
                    # If no username specified and no prompt (GUI), remove all
                    $store.Entries = @()
                    $removed = $true
                }
                $store | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialsStorePath -Encoding UTF8 -Force
            }
        } catch { Write-ActionLog "Failed to update creds store during removal: $_" }
    }

    # Cleanup legacy file too
    if (Test-Path $credentialPath) { Remove-Item -Path $credentialPath -Force; $removed = $true }

    if ($removed) {
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
        Write-ActionLog "Removed stored credentials"
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
        Write-ActionLog "No credentials to remove"
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

function Connect-NetworkShare {
    param (
        [string]$SharePath,
        [string]$DriveLetter,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$Silent
    )

    # Prefer multi-share preference; fallback to legacy
    $persistent = $false
    $multiCfg = Import-AllShares
    if ($multiCfg -and $multiCfg.Preferences.PSObject.Properties["PersistentMapping"]) {
        $persistent = [bool]$multiCfg.Preferences.PersistentMapping
    } else {
        $cfg = Import-ShareConfig
        if ($cfg -and $cfg.Preferences.PSObject.Properties["PersistentMapping"]) {
            $persistent = [bool]$cfg.Preferences.PersistentMapping
        }
    }
    $persistentFlag = if ($persistent) { "/PERSISTENT:YES" } else { "/PERSISTENT:NO" }

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
        Write-ActionLog "Skipped mapping $DriveLetter -> $SharePath (offline)"
        return
    }

    try {
        $user          = $Credential.UserName
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        )
        # If persistent, store credentials in Windows Credential Manager
        if ($persistent) {
            # Extract only the server name from the UNC path (e.g., \\server)
            $target = $null
            if ($SharePath -match '^\\[^\\]+') {
                $target = $Matches[0]
            } else {
                $target = $SharePath
            }
            # Remove any existing credentials for this server
            cmdkey /delete:$target | Out-Null
            # Add credentials for the server
            cmdkey /add:$target /user:$user /pass:$plainPassword | Out-Null
        }
        net use "$DriveLetter`:" $SharePath /USER:$user $plainPassword $persistentFlag 2>&1 | Out-Null

        if ($LASTEXITCODE -eq 0) {
            if ($persistent) { Install-LogonScript -Silent:$Silent }
            if ($UseGUI) {
                $msg = "Mapped $DriveLetter -> $SharePath"
                if ($persistent) { $msg += " (persistent)" }
                [System.Windows.Forms.MessageBox]::Show(
                    $msg,
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
            elseif (-not $Silent) {
                Write-Host "Drive $DriveLetter mapped to $SharePath." -ForegroundColor Green
            }
            Write-ActionLog "Mapped $DriveLetter -> $SharePath (Persistent: $persistent)"
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
            Write-ActionLog "Failed mapping $DriveLetter -> $SharePath"
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
        Write-ActionLog "Error during mapping: $_"
    }
}

function Disconnect-NetworkShare {
    param (
        [string]$DriveLetter,
        [switch]$Silent
    )
    try {
        # Prefer multi-share preference; fallback to legacy
        $persistent = $false
        $sharePath = $null
        $multiCfg = Import-AllShares
        if ($multiCfg -and $multiCfg.Preferences.PSObject.Properties["PersistentMapping"]) {
            $persistent = [bool]$multiCfg.Preferences.PersistentMapping
        } else {
            $cfg = Import-ShareConfig
            if ($cfg -and $cfg.Preferences.PSObject.Properties["PersistentMapping"]) {
                $persistent = [bool]$cfg.Preferences.PersistentMapping
                $sharePath = $cfg.SharePath
            }
        }
        if (Test-Path "$DriveLetter`:") {
            net use "$DriveLetter`:" /DELETE /Y 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                # If persistent, remove credentials from Credential Manager
                if ($persistent -and $sharePath) {
                    # Extract only the server name from the UNC path (e.g., \\server)
                    $target = $null
                    if ($sharePath -match '^\\[^\\]+') {
                        $target = $Matches[0]
                    } else {
                        $target = $sharePath
                    }
                    cmdkey /delete:$target 2>&1 | Out-Null
                }
                # Regenerate or remove logon script based on current preference
                if ($persistent) { Install-LogonScript -Silent:$Silent } else { Remove-LogonScript -Silent:$Silent }
                if ($UseGUI) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Drive $DriveLetter unmapped.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                }
                elseif (-not $Silent) {
                    Write-Host "Drive $DriveLetter unmapped." -ForegroundColor Green
                }
                Write-ActionLog "Unmapped $DriveLetter"
            }
            else {
                if ($UseGUI) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to unmap drive.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
                else {
                    Write-Host "Failed to unmap drive." -ForegroundColor Red
                }
                Write-ActionLog "Failed unmapping $DriveLetter"
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
        Write-ActionLog "Error during unmapping: $_"
    }
}

function Invoke-LogFileOpen {
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
        Write-ActionLog "Opened log file"
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
        Write-ActionLog "Failed to open log file: $_"
    }
}

#endregion

#region First-Run Configuration

function Initialize-Config-CLI {
    Clear-Host
    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "  Welcome to Share Manager v$version" -ForegroundColor Cyan
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "  by $author" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  This appears to be your first time running Share Manager." -ForegroundColor Gray
    Write-Host "  Let's set up your preferences and add your first network share!" -ForegroundColor Gray
    Write-Host ""
    
    # First, set up preferences
    Write-Host "  ======[ PREFERENCES ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $preferredMode = "Prompt"
    Write-Host "  Startup Mode:" -ForegroundColor White
    Write-Host "    1) CLI  - Text-based interface (current)" -ForegroundColor Gray
    Write-Host "    2) GUI  - Graphical interface" -ForegroundColor Gray
    Write-Host "    3) Prompt - Ask each time" -ForegroundColor Gray
    Write-Host ""
    do {
        $m = Read-Host "  Choose default mode (1-3) [3]"
        if ($m -eq "") { $preferredMode = "Prompt"; break }
        if ($m -match '^[123]$') {
            switch ($m) {
                "1" { $preferredMode = "CLI" }
                "2" { $preferredMode = "GUI" }
                "3" { $preferredMode = "Prompt" }
            }
            break
        }
        Write-Host "  Enter 1, 2, or 3." -ForegroundColor Yellow
    } while ($true)
    
    Write-Host ""
    $persistentMapping = $false
    do {
        $yn = Read-Host "  Reconnect shares automatically at logon? (Y/N) [Y]"
        if ($yn -eq "" -or $yn -match '^[Yy]$') { $persistentMapping = $true; break }
        if ($yn -match '^[Nn]$') { $persistentMapping = $false; break }
        Write-Host "  Enter Y or N." -ForegroundColor Yellow
    } while ($true)
    
    # Save initial preferences
    $config = Import-AllShares
    $config.Preferences.PreferredMode = $preferredMode
    $config.Preferences.PersistentMapping = $persistentMapping
    Save-AllShares -Config $config | Out-Null
    
    Write-Host ""
    Write-Host "  [OK] Preferences saved!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Press any key to add your first share..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    # Now add first share using the standard Add-NewShareCli function
    Add-NewShareCli
    
    Write-Host ""
    Write-Host "  [OK] Setup complete! You're ready to use Share Manager." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Initialize-Config-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic

    # Welcome message
    $result = [System.Windows.Forms.MessageBox]::Show(
        "Welcome to Share Manager v$version!`n`nThis wizard will help you:`n`n1. Configure your preferences`n2. Add your first network share`n3. Save credentials securely`n`nReady to begin?",
        "Share Manager v$version - First Time Setup",
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    if ($result -ne 'OK') { return }
    
    # Step 1: Preferences
    $dummyPrefs = [PSCustomObject]@{
        UnmapOldMapping   = $false
        PreferredMode     = "Prompt"
        PersistentMapping = $true
    }
    $prefValues = Show-PreferencesForm -CurrentPrefs $dummyPrefs -IsInitial $true
    if ($null -eq $prefValues) { return }
    
    # Save preferences first
    $config = Import-AllShares
    $config.Preferences.PreferredMode = $prefValues.PreferredMode
    $config.Preferences.PersistentMapping = $prefValues.PersistentMapping
    $config.Preferences.UnmapOldMapping = $prefValues.UnmapOldMapping
    Save-AllShares -Config $config | Out-Null
    
    # Step 2: Add first share
    [System.Windows.Forms.MessageBox]::Show(
        "Now let's add your first network share.",
        "Share Manager v$version - Add Share",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    Show-AddShareDialog
    
    # Add Share dialog now handles credential prompting and connection offer
    # Just show final completion message
    [System.Windows.Forms.MessageBox]::Show(
        "Setup complete!`n`nYou're all set to use Share Manager.`n`nYou can:`n- Add more shares`n- Connect/disconnect shares`n- Manage credentials`n- Configure settings`n`nEnjoy!",
        "Share Manager v$version - Ready",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
}

#endregion

#region Credential GUI Form

function Show-CredentialForm {
    param(
        [string]$Username = "",
        [string]$Message = "Enter credentials"
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Message
    $form.Width = 350
    $form.Height = 220
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = "Username:"
    $lblUser.Left = 20
    $lblUser.Top = 20
    $lblUser.Width = 80
    $form.Controls.Add($lblUser)

    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Left = 110
    $txtUser.Top = 18
    $txtUser.Width = 200
    $txtUser.Text = $Username
    $form.Controls.Add($txtUser)

    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = "Password:"
    $lblPass.Left = 20
    $lblPass.Top = 60
    $lblPass.Width = 80
    $form.Controls.Add($lblPass)

    $txtPass = New-Object System.Windows.Forms.TextBox
    $txtPass.Left = 110
    $txtPass.Top = 58
    $txtPass.Width = 200
    $txtPass.UseSystemPasswordChar = $true
    $form.Controls.Add($txtPass)

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.Left = 60
    $btnOK.Top = 110
    $btnOK.Width = 80
    $okHandler = {
        if ([string]::IsNullOrWhiteSpace($txtUser.Text) -or [string]::IsNullOrWhiteSpace($txtPass.Text)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Username and password cannot be blank.",
                $form.Text,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }
        $form.Tag = @($txtUser.Text, $txtPass.Text)
        $form.Close()
    }
    $btnOK.Add_Click($okHandler)
    $form.Controls.Add($btnOK)

    # Add Ctrl+A and Enter key support
    Add-CtrlASupport -TextBox $txtUser -NextControl $txtPass
    Add-CtrlASupport -TextBox $txtPass -NextControl $btnOK

    # Pressing Enter in password box triggers OK (legacy handler, now handled by Add-CtrlASupport)
    $txtPass.Add_KeyDown({
        if ($_.KeyCode -eq 'Enter') {
            $btnOK.PerformClick()
        }
    })

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Left = 180
    $btnCancel.Top = 110
    $btnCancel.Width = 80
    $btnCancel.Add_Click({ $form.Tag = $null; $form.Close() })
    $form.Controls.Add($btnCancel)

    [void]$form.ShowDialog()
    if ($null -ne $form.Tag) {
        $user = $form.Tag[0]
        $pass = $form.Tag[1]
        $secure = ConvertTo-SecureString $pass -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential($user, $secure)
    } else {
        return $null
    }
}

#endregion

#region CLI Interface
function Start-CliMode {
    # Migrate legacy config if needed
    Convert-LegacyConfig
    
    do {
        Show-CLI-Menu
        Write-Host "  Enter your choice: " -NoNewline -ForegroundColor White
        $choice = Read-Host
        $choice = $choice.Trim().ToUpper()
        
        Write-Host ""
        
    # Auto-continue actions that don't need user confirmation
    $autoContinue = @("L","1","2","C","D","N")
        
        switch ($choice) {
            # Quick Actions
            "C" { 
                # Check if any shares are disconnected
                $shares = Get-ShareConfiguration | Where-Object { $_.Enabled }
                $hasDisconnected = $false
                foreach ($share in $shares) {
                    if (-not (Test-ShareConnection -DriveLetter $share.DriveLetter)) {
                        $hasDisconnected = $true
                        break
                    }
                }
                if ($hasDisconnected) {
                    Connect-AllSharesCli
                } else {
                    Write-Host "  All shares are already connected." -ForegroundColor DarkGray
                    Start-Sleep -Seconds 1
                }
            }
            "D" { 
                # Check if any shares are connected
                $shares = Get-ShareConfiguration
                $hasConnected = $false
                foreach ($share in $shares) {
                    if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                        $hasConnected = $true
                        break
                    }
                }
                if ($hasConnected) {
                    Disconnect-AllSharesCli
                } else {
                    Write-Host "  No shares are currently connected." -ForegroundColor DarkGray
                    Start-Sleep -Seconds 1
                }
            }
            "N" { 
                # Check if any shares are connected or can be connected
                $shares = Get-ShareConfiguration | Where-Object { $_.Enabled }
                if ($shares.Count -gt 0) {
                        Reset-AllSharesCli
                } else {
                    Write-Host "  No enabled shares configured." -ForegroundColor DarkGray
                    Start-Sleep -Seconds 1
                }
            }
            
            # Manage Shares
            "1" { Add-NewShareCli }
            "2" { Show-ManageSharesMenu }
            "3" { 
                Show-ShareStatusCli
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            
            # Settings & Tools
            "P" { Set-CliPreferences }
            "K" { Update-CliCredentialsMenu }
            "B" { Import-ExportConfigCli }
            "L" { Invoke-LogFileOpen; Start-Sleep -Seconds 1 }
            
            # Navigation
            "G" {
                Write-Host "  Switching to GUI mode..." -ForegroundColor Cyan
                Start-Process -FilePath "powershell.exe" `
                    -ArgumentList "-ExecutionPolicy Bypass -STA -File `"$PSCommandPath`" -StartupMode GUI" `
                    -WindowStyle Normal
                exit
            }
            "Q" { 
                exit 
            }
            
            default { 
                Write-Host "  Invalid choice" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
        
        # Only pause for actions that need it (skip for actions with their own pause)
        if ($choice -notin @("Q", "G", "3", "B") + $autoContinue) { 
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } while ($true)
}

function Show-ManageSharesMenu {
    <#
    .SYNOPSIS
        Shows submenu for managing existing shares
    #>
    do {
        Clear-Host
        Write-Host ""
        Write-Host "  ======[ MANAGE SHARES ]======" -ForegroundColor Cyan
        
        $shares = Get-ShareConfiguration
        
        if ($shares.Count -eq 0) {
            Write-Host "  No shares configured." -ForegroundColor Yellow
            return
        }
        
        Write-Host ""
        # Show shares with quick actions
        $index = 1
        foreach ($share in $shares) {
            $connected = Test-ShareConnection -DriveLetter $share.DriveLetter
            $icon = if ($connected) { "[*]" } else { "[ ]" }
            $color = if ($connected) { "Green" } else { "Red" }
            
            Write-Host "  $icon $index. " -ForegroundColor $color -NoNewline
            Write-Host "$($share.Name) " -ForegroundColor $(if ($connected) { "White" } else { "Gray" }) -NoNewline
            Write-Host "[$($share.DriveLetter):]" -ForegroundColor DarkGray
            Write-Host "      $($share.SharePath)" -ForegroundColor DarkGray
            
            $index++
        }
        
        Write-Host ""
        Write-Host "  1-$($shares.Count)" -NoNewline -ForegroundColor White
        Write-Host " - Toggle Connect/Disconnect  " -NoNewline -ForegroundColor Gray
        Write-Host "E" -NoNewline -ForegroundColor White
        Write-Host " - Edit  " -NoNewline -ForegroundColor Gray
        Write-Host "R" -NoNewline -ForegroundColor White
        Write-Host " - Remove  " -NoNewline -ForegroundColor Gray
        Write-Host "B" -NoNewline -ForegroundColor White
        Write-Host " - Back" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  > " -NoNewline -ForegroundColor White
        $choice = Read-Host
        $choice = $choice.Trim().ToUpper()
        
        # Check if numeric choice
        $num = 0
        if ([int]::TryParse($choice, [ref]$num) -and $num -ge 1 -and $num -le $shares.Count) {
            $share = $shares[$num - 1]
            $connected = Test-ShareConnection -DriveLetter $share.DriveLetter
            
            if ($connected) {
                Write-Host "  Disconnecting..." -ForegroundColor Yellow
                Disconnect-NetworkShare -DriveLetter $share.DriveLetter
                Start-Sleep -Milliseconds 500
            } else {
                Write-Host "  Connecting..." -ForegroundColor Green
                $cred = Get-CredentialForShare -Username $share.Username
                
                if (-not $cred) {
                    Write-Host "  No saved credentials" -ForegroundColor Yellow
                    $password = Read-Password "  Password: "
                    if ($password.Length -gt 0) {
                        $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
                        Write-Host "  Save credentials? (Y/N): " -NoNewline
                        $saveIt = Read-Host
                        if ($saveIt -match '^[Yy]$') {
                            Save-Credential -Credential $cred
                        }
                    }
                }
                
                if ($cred) {
                    Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred
                    
                    # Update last connected
                    $config = Import-AllShares
                    $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                    if ($shareObj) {
                        $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Save-AllShares -Config $config | Out-Null
                    }
                }
                Start-Sleep -Milliseconds 800
            }
        }
        elseif ($choice -eq "E") {
            Edit-ShareCli
        }
        elseif ($choice -eq "R") {
            Remove-ShareCli
        }
        elseif ($choice -eq "B") {
            return
        }
        else {
            Write-Host "  Invalid choice" -ForegroundColor Red
            Start-Sleep -Milliseconds 800
        }
        
    } while ($true)
}

function Edit-ShareCli {
    <#
    .SYNOPSIS
        Edit an existing share
    #>
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ EDIT SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration
    if ($shares.Count -eq 0) {
        Write-Host "  No shares to edit" -ForegroundColor Yellow
        return
    }
    
    for ($i = 0; $i -lt $shares.Count; $i++) {
        Write-Host "  $($i + 1). $($shares[$i].Name)"
    }
    
    Write-Host ""
    Write-Host "  Select share (or 0 to cancel): " -NoNewline -ForegroundColor White
    $choice = Read-Host
    $num = 0
    
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $shares.Count) {
        $share = $shares[$num - 1]
        
        Write-Host ""
        Write-Host "  Editing: $($share.Name)" -ForegroundColor Cyan
        Write-Host "  (Leave blank to keep current)" -ForegroundColor DarkGray
        Write-Host ""
        
        Write-Host "  Name [$($share.Name)]: " -NoNewline
        $newName = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newName)) {
            $share.Name = $newName
        }
        
        Write-Host "  Description [$($share.Description)]: " -NoNewline
        $newDesc = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newDesc)) {
            $share.Description = $newDesc
        }
        
        Write-Host "  Enabled [$($share.Enabled)] (Y/N/blank): " -NoNewline
        $toggle = Read-Host
        if ($toggle -match '^[Yy]$') {
            $share.Enabled = $true
        } elseif ($toggle -match '^[Nn]$') {
            $share.Enabled = $false
        }
        
        # Save changes
        $config = Import-AllShares
        $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
        if ($shareObj) {
            $shareObj.Name = $share.Name
            $shareObj.Description = $share.Description
            $shareObj.Enabled = $share.Enabled
            
            if (Save-AllShares -Config $config) {
                Write-Host ""
                Write-Host "  [OK] Share updated!" -ForegroundColor Green
            } else {
                Write-Host ""
                Write-Host "  [X] Failed to save" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  Cancelled" -ForegroundColor Gray
    }
}

function Show-AllSharesCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ ALL SHARES ]======" -ForegroundColor Cyan
    
    $shares = Get-ShareConfiguration
    
    if ($shares.Count -eq 0) {
        Write-Host "  No shares configured. Use option 1 to add." -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    foreach ($share in $shares) {
        $connected = Test-ShareConnection -DriveLetter $share.DriveLetter
        $icon = if ($connected) { "[*]" } else { "[ ]" }
        $statusColor = if ($connected) { "Green" } else { "Red" }
        
        Write-Host "  $icon " -ForegroundColor $statusColor -NoNewline
        Write-Host "$($share.Name) " -ForegroundColor $(if ($connected) { "White" } else { "Gray" }) -NoNewline
        Write-Host "[$($share.DriveLetter):]" -ForegroundColor DarkGray
        Write-Host "      $($share.SharePath)" -ForegroundColor DarkGray
        if (-not [string]::IsNullOrWhiteSpace($share.Description)) {
            Write-Host "      $($share.Description)" -ForegroundColor DarkGray
        }
        if (-not $share.Enabled) {
            Write-Host "      [DISABLED]" -ForegroundColor Red
        }
    }
}

function Add-NewShareCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ ADD NEW SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    # Step 1: Name
    Write-Host "  Share Name" -ForegroundColor White
    Write-Host "  (A friendly name for this share, e.g., 'Office Files')" -ForegroundColor DarkGray
    Write-Host "  > " -ForegroundColor Cyan -NoNewline
    do {
        $name = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($name)) { break }
        Write-Host "  Name cannot be empty. Try again: " -ForegroundColor Yellow -NoNewline
    } while ($true)
    
    Write-Host ""
    
    # Step 2: Path
    Write-Host "  Network Path" -ForegroundColor White
    Write-Host "  (UNC path like \\192.168.1.100\share or \\server\folder)" -ForegroundColor DarkGray
    Write-Host "  > " -ForegroundColor Cyan -NoNewline
    do {
        $sharePath = Read-Host
        if ($sharePath -match '^\\\\[^\\]+\\') { break }
        Write-Host "  Invalid UNC path. Must start with \\ - Try again: " -ForegroundColor Yellow -NoNewline
    } while ($true)
    
    Write-Host ""
    
    # Step 3: Drive Letter
    $existingShares = Get-ShareConfiguration
    $usedLetters = $existingShares | ForEach-Object { $_.DriveLetter }
    $availableLetters = ('Z','Y','X','W','V','U','T','S','R','Q','P','O','N') | Where-Object { $_ -notin $usedLetters }
    
    if ($availableLetters.Count -eq 0) {
        Write-Host "  No drive letters available!" -ForegroundColor Red
        return
    }
    
    Write-Host "  Drive Letter" -ForegroundColor White
    Write-Host "  (The drive letter to map this share to, press Enter for " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($availableLetters[0])" -NoNewline -ForegroundColor Green
    Write-Host ")" -ForegroundColor DarkGray
    Write-Host "  > " -ForegroundColor Cyan -NoNewline
    do {
        $driveLetter = Read-Host
        $driveLetter = $driveLetter.ToUpper().Trim()
        if ([string]::IsNullOrWhiteSpace($driveLetter)) { $driveLetter = $availableLetters[0] }
        if ($driveLetter.Length -eq 1 -and $driveLetter -match '^[A-Z]$' -and $driveLetter -notin $usedLetters) { break }
        Write-Host "  Invalid or in-use. Choose another: " -ForegroundColor Yellow -NoNewline
    } while ($true)
    
    Write-Host ""
    
    # Step 4: Username
    Write-Host "  Username" -ForegroundColor White
    Write-Host "  (Username for authentication, e.g., DOMAIN\user or user)" -ForegroundColor DarkGray
    Write-Host "  > " -ForegroundColor Cyan -NoNewline
    do {
        $username = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($username)) { break }
        Write-Host "  Username required. Try again: " -ForegroundColor Yellow -NoNewline
    } while ($true)
    
    Write-Host ""
    
    # Optional: Description
    Write-Host "  Description (optional)" -ForegroundColor White
    Write-Host "  (Additional notes about this share)" -ForegroundColor DarkGray
    Write-Host "  > " -ForegroundColor Cyan -NoNewline
    $description = Read-Host
    
    Write-Host ""
    
    # Add the share
    $result = Add-ShareConfiguration -Name $name -SharePath $sharePath -DriveLetter $driveLetter -Username $username -Description $description
    
    if ($result) {
        Write-Host "  [OK] Share '$name' added successfully!" -ForegroundColor Green
        Write-Host ""
        
        # Check if credentials exist for this user
        $existingCred = Get-CredentialForShare -Username $username
        $credential = $null
        
        if (-not $existingCred) {
            # No credentials exist - prompt to save them
            Write-Host "  No credentials found for user: " -NoNewline -ForegroundColor Yellow
            Write-Host "$username" -ForegroundColor White
            Write-Host "  Would you like to save credentials now? (Y/N) " -ForegroundColor Yellow -NoNewline
            $saveCreds = Read-Host
            
            if ($saveCreds -match '^[Yy]$') {
                $password = Read-Password "  Enter password: "
                if ($password.Length -gt 0) {
                    $credential = New-Object System.Management.Automation.PSCredential($username, $password)
                    Save-Credential -Credential $credential
                    Write-Host "  [OK] Credentials saved" -ForegroundColor Green
                }
            }
        } else {
            Write-Host "  Using existing credentials for: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$username" -ForegroundColor White
            $credential = $existingCred
        }
        
        # Ask if user wants to connect now
        Write-Host ""
        Write-Host "  Connect now? (Y/N) " -ForegroundColor Yellow -NoNewline
        $connectNow = Read-Host
        
        if ($connectNow -match '^[Yy]$') {
            Write-Host ""
            
            # If still no credential, prompt one more time
            if (-not $credential) {
                Write-Host "  Credentials required to connect." -ForegroundColor Yellow
                $password = Read-Password "  Enter password for ${username}: "
                if ($password.Length -gt 0) {
                    $credential = New-Object System.Management.Automation.PSCredential($username, $password)
                }
            }
            
            if ($credential) {
                Write-Host "  Connecting..." -ForegroundColor Cyan
                Connect-NetworkShare -SharePath $sharePath -DriveLetter $driveLetter -Credential $credential
                
                # Update last connected
                $config = Import-AllShares
                $shareId = ($config.Shares | Where-Object { $_.DriveLetter -eq $driveLetter }).Id
                if ($shareId) {
                    $shareObj = $config.Shares | Where-Object { $_.Id -eq $shareId }
                    if ($shareObj) {
                        $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Save-AllShares -Config $config | Out-Null
                    }
                }
            } else {
                Write-Host "  [X] No credentials provided - cannot connect" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [X] Failed to add share" -ForegroundColor Red
    }
}

function Remove-ShareCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ REMOVE SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration
    if ($shares.Count -eq 0) {
        Write-Host "  No shares configured." -ForegroundColor Yellow
        return
    }
    
    # Show numbered list
    for ($i = 0; $i -lt $shares.Count; $i++) {
        Write-Host "  $($i + 1). " -NoNewline -ForegroundColor White
        Write-Host "$($shares[$i].Name)" -NoNewline
        Write-Host " [$($shares[$i].DriveLetter):]" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "  Select share to remove (or 0 to cancel): " -NoNewline -ForegroundColor White
    $choice = Read-Host
    $num = 0
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $shares.Count) {
        $share = $shares[$num - 1]
        
        Write-Host ""
        Write-Host "  Remove '$($share.Name)'? This cannot be undone." -ForegroundColor Yellow
        Write-Host "  Confirm (Y/N): " -NoNewline
        $confirm = Read-Host
        
        if ($confirm -match '^[Yy]$') {
            # Disconnect if connected
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                Write-Host "  Disconnecting..." -ForegroundColor Yellow
                Disconnect-NetworkShare -DriveLetter $share.DriveLetter
            }
            
            if (Remove-ShareConfiguration -ShareId $share.Id) {
                Write-Host ""
                Write-Host "  [OK] Share removed!" -ForegroundColor Green
            } else {
                Write-Host ""
                Write-Host "  [X] Failed to remove" -ForegroundColor Red
            }
        } else {
            Write-Host ""
            Write-Host "  Cancelled" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Cancelled" -ForegroundColor Gray
    }
}

function Connect-ShareCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ CONNECT SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration | Where-Object { $_.Enabled }
    if ($shares.Count -eq 0) {
        Write-Host "  No enabled shares configured." -ForegroundColor Yellow
        return
    }
    
    # Show only disconnected shares
    $disconnected = $shares | Where-Object { -not (Test-ShareConnection -DriveLetter $_.DriveLetter) }
    if ($disconnected.Count -eq 0) {
        Write-Host "  [OK] All enabled shares are already connected!" -ForegroundColor Green
        return
    }
    
    Write-Host "  Disconnected Shares:" -ForegroundColor Gray
    Write-Host ""
    for ($i = 0; $i -lt $disconnected.Count; $i++) {
        Write-Host "  $($i + 1). " -NoNewline -ForegroundColor White
        Write-Host "$($disconnected[$i].Name)" -NoNewline
        Write-Host " [$($disconnected[$i].DriveLetter):]" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "  Enter number to connect (or 0 to cancel): " -NoNewline -ForegroundColor White
    $choice = Read-Host
    $num = 0
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $disconnected.Count) {
        $share = $disconnected[$num - 1]
        
        Write-Host ""
        Write-Host "  Connecting to '$($share.Name)'..." -ForegroundColor Cyan
        
        $cred = Get-CredentialForShare -Username $share.Username
        
        if (-not $cred) {
            Write-Host "  [!] No saved credentials found" -ForegroundColor Yellow
            $password = Read-Password "  Enter password: "
            if ($password.Length -gt 0) {
                $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
                
                Write-Host "  Save these credentials? (Y/N): " -NoNewline
                $save = Read-Host
                if ($save -match '^[Yy]$') {
                    Save-Credential -Credential $cred
                }
            } else {
                Write-Host "  [X] Connection cancelled" -ForegroundColor Red
                return
            }
        }
        
        Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred
        
        # Update last connected
        $config = Import-AllShares
        $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
        if ($shareObj) {
            $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Save-AllShares -Config $config | Out-Null
        }
    }
}

function Disconnect-ShareCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ DISCONNECT SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration
    $connected = $shares | Where-Object { Test-ShareConnection -DriveLetter $_.DriveLetter }
    
    if ($connected.Count -eq 0) {
        Write-Host "  No shares are currently connected." -ForegroundColor Yellow
        return
    }
    
    Write-Host "  Connected Shares:" -ForegroundColor Gray
    Write-Host ""
    for ($i = 0; $i -lt $connected.Count; $i++) {
        Write-Host "  $($i + 1). " -NoNewline -ForegroundColor White
        Write-Host "$($connected[$i].Name)" -NoNewline
        Write-Host " [$($connected[$i].DriveLetter):]" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "  Enter number to disconnect (or 0 to cancel): " -NoNewline -ForegroundColor White
    $choice = Read-Host
    $num = 0
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $connected.Count) {
        $share = $connected[$num - 1]
        Write-Host ""
        Write-Host "  Disconnecting '$($share.Name)'..." -ForegroundColor Yellow
        Disconnect-NetworkShare -DriveLetter $share.DriveLetter
    }
}

function Connect-AllSharesCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ CONNECT ALL ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration | Where-Object { $_.Enabled }
    if ($shares.Count -eq 0) {
        Write-Host "  No enabled shares configured." -ForegroundColor Yellow
        return
    }
    
    $success = 0
    $failed = 0
    $skipped = 0
    
    foreach ($share in $shares) {
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            Write-Host "  [ ] " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($share.Name)" -NoNewline -ForegroundColor Gray
            Write-Host " (already connected)" -ForegroundColor DarkGray
            $skipped++
            continue
        }
        
        Write-Host "  [*] " -NoNewline -ForegroundColor Cyan
        Write-Host "$($share.Name)" -NoNewline
        Write-Host "... " -NoNewline -ForegroundColor DarkGray
        
        $cred = Get-CredentialForShare -Username $share.Username
        if (-not $cred) {
            Write-Host "[X] No credentials" -ForegroundColor Yellow
            $failed++
            continue
        }
        
        try {
            Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                Write-Host "[OK]" -ForegroundColor Green
                $success++
                
                # Update last connected
                $config = Import-AllShares
                $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                if ($shareObj) {
                    $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Save-AllShares -Config $config | Out-Null
                }
            } else {
                Write-Host "[X]" -ForegroundColor Red
                $failed++
            }
        }
        catch {
            Write-Host "[X]" -ForegroundColor Red
            $failed++
        }
    }
    
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Results: " -NoNewline
    Write-Host "$success connected" -NoNewline -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host ", " -NoNewline
        Write-Host "$failed failed" -NoNewline -ForegroundColor Red
    }
    if ($skipped -gt 0) {
        Write-Host ", " -NoNewline
        Write-Host "$skipped skipped" -NoNewline -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host ""
    Write-Host "  Press any key..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Reset-AllSharesCli {
    <#
    .SYNOPSIS
        Disconnects and reconnects all enabled shares (forces refresh)
    #>
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ RECONNECT ALL SHARES ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration | Where-Object { $_.Enabled }
    if ($shares.Count -eq 0) {
        Write-Host "  No enabled shares configured." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
        Write-Host "  This will disconnect and reset " -NoNewline -ForegroundColor Yellow
    Write-Host "$($shares.Count)" -NoNewline -ForegroundColor White
    Write-Host " share(s)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Continue? (Y/N): " -NoNewline
    $confirm = Read-Host
    
    if ($confirm -notmatch '^[Yy]$') {
        Write-Host "  Cancelled" -ForegroundColor Gray
        return
    }
    
    Write-Host ""
    Write-Host "  Disconnecting..." -ForegroundColor Yellow
    $disconnected = 0
    foreach ($share in $shares) {
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent
            $disconnected++
        }
    }
    
    Write-Host "  Disconnected $disconnected share(s)" -ForegroundColor DarkGray
    Write-Host ""
        Write-Host "  Reconnecting shares..." -ForegroundColor Green
    
    $success = 0
    $failed = 0
    
    foreach ($share in $shares) {
        Write-Host "  [*] " -NoNewline -ForegroundColor Cyan
        Write-Host "$($share.Name)" -NoNewline
        Write-Host "... " -NoNewline -ForegroundColor DarkGray
        
        $cred = Get-CredentialForShare -Username $share.Username
        if (-not $cred) {
            Write-Host "[X] No credentials" -ForegroundColor Yellow
            $failed++
            continue
        }
        
        try {
            Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                Write-Host "[OK]" -ForegroundColor Green
                $success++
                
                # Update last connected
                $config = Import-AllShares
                $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                if ($shareObj) {
                    $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Save-AllShares -Config $config | Out-Null
                }
            } else {
                Write-Host "[X]" -ForegroundColor Red
                $failed++
            }
        }
        catch {
            Write-Host "[X]" -ForegroundColor Red
            $failed++
        }
    }
    
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Results: " -NoNewline
        Write-Host "$success reset" -NoNewline -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host ", " -NoNewline
        Write-Host "$failed failed" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host ""
    Write-Host "  Press any key..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Disconnect-AllSharesCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ DISCONNECT ALL ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration
    
        # Build array of connected shares
        $connected = @()
        foreach ($share in $shares) {
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                $connected += $share
            }
        }
    
    if ($connected.Count -eq 0) {
        Write-Host "  No shares are currently connected." -ForegroundColor Yellow
        return
    }
    
    Write-Host "  This will disconnect " -NoNewline -ForegroundColor Yellow
    Write-Host "$($connected.Count)" -NoNewline -ForegroundColor White
    Write-Host " share(s)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Are you sure? (Y/N): " -NoNewline
    $confirm = Read-Host
    
    if ($confirm -notmatch '^[Yy]$') {
        Write-Host "  Cancelled" -ForegroundColor Gray
        return
    }
    
    Write-Host ""
    $disconnected = 0
    foreach ($share in $connected) {
        Write-Host "  [*] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($share.Name)" -NoNewline
        Write-Host "... " -NoNewline -ForegroundColor DarkGray
        Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent
        Write-Host "[OK]" -ForegroundColor Green
        $disconnected++
    }
    
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Disconnected " -NoNewline
    Write-Host "$disconnected" -NoNewline -ForegroundColor Yellow
    Write-Host " share(s)" -ForegroundColor Gray
    Write-Host ""
    Write-Host ""
    Write-Host "  Press any key..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-ShareStatusCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ STATUS ]======" -ForegroundColor Cyan
    
    $shares = Get-ShareConfiguration
    if ($shares.Count -eq 0) {
        Write-Host "  No shares configured." -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    foreach ($share in $shares) {
        $status = Get-DetailedShareStatus -ShareId $share.Id
        
        $icon = if ($status.IsConnected) { "[*]" } else { "[ ]" }
        $iconColor = if ($status.IsConnected) { "Green" } else { "Red" }
        
        Write-Host "  $icon " -NoNewline -ForegroundColor $iconColor
        Write-Host "$($share.Name) " -ForegroundColor White -NoNewline
        Write-Host "[$($share.DriveLetter):]" -ForegroundColor DarkGray
        
        $statusLine = @()
        if ($status.IsConnected) { $statusLine += "[OK] Connected" } else { $statusLine += "[X] Disconnected" }
        if (-not $status.HostOnline) { $statusLine += "[X] Host Offline" }
        if (-not $status.HasCredentials) { $statusLine += "[!] No Creds" }
        if ($status.Issue -ne "None") { $statusLine += "[!] $($status.Issue)" }
        
        if ($statusLine.Count -gt 0) {
            Write-Host "      $($statusLine -join ' | ')" -ForegroundColor $(if ($status.IsConnected) { "DarkGray" } else { "Yellow" })
        }
        Write-Host "      $($share.SharePath)" -ForegroundColor DarkGray
    }
}

function Import-ExportConfigCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ BACKUP & RESTORE ]======" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. " -NoNewline
    Write-Host "Export Configuration" -ForegroundColor White -NoNewline
    Write-Host " (Create backup)" -ForegroundColor DarkGray
    Write-Host "  2. " -NoNewline
    Write-Host "Import & Replace" -ForegroundColor White -NoNewline
    Write-Host " (Overwrite current)" -ForegroundColor DarkGray
    Write-Host "  3. " -NoNewline
    Write-Host "Import & Merge" -ForegroundColor White -NoNewline
    Write-Host " (Add to current)" -ForegroundColor DarkGray
    Write-Host "  4. " -NoNewline
    Write-Host "Back to Main Menu" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Enter choice: " -NoNewline -ForegroundColor White
    $choice = Read-Host
    
    Write-Host ""
    
    switch ($choice) {
        "1" {
            Write-Host "  +- EXPORT CONFIGURATION -----------------+" -ForegroundColor Cyan
            Write-Host ""
            
            $defaultPath = Join-Path $env:USERPROFILE "Desktop\ShareManager_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            Write-Host "  Default location:" -ForegroundColor DarkGray
            Write-Host "  $defaultPath" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Enter path (or press Enter for default): " -NoNewline
            $exportPath = Read-Host
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = $defaultPath
            }
            
            Write-Host ""
            Write-Host "  Exporting..." -ForegroundColor Cyan
            
            if (Export-ShareConfiguration -ExportPath $exportPath) {
                Write-Host ""
                Write-Host "  [OK] Configuration exported successfully!" -ForegroundColor Green
                Write-Host "  Location: " -NoNewline -ForegroundColor DarkGray
                Write-Host "$exportPath" -ForegroundColor White
            } else {
                Write-Host ""
                Write-Host "  [X] Export failed. Check log for details." -ForegroundColor Red
            }
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" {
            Write-Host "  +- IMPORT & REPLACE ---------------------+" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [!] WARNING: This will DELETE all current shares" -ForegroundColor Yellow
            Write-Host "            and replace with the imported config." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Enter backup file path: " -NoNewline
            $importPath = Read-Host
            
            if (-not [string]::IsNullOrWhiteSpace($importPath)) {
                if (-not (Test-Path $importPath)) {
                    Write-Host ""
                    Write-Host "  [X] File not found: $importPath" -ForegroundColor Red
                    return
                }
                
                Write-Host ""
                Write-Host "  Type 'REPLACE' to confirm: " -NoNewline
                $confirm = Read-Host
                
                if ($confirm -eq "REPLACE") {
                    Write-Host ""
                    Write-Host "  Importing..." -ForegroundColor Cyan
                    
                    $result = Import-ShareConfiguration -ImportPath $importPath -Merge $false
                    
                    if ($result.Success) {
                        Write-Host ""
                        Write-Host "  [OK] Configuration replaced successfully!" -ForegroundColor Green
                        Write-Host "  Imported: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($result.Added)" -NoNewline -ForegroundColor White
                        Write-Host " share(s)" -ForegroundColor DarkGray
                    } else {
                        Write-Host ""
                        Write-Host "  [X] Import failed" -ForegroundColor Red
                    }
                } else {
                    Write-Host ""
                    Write-Host "  Cancelled" -ForegroundColor Gray
                }
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
        "3" {
            Write-Host "  +- IMPORT & MERGE -----------------------+" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  This will add shares from the backup file" -ForegroundColor Gray
            Write-Host "  to your current configuration." -ForegroundColor Gray
            Write-Host "  (Duplicates will be automatically skipped)" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Enter backup file path: " -NoNewline
            $importPath = Read-Host
            
            if (-not [string]::IsNullOrWhiteSpace($importPath)) {
                if (-not (Test-Path $importPath)) {
                    Write-Host ""
                    Write-Host "  [X] File not found: $importPath" -ForegroundColor Red
                    return
                }
                
                Write-Host ""
                Write-Host "  Merging..." -ForegroundColor Cyan
                
                $result = Import-ShareConfiguration -ImportPath $importPath -Merge $true
                
                if ($result.Success) {
                    Write-Host ""
                    Write-Host "  [OK] Configuration merged successfully!" -ForegroundColor Green
                    Write-Host "  Added: " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($result.Added)" -NoNewline -ForegroundColor White
                    Write-Host " share(s)" -ForegroundColor DarkGray
                    if ($result.Skipped -gt 0) {
                        Write-Host "  Skipped: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($result.Skipped)" -NoNewline -ForegroundColor Yellow
                        Write-Host " duplicate(s)" -ForegroundColor DarkGray
                    }
                } else {
                    Write-Host ""
                    Write-Host "  [X] Merge failed" -ForegroundColor Red
                }
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    }
}
function Show-CLI-Menu {
    Clear-Host
    
    # Show quick status summary
    $shares = @(Get-ShareConfiguration)
    $total = $shares.Count
    
    # Count connected shares properly
    $connected = 0
    foreach ($share in $shares) {
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            $connected++
        }
    }
    
    Write-Host ""
    Write-Host "  ======[ " -ForegroundColor Cyan -NoNewline
    Write-Host "SHARE MANAGER v$version" -ForegroundColor White -NoNewline
    Write-Host " ]======" -ForegroundColor Cyan
    Write-Host "  by $author" -ForegroundColor DarkGray
    Write-Host "  Status: " -NoNewline -ForegroundColor DarkGray
    
    if ($total -eq 0) {
        Write-Host "No shares configured" -ForegroundColor Yellow
    } else {
        Write-Host "$connected/$total" -NoNewline -ForegroundColor $(if ($connected -eq $total) { "Green" } elseif ($connected -eq 0) { "Red" } else { "Yellow" })
        Write-Host " connected" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    if ($total -eq 0) {
        Write-Host "  1" -NoNewline -ForegroundColor White
        Write-Host " - Add Your First Share" -ForegroundColor Gray
    } else {
        $disconnected = $total - $connected
        
        # Connect All - gray out if all connected
        if ($disconnected -gt 0) {
            Write-Host "  C" -NoNewline -ForegroundColor Green
            Write-Host " - Connect All (" -NoNewline -ForegroundColor Gray
            Write-Host "$disconnected" -NoNewline -ForegroundColor Yellow
            Write-Host " disconnected)" -ForegroundColor Gray
        } else {
            Write-Host "  C" -NoNewline -ForegroundColor DarkGray
            Write-Host " - Connect All " -NoNewline -ForegroundColor DarkGray
            Write-Host "(all connected)" -ForegroundColor DarkGray
        }
        
        # Disconnect All - gray out if none connected
        if ($connected -gt 0) {
            Write-Host "  D" -NoNewline -ForegroundColor Yellow
            Write-Host " - Disconnect All    " -NoNewline -ForegroundColor Gray
            Write-Host "N" -NoNewline -ForegroundColor Cyan
                Write-Host " - Reconnect All" -ForegroundColor Gray
        } else {
            Write-Host "  D" -NoNewline -ForegroundColor DarkGray
            Write-Host " - Disconnect All " -NoNewline -ForegroundColor DarkGray
            Write-Host "(none connected)    " -NoNewline -ForegroundColor DarkGray
            Write-Host "N" -NoNewline -ForegroundColor DarkGray
                Write-Host " - Reconnect All " -NoNewline -ForegroundColor DarkGray
            Write-Host "(none connected)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host ""
    Write-Host "  1" -NoNewline -ForegroundColor White
    Write-Host " - Add Share    " -NoNewline -ForegroundColor Gray
    Write-Host "2" -NoNewline -ForegroundColor White
    Write-Host " - Manage    " -NoNewline -ForegroundColor Gray
    Write-Host "   3" -NoNewline -ForegroundColor White
    Write-Host " - Status" -ForegroundColor Gray
    
    Write-Host "  P" -NoNewline -ForegroundColor White
    Write-Host " - Preferences  " -NoNewline -ForegroundColor Gray
    Write-Host "K" -NoNewline -ForegroundColor White
    Write-Host " - Credentials  " -NoNewline -ForegroundColor Gray
    Write-Host "B" -NoNewline -ForegroundColor White
    Write-Host " - Backup" -ForegroundColor Gray
    
    Write-Host "  L" -NoNewline -ForegroundColor White
    Write-Host " - Log File     " -NoNewline -ForegroundColor Gray
    Write-Host "G" -NoNewline -ForegroundColor Cyan
    Write-Host " - GUI Mode     " -NoNewline -ForegroundColor Gray
    Write-Host "Q" -NoNewline -ForegroundColor Red
    Write-Host " - Quit" -ForegroundColor Gray
    Write-Host ""
}

function Set-CliSettings {
    $cfg = Import-ShareConfig
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
        $newDriveLetter = Read-Host "New drive letter (A-Z), or Enter"
        if ($newDriveLetter -eq "") { break }
        if ($newDriveLetter -match '^[A-Za-z]$') {
            $cfg.DriveLetter = $newDriveLetter.ToUpper()
            break
        }
        else {
            Write-Host "Enter single letter A-Z, or blank." -ForegroundColor Yellow
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
        Disconnect-NetworkShare -DriveLetter $oldDrive
        Write-Host "Old drive $oldDrive unmapped due to letter change." -ForegroundColor Yellow
        Write-ActionLog "Unmapped old drive $oldDrive"
    }
}

function Set-CliPreferences {
    $config = Import-AllShares
    if (-not $config) { return }
    
    # Ensure preferences exist
    if (-not $config.Preferences) {
        $config.Preferences = [PSCustomObject]@{
            UnmapOldMapping = $false
            PreferredMode = "Prompt"
            PersistentMapping = $false
        }
    }
    $prefs = $config.Preferences

    while ($true) {
        Clear-Host
        Write-Host "=== Preferences v$version ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Auto-unmap on drive change: $($prefs.UnmapOldMapping)"
        Write-Host "2. Preferred startup mode    : $($prefs.PreferredMode)"
        Write-Host "3. Persistent mapping        : $($prefs.PersistentMapping)"
        Write-Host "4. Back"
        Write-Host ""
        $choice = Read-Host "Select (1-4)"
        switch ($choice) {
            "1" {
                do {
                    $yn = Read-Host "Auto-unmap on letter change? (Y/N)"
                    if ($yn -match '^[YyNn]$') { break }
                    Write-Host "Enter Y or N." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.UnmapOldMapping = $yn -match '^[Yy]$'
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "2" {
                Write-Host "Mode: 1) CLI  2) GUI  3) Prompt"
                do {
                    $m = Read-Host "Enter 1, 2, or 3"
                    if ($m -match '^[123]$') { break }
                    Write-Host "Enter 1-3." -ForegroundColor Yellow
                } while ($true)
                switch ($m) {
                    "1" { $config.Preferences.PreferredMode = "CLI" }
                    "2" { $config.Preferences.PreferredMode = "GUI" }
                    "3" { $config.Preferences.PreferredMode = "Prompt" }
                }
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "3" {
                do {
                    $yn = Read-Host "Enable persistent mapping (reconnect at logon)? (Y/N)"
                    if ($yn -match '^[YyNn]$') { break }
                    Write-Host "Enter Y or N." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.PersistentMapping = $yn -match '^[Yy]$'
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            default { return }
        }
    }
}

function Update-CliCredentialsMenu {
    Write-Host "=== Credentials Menu v$version ===" -ForegroundColor Cyan
    Write-Host "1. Add/Update Credentials"
    Write-Host "2. List Credentials"
    Write-Host "3. Remove Credential"
    Write-Host "4. Back"
    Write-Host ""
    $sub = Read-Host "Select (1-4)"
    switch ($sub) {
        "1" {
            # Prompt for username
            $username = Read-Host "Username"
            if ([string]::IsNullOrWhiteSpace($username)) {
                Write-Host "Username cannot be blank." -ForegroundColor Yellow
                return
            }
            $password = Read-Password "Enter password for ${username}: "
            if ($password.Length -gt 0) {
                $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                Save-Credential -Credential $cred
                Write-Host "Credential saved for user: $username" -ForegroundColor Green
            }
            else {
                Write-Host "Credential prompt cancelled; nothing saved." -ForegroundColor Yellow
            }
        }
        "2" {
            # List all credentials
            $creds = Get-AllCredentials
            if ($creds.Count -eq 0) {
                Write-Host "No credentials stored." -ForegroundColor Yellow
            } else {
                Write-Host "`nStored credentials:" -ForegroundColor Cyan
                foreach ($c in $creds) {
                    Write-Host "  - $($c.Username)" -ForegroundColor White
                }
                Write-Host ""
            }
        }
        "3" {
            # Remove credential
            $creds = Get-AllCredentials
            if ($creds.Count -eq 0) {
                Write-Host "No credentials to remove." -ForegroundColor Yellow
                return
            }
            Write-Host "`nAvailable credentials:" -ForegroundColor Cyan
            $i = 1
            foreach ($c in $creds) {
                Write-Host "  $i. $($c.Username)" -ForegroundColor White
                $i++
            }
            Write-Host ""
            $choice = Read-Host "Select credential to remove (1-$($creds.Count))"
            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $creds.Count) {
                $username = $creds[[int]$choice - 1].Username
                Remove-Credential -Username $username
                Write-Host "Credential removed for user: $username" -ForegroundColor Green
            } else {
                Write-Host "Invalid selection." -ForegroundColor Yellow
            }
        }
        default { return }
    }
}

function Install-LogonScript {
    param([switch]$Silent)
    
    $startupFolder = Get-StartupFolder
    $baseFolder = Join-Path $env:APPDATA "Share_Manager"
    $ps1Path = Join-Path $baseFolder 'Share_Manager_AutoMap.ps1'
    $cmdPath = Join-Path $startupFolder 'Share_Manager_AutoMap.cmd'
    $logonScript = @'
# Auto-generated by Share Manager v2 (multi-share, DPAPI-protected)
param()
$baseFolder = Join-Path $env:APPDATA "Share_Manager"
$keyPath    = Join-Path $baseFolder "key.bin"
$sharesPath = Join-Path $baseFolder "shares.json"
$credsPath  = Join-Path $baseFolder "creds.json"
$logPath    = Join-Path $baseFolder "LogonScript.log"

function Write-Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$ts`t$msg" | Out-File -FilePath $logPath -Encoding UTF8 -Append
}

if (!(Test-Path $sharesPath)) { Write-Log "Missing shares.json"; return }

$cfg = $null
try { $cfg = (Get-Content -Path $sharesPath -Raw) | ConvertFrom-Json } catch { Write-Log "shares.json parse error"; return }
if (-not $cfg -or -not $cfg.Shares) { Write-Log "No shares in config"; return }

# Load credential map (username -> SecureString) with DPAPI/legacy AES support
$credMap = @{}
if (Test-Path $credsPath) {
    try {
        $store = (Get-Content -Path $credsPath -Raw) | ConvertFrom-Json
        if ($store -and $store.Entries) {
            $aesKey = $null
            if (Test-Path $keyPath) { $aesKey = [System.IO.File]::ReadAllBytes($keyPath) }
            
            foreach ($e in $store.Entries) {
                try { 
                    if ($e.EncryptionType -eq "DPAPI") {
                        # Modern DPAPI encryption
                        $credMap[$e.Username] = ($e.Encrypted | ConvertTo-SecureString)
                    } elseif ($aesKey) {
                        # Legacy AES encryption
                        $credMap[$e.Username] = ($e.Encrypted | ConvertTo-SecureString -Key $aesKey)
                    } else {
                        # Try DPAPI anyway
                        $credMap[$e.Username] = ($e.Encrypted | ConvertTo-SecureString)
                    }
                } catch { Write-Log "Failed to decrypt credential for $($e.Username)" }
            }
        }
    } catch { Write-Log "Failed to load creds store" }
}

foreach ($s in $cfg.Shares) {
    if (-not $s.Enabled) { continue }
    $drive = "$($s.DriveLetter):"
    $share = $s.SharePath
    $user  = $s.Username

    # Remove existing mapping silently
    cmd /c "net use `"$drive`" /delete /y >nul 2>&1"

    $plainPW = $null
    if ($user -and $credMap.ContainsKey($user)) {
        $plainPW = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credMap[$user])
        )
    }

    # Try mapping up to 3 times
    for ($i=0; $i -lt 3; $i++) {
        if ($plainPW) {
            cmd /c "net use `"$drive`" `"$share`" /user:$user $plainPW /persistent:yes >nul 2>&1"
        } else {
            cmd /c "net use `"$drive`" `"$share`" /persistent:yes >nul 2>&1"
        }
        if ($LASTEXITCODE -eq 0) { Write-Log "Mapped $drive to $share"; break }
        Start-Sleep -Seconds 5
    }
}
'@
    $cmdScript = @"
@echo off
set SCRIPT=%APPDATA%\Share_Manager\Share_Manager_AutoMap.ps1
set LOG=%APPDATA%\Share_Manager\LogonScript_cmd.log
where pwsh >nul 2>nul
if %errorlevel%==0 (
    start "" pwsh -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""%SCRIPT%"" >>""%LOG%"" 2>&1
) else (
    start "" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""%SCRIPT%"" >>""%LOG%"" 2>&1
)
"@
    if (-not (Test-Path $baseFolder)) {
        New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
    }
    Set-Content -Path $ps1Path -Value $logonScript -Encoding UTF8 -Force
    Set-Content -Path $cmdPath -Value $cmdScript -Encoding ASCII -Force
    if (-not $Silent) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Persistent mapping enabled. Logon script installed to $cmdPath.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } else {
            Write-Host "Persistent mapping enabled. Logon script installed to $cmdPath." -ForegroundColor Green
        }
    }
    Write-ActionLog "Logon script installed to $cmdPath and $ps1Path"
}

function Remove-LogonScript {
    param([switch]$Silent)
    
    $startupFolder = Get-StartupFolder
    $baseFolder = Join-Path $env:APPDATA "Share_Manager"
    $ps1Path = Join-Path $baseFolder 'Share_Manager_AutoMap.ps1'
    $cmdPath = Join-Path $startupFolder 'Share_Manager_AutoMap.cmd'
    $logPath = Join-Path $baseFolder 'LogonScript.log'
    $removed = $false
    if (Test-Path $ps1Path) { Remove-Item $ps1Path -Force; $removed = $true }
    if (Test-Path $cmdPath) { Remove-Item $cmdPath -Force; $removed = $true }
    if (Test-Path $logPath) { Remove-Item $logPath -Force }
    if ($removed -and -not $Silent) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Persistent mapping removed. Logon script removed from $startupFolder.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } else {
            Write-Host "Persistent mapping removed. Logon script removed from $startupFolder." -ForegroundColor Yellow
        }
        Write-ActionLog "Logon script removed from $startupFolder and $ps1Path"
    }
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
        PersistentMapping = if ($CurrentPrefs.PSObject.Properties["PersistentMapping"]) { [bool]$CurrentPrefs.PersistentMapping } else { $false }
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "Preferences v$version"
    $form.Width           = 350
    $form.Height          = 300
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

    # Persistent mapping checkbox
    $chkPersist = New-Object System.Windows.Forms.CheckBox
    $chkPersist.Text     = "Map drive persistently (reconnect at logon)"
    $chkPersist.AutoSize = $true
    $chkPersist.Top      = 50
    $chkPersist.Left     = 20
    $chkPersist.Checked  = $prefs.PersistentMapping
    $form.Controls.Add($chkPersist)

    # Label
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text     = "Startup mode:"
    $lbl.AutoSize = $true
    $lbl.Top      = 90
    $lbl.Left     = 20
    $form.Controls.Add($lbl)

    # Radio buttons
    $rdoCLI    = New-Object System.Windows.Forms.RadioButton
    $rdoCLI.Text     = "CLI"
    $rdoCLI.AutoSize = $true
    $rdoCLI.Top      = 120
    $rdoCLI.Left     = 40
    $rdoGUI    = New-Object System.Windows.Forms.RadioButton
    $rdoGUI.Text     = "GUI"
    $rdoGUI.AutoSize = $true
    $rdoGUI.Top      = 150
    $rdoGUI.Left     = 40
    $rdoPrompt = New-Object System.Windows.Forms.RadioButton
    $rdoPrompt.Text     = "Prompt"
    $rdoPrompt.AutoSize = $true
    $rdoPrompt.Top      = 180
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
    $btnSave.Top    = 220
    $btnSave.Left   = 50
    $btnSave.Add_Click({
        $prefs.UnmapOldMapping   = $chk.Checked
        $prefs.PersistentMapping = $chkPersist.Checked
        if ($rdoCLI.Checked)    { $prefs.PreferredMode = "CLI" }
        elseif ($rdoGUI.Checked) { $prefs.PreferredMode = "GUI" }
        else                     { $prefs.PreferredMode = "Prompt" }
        $form.Tag = $prefs
        $form.Close()
    })
    $form.Controls.Add($btnSave)
    
    # Set the Save button as the default accept button (triggered by Enter)
    $form.AcceptButton = $btnSave

    # Cancel (if not initial)
    if (-not $IsInitial) {
        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text   = "Cancel"
        $btnCancel.Width  = 100
        $btnCancel.Height = 30
        $btnCancel.Top    = 220
        $btnCancel.Left   = 180
        $btnCancel.Add_Click({ $form.Close() })
        $form.Controls.Add($btnCancel)
    }

    [void]$form.ShowDialog()
    return $form.Tag
}

function Hide-ConsoleWindow {
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

function Show-AddShareDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Add New Share"
    $form.Width = 500
    $form.Height = 480
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    $y = 20
    
    # Name
    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Text = "Share Name:"
    $lblName.Top = $y
    $lblName.Left = 20
    $lblName.Width = 120
    $form.Controls.Add($lblName)
    
    $txtName = New-Object System.Windows.Forms.TextBox
    $txtName.Top = $y
    $txtName.Left = 150
    $txtName.Width = 310
    $form.Controls.Add($txtName)
    
    $y += 25
    
    $lblNameHint = New-Object System.Windows.Forms.Label
    $lblNameHint.Text = "Example: Office Files, Project Drive"
    $lblNameHint.Top = $y
    $lblNameHint.Left = 150
    $lblNameHint.Width = 310
    $lblNameHint.ForeColor = [System.Drawing.Color]::Gray
    $lblNameHint.Font = New-Object System.Drawing.Font($lblNameHint.Font.FontFamily, 8)
    $form.Controls.Add($lblNameHint)
    
    $y += 30
    
    # Share Path
    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Text = "Network Path:"
    $lblPath.Top = $y
    $lblPath.Left = 20
    $lblPath.Width = 120
    $form.Controls.Add($lblPath)
    
    $txtPath = New-Object System.Windows.Forms.TextBox
    $txtPath.Top = $y
    $txtPath.Left = 150
    $txtPath.Width = 310
    $form.Controls.Add($txtPath)
    
    $y += 25
    
    $lblPathHint = New-Object System.Windows.Forms.Label
    $lblPathHint.Text = "Example: \\192.168.1.100\share or \\server\folder"
    $lblPathHint.Top = $y
    $lblPathHint.Left = 150
    $lblPathHint.Width = 310
    $lblPathHint.ForeColor = [System.Drawing.Color]::Gray
    $lblPathHint.Font = New-Object System.Drawing.Font($lblPathHint.Font.FontFamily, 8)
    $form.Controls.Add($lblPathHint)
    
    $y += 30
    
    # Drive Letter
    $lblDrive = New-Object System.Windows.Forms.Label
    $lblDrive.Text = "Drive Letter:"
    $lblDrive.Top = $y
    $lblDrive.Left = 20
    $lblDrive.Width = 120
    $form.Controls.Add($lblDrive)
    
    $txtDrive = New-Object System.Windows.Forms.TextBox
    $txtDrive.Top = $y
    $txtDrive.Left = 150
    $txtDrive.Width = 50
    $txtDrive.MaxLength = 1
    $form.Controls.Add($txtDrive)
    
    $y += 25
    
    $lblDriveHint = New-Object System.Windows.Forms.Label
    $lblDriveHint.Text = "Example: Z, Y, X (single letter)"
    $lblDriveHint.Top = $y
    $lblDriveHint.Left = 150
    $lblDriveHint.Width = 310
    $lblDriveHint.ForeColor = [System.Drawing.Color]::Gray
    $lblDriveHint.Font = New-Object System.Drawing.Font($lblDriveHint.Font.FontFamily, 8)
    $form.Controls.Add($lblDriveHint)
    
    $y += 30
    
    # Username
    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = "Username:"
    $lblUser.Top = $y
    $lblUser.Left = 20
    $lblUser.Width = 120
    $form.Controls.Add($lblUser)
    
    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Top = $y
    $txtUser.Left = 150
    $txtUser.Width = 310
    $form.Controls.Add($txtUser)
    
    $y += 25
    
    $lblUserHint = New-Object System.Windows.Forms.Label
    $lblUserHint.Text = "Example: john, DOMAIN\john, user@domain.com"
    $lblUserHint.Top = $y
    $lblUserHint.Left = 150
    $lblUserHint.Width = 310
    $lblUserHint.ForeColor = [System.Drawing.Color]::Gray
    $lblUserHint.Font = New-Object System.Drawing.Font($lblUserHint.Font.FontFamily, 8)
    $form.Controls.Add($lblUserHint)
    
    $y += 30
    
    # Description
    $lblDesc = New-Object System.Windows.Forms.Label
    $lblDesc.Text = "Description:"
    $lblDesc.Top = $y
    $lblDesc.Left = 20
    $lblDesc.Width = 120
    $form.Controls.Add($lblDesc)
    
    $txtDesc = New-Object System.Windows.Forms.TextBox
    $txtDesc.Top = $y
    $txtDesc.Left = 150
    $txtDesc.Width = 310
    $form.Controls.Add($txtDesc)
    
    $y += 25
    
    $lblDescHint = New-Object System.Windows.Forms.Label
    $lblDescHint.Text = "(Optional) Additional notes about this share"
    $lblDescHint.Top = $y
    $lblDescHint.Left = 150
    $lblDescHint.Width = 310
    $lblDescHint.ForeColor = [System.Drawing.Color]::Gray
    $lblDescHint.Font = New-Object System.Drawing.Font($lblDescHint.Font.FontFamily, 8)
    $form.Controls.Add($lblDescHint)
    
    $y += 35
    
    # Enabled checkbox
    $chkEnabled = New-Object System.Windows.Forms.CheckBox
    $chkEnabled.Text = "Enabled"
    $chkEnabled.Top = $y
    $chkEnabled.Left = 150
    $chkEnabled.Checked = $true
    $form.Controls.Add($chkEnabled)
    
    $y += 40
    
    # Save button (needs to be created before adding Enter key handlers)
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Save"
    $btnSave.Top = $y
    $btnSave.Left = 180
    $btnSave.Width = 120
    
    # Add Enter key navigation for textboxes
    Add-CtrlASupport -TextBox $txtName -NextControl $txtPath
    Add-CtrlASupport -TextBox $txtPath -NextControl $txtDrive
    Add-CtrlASupport -TextBox $txtDrive -NextControl $txtUser
    Add-CtrlASupport -TextBox $txtUser -NextControl $txtDesc
    Add-CtrlASupport -TextBox $txtDesc -NextControl $btnSave
    $btnSave.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Share name is required.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if ($txtPath.Text -notmatch '^\\\\[^\\]+\\') {
            [System.Windows.Forms.MessageBox]::Show("Invalid UNC path. Must start with \\ (e.g., \\server\share)", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if ($txtDrive.Text -notmatch '^[A-Za-z]$') {
            [System.Windows.Forms.MessageBox]::Show("Invalid drive letter. Enter a single letter (A-Z).", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if ([string]::IsNullOrWhiteSpace($txtUser.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Username is required.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        # Prevent drive-letter conflicts with other enabled shares
        $cfgCheck = Import-AllShares
        $conflict = $cfgCheck.Shares | Where-Object { $_.Enabled -and $_.DriveLetter -eq $txtDrive.Text.ToUpper() }
        if ($conflict) {
            [System.Windows.Forms.MessageBox]::Show("Drive letter $($txtDrive.Text.ToUpper()) is already assigned to share '$($conflict.Name)'.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        $username = $txtUser.Text.Trim()
        
        $result = Add-ShareConfiguration -Name $txtName.Text -SharePath $txtPath.Text `
            -DriveLetter $txtDrive.Text.ToUpper() -Username $username `
            -Description $txtDesc.Text -Enabled $chkEnabled.Checked
        
        if ($result) {
            $shareName = $txtName.Text
            $sharePath = $txtPath.Text
            $driveLetter = $txtDrive.Text.ToUpper()
            
            # Check if credentials exist for this username
            $existingCred = Get-CredentialForShare -Username $username
            $credentialSaved = $false
            
            if (-not $existingCred) {
                # No credentials found - prompt to save them
                $promptResult = [System.Windows.Forms.MessageBox]::Show(
                    "No credentials found for user: $username`n`nWould you like to save credentials now?`n(Required to connect to this share)",
                    "Credentials Required",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                
                if ($promptResult -eq 'Yes') {
                    $cred = Show-CredentialForm -Username $username -Message "Enter password for $username"
                    if ($cred) {
                        Save-Credential -Credential $cred
                        $existingCred = $cred
                        $credentialSaved = $true
                    }
                }
            } else {
                $credentialSaved = $true
            }
            
            # Offer to connect if we have credentials and share is enabled
            if ($existingCred -and $chkEnabled.Checked) {
                $connectResult = [System.Windows.Forms.MessageBox]::Show(
                    "Share '$shareName' added successfully!`n`nWould you like to connect to it now?",
                    "Connect Share",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                
                if ($connectResult -eq 'Yes') {
                    Connect-NetworkShare -SharePath $sharePath -DriveLetter $driveLetter -Credential $existingCred
                    
                    # Update last connected
                    $config = Import-AllShares
                    $shareObj = $config.Shares | Where-Object { $_.DriveLetter -eq $driveLetter }
                    if ($shareObj) {
                        $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Save-AllShares -Config $config | Out-Null
                    }
                } else {
                    [System.Windows.Forms.MessageBox]::Show("Share added successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
            } elseif (-not $credentialSaved) {
                [System.Windows.Forms.MessageBox]::Show("Share added, but no credentials saved.`nAdd credentials later to connect.", "Partial Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Share added successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            
            $form.DialogResult = 'OK'
            $form.Close()
        }
    })
    $form.Controls.Add($btnSave)
    
    # Cancel button
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Top = $y
    $btnCancel.Left = 310
    $btnCancel.Width = 100
    $btnCancel.Add_Click({ $form.Close() })
    $form.Controls.Add($btnCancel)
    
    [void]$form.ShowDialog()
}

function Show-ManageShareDialog {
    param([string]$ShareId)
    
    $share = Get-ShareConfiguration -ShareId $ShareId
    if (-not $share) {
        [System.Windows.Forms.MessageBox]::Show("Share not found", "Error")
        return
    }
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Manage Share - $($share.Name)"
    $form.Width = 500
    $form.Height = 450
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    
    $y = 20
    
    # Name
    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Text = "Share Name:"
    $lblName.Top = $y
    $lblName.Left = 20
    $lblName.AutoSize = $true
    $form.Controls.Add($lblName)
    
    $txtName = New-Object System.Windows.Forms.TextBox
    $txtName.Text = $share.Name
    $txtName.Top = $y
    $txtName.Left = 150
    $txtName.Width = 300
    $form.Controls.Add($txtName)
    
    $y += 35
    
    # Share Path
    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Text = "Network Path:"
    $lblPath.Top = $y
    $lblPath.Left = 20
    $lblPath.AutoSize = $true
    $form.Controls.Add($lblPath)
    
    $txtPath = New-Object System.Windows.Forms.TextBox
    $txtPath.Text = $share.SharePath
    $txtPath.Top = $y
    $txtPath.Left = 150
    $txtPath.Width = 300
    $form.Controls.Add($txtPath)
    
    $y += 35
    
    # Drive Letter
    $lblDrive = New-Object System.Windows.Forms.Label
    $lblDrive.Text = "Drive Letter:"
    $lblDrive.Top = $y
    $lblDrive.Left = 20
    $lblDrive.AutoSize = $true
    $form.Controls.Add($lblDrive)
    
    $txtDrive = New-Object System.Windows.Forms.TextBox
    $txtDrive.Text = $share.DriveLetter
    $txtDrive.Top = $y
    $txtDrive.Left = 150
    $txtDrive.Width = 50
    $txtDrive.MaxLength = 1
    $form.Controls.Add($txtDrive)
    
    $y += 35
    
    # Username
    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = "Username:"
    $lblUser.Top = $y
    $lblUser.Left = 20
    $lblUser.AutoSize = $true
    $form.Controls.Add($lblUser)
    
    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Text = $share.Username
    $txtUser.Top = $y
    $txtUser.Left = 150
    $txtUser.Width = 300
    $form.Controls.Add($txtUser)
    
    $y += 35
    
    # Description
    $lblDesc = New-Object System.Windows.Forms.Label
    $lblDesc.Text = "Description:"
    $lblDesc.Top = $y
    $lblDesc.Left = 20
    $lblDesc.AutoSize = $true
    $form.Controls.Add($lblDesc)
    
    $txtDesc = New-Object System.Windows.Forms.TextBox
    $txtDesc.Text = $share.Description
    $txtDesc.Top = $y
    $txtDesc.Left = 150
    $txtDesc.Width = 300
    $form.Controls.Add($txtDesc)
    
    $y += 35
    
    # Enabled checkbox
    $chkEnabled = New-Object System.Windows.Forms.CheckBox
    $chkEnabled.Text = "Enabled"
    $chkEnabled.Top = $y
    $chkEnabled.Left = 150
    $chkEnabled.Checked = $share.Enabled
    $form.Controls.Add($chkEnabled)
    
    $y += 50
    
    # Save button
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Save Changes"
    $btnSave.Top = $y
    $btnSave.Left = 20
    $btnSave.Width = 120
    
    # Add Enter key navigation for textboxes
    Add-CtrlASupport -TextBox $txtName -NextControl $txtPath
    Add-CtrlASupport -TextBox $txtPath -NextControl $txtDrive
    Add-CtrlASupport -TextBox $txtDrive -NextControl $txtUser
    Add-CtrlASupport -TextBox $txtUser -NextControl $txtDesc
    Add-CtrlASupport -TextBox $txtDesc -NextControl $btnSave
    
    $btnSave.Add_Click({
        # Validate inputs
        if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Name is required", "Validation Error")
            return
        }
        if ($txtPath.Text -notmatch '^\\\\[^\\]+\\') {
            [System.Windows.Forms.MessageBox]::Show("Invalid UNC path", "Validation Error")
            return
        }
        if ($txtDrive.Text -notmatch '^[A-Za-z]$') {
            [System.Windows.Forms.MessageBox]::Show("Invalid drive letter", "Validation Error")
            return
        }
        if ([string]::IsNullOrWhiteSpace($txtUser.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Username is required", "Validation Error")
            return
        }
        # Prevent drive-letter conflicts with other enabled shares
        $cfgCheck = Import-AllShares
        $conflict = $cfgCheck.Shares | Where-Object { $_.Id -ne $ShareId -and $_.Enabled -and $_.DriveLetter -eq $txtDrive.Text.ToUpper() }
        if ($conflict) {
            [System.Windows.Forms.MessageBox]::Show("Drive letter $($txtDrive.Text.ToUpper()) is already assigned to share '$($conflict.Name)'.", "Validation Error")
            return
        }

        $result = Update-ShareConfiguration -ShareId $ShareId -Name $txtName.Text `
            -SharePath $txtPath.Text -DriveLetter $txtDrive.Text.ToUpper() `
            -Username $txtUser.Text -Description $txtDesc.Text -Enabled $chkEnabled.Checked
        
        if ($result) {
            [System.Windows.Forms.MessageBox]::Show("Share updated successfully!", "Success")
            $form.DialogResult = 'OK'
            $form.Close()
        }
    })
    $form.Controls.Add($btnSave)
    
    # Delete button
    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Text = "Delete Share"
    $btnDelete.Top = $y
    $btnDelete.Left = 150
    $btnDelete.Width = 120
    $btnDelete.ForeColor = [System.Drawing.Color]::Red
    $btnDelete.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to delete this share?",
            "Confirm Delete",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -eq 'Yes') {
            Remove-ShareConfiguration -ShareId $ShareId
            [System.Windows.Forms.MessageBox]::Show("Share deleted", "Success")
            $form.DialogResult = 'OK'
            $form.Close()
        }
    })
    $form.Controls.Add($btnDelete)
    
    # Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Top = $y
    $btnClose.Left = 280
    $btnClose.Width = 120
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)
    
    [void]$form.ShowDialog()
}

function Show-CredentialsDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Manage Credentials"
    $form.Width = 500
    $form.Height = 400
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    
    # ListView for credentials
    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = 'Details'
    $listView.FullRowSelect = $true
    $listView.Top = 20
    $listView.Left = 20
    $listView.Width = 440
    $listView.Height = 200
    [void]$listView.Columns.Add("Username", 200)
    [void]$listView.Columns.Add("Encryption", 120)
    [void]$listView.Columns.Add("Shares Using", 100)
    $form.Controls.Add($listView)
    
    function Update-CredList {
        $listView.Items.Clear()
        $store = Import-CredentialStore
        $shares = Get-ShareConfiguration
        
        if ($store -and $store.Entries) {
            foreach ($entry in $store.Entries) {
                $item = New-Object System.Windows.Forms.ListViewItem($entry.Username)
                [void]$item.SubItems.Add($entry.EncryptionType)
                
                # Count shares using this credential (case-insensitive comparison)
                $usingCount = 0
                if ($shares) {
                    $usingCount = @($shares | Where-Object { 
                        $_.Username -and $_.Username -eq $entry.Username 
                    }).Count
                }
                [void]$item.SubItems.Add($usingCount.ToString())
                $item.Tag = $entry.Username
                
                [void]$listView.Items.Add($item)
            }
        }
    }
    
    Update-CredList
    
    $y = 240
    
    # Add/Update button
    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Text = "Add/Update"
    $btnAdd.Top = $y
    $btnAdd.Left = 20
    $btnAdd.Width = 130
    $btnAdd.Add_Click({
        $username = Show-InputBox -Prompt "Enter username:" -Title "Add/Update Credential"
        if ([string]::IsNullOrWhiteSpace($username)) { return }
        
        $cred = Get-Credential -Message "Enter password for $username" -UserName $username
        if ($cred) {
            Save-Credential -Credential $cred
            Update-CredList
            [System.Windows.Forms.MessageBox]::Show("Credential saved", "Success")
        }
    })
    $form.Controls.Add($btnAdd)
    
    # Remove button
    $btnRemove = New-Object System.Windows.Forms.Button
    $btnRemove.Text = "Remove"
    $btnRemove.Top = $y
    $btnRemove.Left = 160
    $btnRemove.Width = 130
    $btnRemove.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a credential first", "No Selection")
            return
        }
        
        $username = $listView.SelectedItems[0].Tag
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Remove credential for $username?",
            "Confirm Remove",
            [System.Windows.Forms.MessageBoxButtons]::YesNo
        )
        
        if ($result -eq 'Yes') {
            Remove-Credential -Username $username
            Update-CredList
            [System.Windows.Forms.MessageBox]::Show("Credential removed", "Success")
        }
    })
    $form.Controls.Add($btnRemove)
    
    # Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Top = $y
    $btnClose.Left = 300
    $btnClose.Width = 130
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)
    
    [void]$form.ShowDialog()
}

function Show-BackupDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Backup & Restore"
    $form.Width = 450
    $form.Height = 330
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    
    $y = 30
    
    # Export button
    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = "Export Configuration"
    $btnExport.Top = $y
    $btnExport.Left = 30
    $btnExport.Width = 370
    $btnExport.Height = 45
    $btnExport.Add_Click({
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        $dialog.DefaultExt = "json"
        $dialog.FileName = "ShareManager_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        
        if ($dialog.ShowDialog() -eq 'OK') {
            if (Export-ShareConfiguration -ExportPath $dialog.FileName) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Configuration exported successfully!`n`nLocation: $($dialog.FileName)",
                    "Export Successful",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
        }
    })
    $form.Controls.Add($btnExport)
    
    $y += 55
    
    # Import & Replace button
    $btnReplace = New-Object System.Windows.Forms.Button
    $btnReplace.Text = "Import && Replace (Overwrite current)"
    $btnReplace.Top = $y
    $btnReplace.Left = 30
    $btnReplace.Width = 370
    $btnReplace.Height = 45
    $btnReplace.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show(
            "WARNING: This will DELETE all current shares and replace with the imported configuration.`n`nContinue?",
            "Confirm Replace",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        
        if ($result -eq 'Yes') {
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
            
            if ($dialog.ShowDialog() -eq 'OK') {
                $importResult = Import-ShareConfiguration -ImportPath $dialog.FileName -Merge $false
                if ($importResult.Success) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Configuration replaced successfully!`n`nImported: $($importResult.Added) share(s)",
                        "Replace Successful",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                    $form.DialogResult = 'OK'
                    $form.Close()
                }
            }
        }
    })
    $form.Controls.Add($btnReplace)
    
    $y += 55
    
    # Import & Merge button
    $btnMerge = New-Object System.Windows.Forms.Button
    $btnMerge.Text = "Import && Merge (Add to current)"
    $btnMerge.Top = $y
    $btnMerge.Left = 30
    $btnMerge.Width = 370
    $btnMerge.Height = 45
    $btnMerge.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        
        if ($dialog.ShowDialog() -eq 'OK') {
            $importResult = Import-ShareConfiguration -ImportPath $dialog.FileName -Merge $true
            if ($importResult.Success) {
                $msg = "Configuration merged successfully!`n`nAdded: $($importResult.Added) share(s)"
                if ($importResult.Skipped -gt 0) {
                    $msg += "`nSkipped: $($importResult.Skipped) duplicate(s)"
                }
                [System.Windows.Forms.MessageBox]::Show(
                    $msg,
                    "Merge Successful",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                $form.DialogResult = 'OK'
                $form.Close()
            }
        }
    })
    $form.Controls.Add($btnMerge)
    
    $y += 60
    
    # Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Top = $y
    $btnClose.Left = 165
    $btnClose.Width = 100
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)
    
    [void]$form.ShowDialog()
}

function Show-PreferencesDialog {
    $config = Import-AllShares
    if (-not $config.Preferences) {
        $config.Preferences = [PSCustomObject]@{
            UnmapOldMapping = $false
            PreferredMode = "Prompt"
            PersistentMapping = $false
        }
    }
    
    $newPrefs = Show-PreferencesForm -CurrentPrefs $config.Preferences -IsInitial $false
    if ($newPrefs) {
        $config.Preferences = $newPrefs
        Save-AllShares -Config $config | Out-Null
        [System.Windows.Forms.MessageBox]::Show("Preferences saved", "Success")
    }
}

function Show-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    Hide-ConsoleWindow

    # Main Form
    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "Share Manager v$version - by $author"
    $form.Width           = 700
    $form.Height          = 650
    $form.StartPosition   = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.MinimumSize     = New-Object System.Drawing.Size(700, 650)
    $form.MaximizeBox     = $true

    # Title Label
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = "Network Shares"
    $lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI",12,[System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize = $true
    $lblTitle.Top      = 15
    $lblTitle.Left     = 15
    $form.Controls.Add($lblTitle)
    
    # Hint Label
    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text     = "Double-click to connect/disconnect | Right-click for more options"
    $lblHint.Font     = New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Italic)
    $lblHint.ForeColor = [System.Drawing.Color]::Gray
    $lblHint.AutoSize = $true
    $lblHint.Top      = 28
    $lblHint.Left     = 200
    $form.Controls.Add($lblHint)

    # ListView for shares
    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = 'Details'
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    $listView.Top = 50
    $listView.Left = 15
    $listView.Width = 660
    $listView.Height = 350
    $listView.Anchor = 'Top,Left,Right,Bottom'
    [void]$listView.Columns.Add("Status", 60)
    [void]$listView.Columns.Add("Name", 150)
    [void]$listView.Columns.Add("Drive", 50)
    [void]$listView.Columns.Add("Path", 250)
    [void]$listView.Columns.Add("Enabled", 70)
    $form.Controls.Add($listView)
    
    # Context menu for right-click on shares
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    
    $menuConnect = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuConnect.Text = "Connect"
    $menuConnect.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        $share = Get-ShareConfiguration -ShareId $shareId
        if (-not $share) { return }

        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            [System.Windows.Forms.MessageBox]::Show("Already connected", "Info")
            return
        }
        
        $cred = Get-CredentialForShare -Username $share.Username
        if (-not $cred) {
            [System.Windows.Forms.MessageBox]::Show("No credentials found for $($share.Username)", "Error")
            return
        }
        
        Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
        Update-ShareList
    })
    [void]$contextMenu.Items.Add($menuConnect)
    
    $menuDisconnect = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuDisconnect.Text = "Disconnect"
    $menuDisconnect.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        $share = Get-ShareConfiguration -ShareId $shareId
        
        if (-not (Test-ShareConnection -DriveLetter $share.DriveLetter)) {
            [System.Windows.Forms.MessageBox]::Show("Not connected", "Info")
            return
        }
        
        Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent
        Update-ShareList
    })
    [void]$contextMenu.Items.Add($menuDisconnect)
    
    [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    
    $menuEdit = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuEdit.Text = "Edit..."
    $menuEdit.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        Show-ManageShareDialog -ShareId $shareId
        Update-ShareList
    })
    [void]$contextMenu.Items.Add($menuEdit)
    
    $menuToggle = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuToggle.Text = "Toggle Enabled/Disabled"
    $menuToggle.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        
        $config = Import-AllShares
        $shareObj = $config.Shares | Where-Object { $_.Id -eq $shareId }
        if ($shareObj) {
            $shareObj.Enabled = -not $shareObj.Enabled
            Save-AllShares -Config $config | Out-Null
            Update-ShareList
        }
    })
    [void]$contextMenu.Items.Add($menuToggle)
    
    [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    
    $menuDelete = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuDelete.Text = "Delete..."
    $menuDelete.ForeColor = [System.Drawing.Color]::Red
    $menuDelete.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        $share = Get-ShareConfiguration -ShareId $shareId
        
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Delete share '$($share.Name)'?",
            "Confirm Delete",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -eq 'Yes') {
            Remove-ShareConfiguration -ShareId $shareId
            Update-ShareList
        }
    })
    [void]$contextMenu.Items.Add($menuDelete)
    
    $listView.ContextMenuStrip = $contextMenu
    
    # Double-click to toggle connection
    $listView.Add_DoubleClick({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        $share = Get-ShareConfiguration -ShareId $shareId
        
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent
        } else {
            $cred = Get-CredentialForShare -Username $share.Username
            if ($cred) {
                Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
            }
        }
        Update-ShareList
    })

    # Toolbar panel (below ListView)
    $toolbarY = 410
    
    # Group: Share Actions
    $grpShares = New-Object System.Windows.Forms.GroupBox
    $grpShares.Text = "Share Actions"
    $grpShares.Top = $toolbarY
    $grpShares.Left = 15
    $grpShares.Width = 435
    $grpShares.Height = 75
    $form.Controls.Add($grpShares)

    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Text = "Add New"
    $btnAdd.Width = 100
    $btnAdd.Height = 40
    $btnAdd.Top = 25
    $btnAdd.Left = 10
    $btnAdd.Add_Click({
        Show-AddShareDialog
        Update-ShareList
    })
    $grpShares.Controls.Add($btnAdd)
    
    $btnConnectAll = New-Object System.Windows.Forms.Button
    $btnConnectAll.Text = "Connect All"
    $btnConnectAll.Width = 100
    $btnConnectAll.Height = 40
    $btnConnectAll.Top = 25
    $btnConnectAll.Left = 115
    $btnConnectAll.Add_Click({
        $shares = Get-ShareConfiguration | Where-Object { $_.Enabled }
        $success = 0
        $failed = 0
        
        foreach ($share in $shares) {
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) { continue }
            
            $cred = Get-CredentialForShare -Username $share.Username
            if (-not $cred) {
                $failed++
                continue
            }
            
            try {
                Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
                if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                    $success++
                    $config = Import-AllShares
                    $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                    if ($shareObj) {
                        $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Save-AllShares -Config $config | Out-Null
                    }
                } else {
                    $failed++
                }
            } catch {
                $failed++
            }
        }
        
        Update-ShareList
        if ($success -gt 0 -or $failed -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Connected: $success`nFailed: $failed",
                "Connect All",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })
    $grpShares.Controls.Add($btnConnectAll)

    $btnDisconnectAll = New-Object System.Windows.Forms.Button
    $btnDisconnectAll.Text = "Disconnect All"
    $btnDisconnectAll.Width = 100
    $btnDisconnectAll.Height = 40
    $btnDisconnectAll.Top = 25
    $btnDisconnectAll.Left = 220
    $btnDisconnectAll.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Disconnect all connected shares?",
            "Confirm",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($result -eq 'Yes') {
            $shares = Get-ShareConfiguration
            $disconnected = 0
            
            foreach ($share in $shares) {
                if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                    Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent
                    $disconnected++
                }
            }
            
            Update-ShareList
            if ($disconnected -gt 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Disconnected $disconnected share(s)",
                    "Disconnect All",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
        }
    })
    $grpShares.Controls.Add($btnDisconnectAll)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = "Refresh"
    $btnRefresh.Width = 100
    $btnRefresh.Height = 40
    $btnRefresh.Top = 25
    $btnRefresh.Left = 325
    $btnRefresh.Add_Click({
        Update-ShareList
    })
    $grpShares.Controls.Add($btnRefresh)
    
    # Group: System
    $grpSystem = New-Object System.Windows.Forms.GroupBox
    $grpSystem.Text = "System"
    $grpSystem.Top = $toolbarY
    $grpSystem.Left = 460
    $grpSystem.Width = 215
    $grpSystem.Height = 120
    $form.Controls.Add($grpSystem)
    
    $btnCredentials = New-Object System.Windows.Forms.Button
    $btnCredentials.Text = "Credentials"
    $btnCredentials.Width = 95
    $btnCredentials.Height = 40
    $btnCredentials.Top = 25
    $btnCredentials.Left = 10
    $btnCredentials.Add_Click({
        Show-CredentialsDialog
    })
    $grpSystem.Controls.Add($btnCredentials)
    
    $btnSettings = New-Object System.Windows.Forms.Button
    $btnSettings.Text = "Settings"
    $btnSettings.Width = 95
    $btnSettings.Height = 40
    $btnSettings.Top = 25
    $btnSettings.Left = 110
    $btnSettings.Add_Click({
        $formSettings = New-Object System.Windows.Forms.Form
        $formSettings.Text = "Settings"
        $formSettings.Width = 350
        $formSettings.Height = 200
        $formSettings.StartPosition = "CenterParent"
        $formSettings.FormBorderStyle = "FixedDialog"
        $formSettings.MaximizeBox = $false
        
        $yPos = 20
        
        $btnPref = New-Object System.Windows.Forms.Button
        $btnPref.Text = "Preferences"
        $btnPref.Width = 280
        $btnPref.Height = 35
        $btnPref.Top = $yPos
        $btnPref.Left = 30
        $btnPref.Add_Click({
            Show-PreferencesDialog
        })
        $formSettings.Controls.Add($btnPref)
        
        $yPos += 45
        
        $btnBackup = New-Object System.Windows.Forms.Button
        $btnBackup.Text = "Backup / Restore"
        $btnBackup.Width = 280
        $btnBackup.Height = 35
        $btnBackup.Top = $yPos
        $btnBackup.Left = 30
        $btnBackup.Add_Click({
            Show-BackupDialog
        })
        $formSettings.Controls.Add($btnBackup)
        
        $yPos += 45
        
        $btnLog = New-Object System.Windows.Forms.Button
        $btnLog.Text = "Open Log File"
        $btnLog.Width = 280
        $btnLog.Height = 35
        $btnLog.Top = $yPos
        $btnLog.Left = 30
        $btnLog.Add_Click({
            Invoke-LogFileOpen
        })
        $formSettings.Controls.Add($btnLog)
        
        [void]$formSettings.ShowDialog()
    })
    $grpSystem.Controls.Add($btnSettings)

    # About button
    $btnAbout = New-Object System.Windows.Forms.Button
    $btnAbout.Text = "About"
    $btnAbout.Width = 195
    $btnAbout.Height = 35
    $btnAbout.Top = 70
    $btnAbout.Left = 10
    $btnAbout.Add_Click({
        [System.Windows.Forms.MessageBox]::Show(
            "Share Manager v$version`nAuthor: $author",
            "About",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    })
    $grpSystem.Controls.Add($btnAbout)
    
    # Bottom buttons (CLI/Exit) - position below the taller of the two groups
    $bottomY = $toolbarY + ([Math]::Max($grpShares.Height, $grpSystem.Height)) + 10
    
    $btnCLI = New-Object System.Windows.Forms.Button
    $btnCLI.Text = "Switch to CLI"
    $btnCLI.Width = 320
    $btnCLI.Height = 35
    $btnCLI.Top = $bottomY
    $btnCLI.Left = 15
    $btnCLI.Anchor = 'Bottom,Left'
    $btnCLI.Add_Click({
        $scriptPath = $PSCommandPath
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`" -StartupMode CLI" `
            -WindowStyle Normal
        $form.Close()
    })
    $form.Controls.Add($btnCLI)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "Exit"
    $btnExit.Width = 330
    $btnExit.Height = 35
    $btnExit.Top = $bottomY
    $btnExit.Left = 345
    $btnExit.Anchor = 'Bottom,Left,Right'
    $btnExit.Add_Click({
        $form.Close()
    })
    $form.Controls.Add($btnExit)

    # Status bar
    $statusBar = New-Object System.Windows.Forms.StatusBar
    $statusBar.Text = "Ready"
    $form.Controls.Add($statusBar)

    # Helper function to update the ListView
    function Update-ShareList {
        $listView.Items.Clear()
        $shares = @(Get-ShareConfiguration)
        
        foreach ($share in $shares) {
            $item = New-Object System.Windows.Forms.ListViewItem
            
            # Status column
            $isConnected = Test-ShareConnection -DriveLetter $share.DriveLetter
            $item.Text = if ($isConnected) { "[*]" } else { "[ ]" }
            $item.ForeColor = if ($isConnected) { [System.Drawing.Color]::Green } else { [System.Drawing.Color]::Red }
            
            # Name column
            [void]$item.SubItems.Add($share.Name)
            
            # Drive column
            [void]$item.SubItems.Add("$($share.DriveLetter):")
            
            # Path column
            [void]$item.SubItems.Add($share.SharePath)
            
            # Enabled column
            [void]$item.SubItems.Add($(if ($share.Enabled) { "Yes" } else { "No" }))
            
            # Store ShareId in Tag for later reference
            $item.Tag = $share.Id
            
            [void]$listView.Items.Add($item)
        }
        
        # Update status bar
        $total = $shares.Count
        $connectedCount = 0
        foreach ($share in $shares) {
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                $connectedCount++
            }
        }
        $statusBar.Text = "Total: $total shares | Connected: $connectedCount | Disconnected: $($total - $connectedCount)"
        
        # Update button states based on share status
        $hasDisconnected = ($total - $connectedCount) -gt 0
        $hasConnected = $connectedCount -gt 0
        
        # Enable Connect All only if there are disconnected shares
        $btnConnectAll.Enabled = $hasDisconnected
        if (-not $hasDisconnected) {
            $btnConnectAll.ForeColor = [System.Drawing.Color]::Gray
        } else {
            $btnConnectAll.ForeColor = [System.Drawing.Color]::Black
        }
        
        # Enable Disconnect All only if there are connected shares
        $btnDisconnectAll.Enabled = $hasConnected
        if (-not $hasConnected) {
            $btnDisconnectAll.ForeColor = [System.Drawing.Color]::Gray
        } else {
            $btnDisconnectAll.ForeColor = [System.Drawing.Color]::Black
        }
        
        # Update context menu items based on selection
        if ($listView.SelectedItems.Count -gt 0) {
            $shareId = $listView.SelectedItems[0].Tag
            $share = Get-ShareConfiguration -ShareId $shareId
            $isConnected = Test-ShareConnection -DriveLetter $share.DriveLetter
            
            $menuConnect.Enabled = -not $isConnected
            $menuDisconnect.Enabled = $isConnected
        }
    }
    
    # Selection changed event to update context menu
    $listView.Add_SelectedIndexChanged({
        if ($listView.SelectedItems.Count -gt 0) {
            $shareId = $listView.SelectedItems[0].Tag
            $share = Get-ShareConfiguration -ShareId $shareId
            $isConnected = Test-ShareConnection -DriveLetter $share.DriveLetter
            
            $menuConnect.Enabled = -not $isConnected
            $menuDisconnect.Enabled = $isConnected
        }
    })

    # Initial population
    Update-ShareList

    [void]$form.ShowDialog()
}

#endregion

#region Mode Selection (Entry Point)

# Migrate legacy config first time
Convert-LegacyConfig

$cfg = Import-AllShares
$hasShares = ($cfg.Shares.Count -gt 0)

# If StartupMode parameter is provided, override preference
if ($StartupMode -eq "CLI" -or $StartupMode -eq "GUI") {
    if ($StartupMode -eq "CLI") {
        $script:UseGUI = $false
        if (-not $hasShares) { Initialize-Config-CLI }
        Start-CliMode
        return
    }
    elseif ($StartupMode -eq "GUI") {
        $script:UseGUI = $true
        if (-not $hasShares) { Initialize-Config-GUI }
        Show-GUI
        return
    }
}

# Otherwise, use saved preference if present
if ($hasShares) {
    switch ($cfg.Preferences.PreferredMode) {
        "CLI" {
            $script:UseGUI = $false
            Start-CliMode
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
        if (-not $hasShares) { Initialize-Config-CLI }
        Start-CliMode
    }
    "2" {
        $script:UseGUI = $true
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName Microsoft.VisualBasic
        if (-not $hasShares) { Initialize-Config-GUI }
        Show-GUI
    }
    default {
        Write-Host "Invalid. Defaulting to CLI v${version}." -ForegroundColor Yellow
        $script:UseGUI = $false
        if (-not $hasShares) { Initialize-Config-CLI }
        Start-CliMode
    }
}#endregion
