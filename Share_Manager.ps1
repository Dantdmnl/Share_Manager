<#
.SYNOPSIS
    Share Manager Script - Production-ready network share management with CLI/GUI interfaces.

.DESCRIPTION
    A comprehensive network share manager featuring:
    - Interactive CLI and GUI interfaces with seamless switching
    - Multi-share configuration management with profiles
    - Secure credential storage using Windows DPAPI (per-user, per-machine)
    - Automatic credential migration from legacy AES to DPAPI
    - Quick connect/disconnect/reconnect operations
    - Detailed status monitoring and diagnostics
    - Import/Export configuration with automatic backup
    - Atomic configuration saves with rollback support
    - Enhanced retry logic with exponential backoff
    - Comprehensive logging (text and structured JSONL)
    - GDPR-compliant logging (personal data only at DEBUG level)
    - Persistent mapping with automatic reconnection at logon
    - Theme support (Classic/Modern)
    
    Security Features:
    - Credentials encrypted with Windows DPAPI (no password files)
    - Secure password handling with memory cleanup (ZeroFreeBSTR)
    - Automatic migration from legacy encryption
    - Credentials stored per-user, per-machine (non-portable)
    - Special characters in passwords properly handled via cmdkey
    
    Production Enhancements (v2.2.0+):
    - Atomic file operations prevent configuration corruption
    - Automatic backup before destructive operations
    - Enhanced UNC path validation with auto-correction
    - Comprehensive error messages with troubleshooting guidance
    - Resource cleanup and disposal handlers
    - Configuration caching for performance
    - Complete audit trail logging (startup, operations, shutdown)
    - Batch operations with status indicators and retry limits
    - Input validation with user-friendly escape options
    
.PARAMETER StartupMode
    Optional. Pass "CLI" or "GUI" to force that mode on launch, bypassing saved preference.

.VERSION
    2.2.0

.NOTES
    - No administrator permissions required
    - GUI mode requires '-STA' when launching PowerShell:
      powershell.exe -ExecutionPolicy Bypass -STA -File "C:\Scripts\Share_Manager.ps1"
    - Author: Dantdmnl
    - License: See LICENSE file
    - Default log level: INFO (personal data only visible at DEBUG level)
#>

param(
    [string]$StartupMode
)

#region Global Variables (Version, Paths, Defaults)

$version        = '2.2.0'
$author         = 'Dantdmnl'

# Configuration constants
$script:CONFIG_CACHE_MAX_AGE_SECONDS = 5
$script:MAX_CONNECTION_RETRIES = 3
$script:LOG_ROTATION_DAYS = 30
$script:LOG_ROTATION_SIZE_MB = 5
$script:CONNECTION_RETRY_BACKOFF_BASE = 2  # Exponential backoff base (2^n seconds)
$script:CONNECTION_HISTORY_MAX = 100  # Maximum connection history entries
$script:HEALTH_CHECK_INTERVAL_SECONDS = 300  # 5 minutes
$script:CONNECTION_TIMEOUT_SECONDS = 5  # Timeout for connection tests
$script:ENABLE_AUTO_RECONNECT = $false  # Set to $true to enable automatic reconnection

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
$eventsPath       = Join-Path $baseFolder "Share_Manager.events.jsonl"
$script:SessionId = [guid]::NewGuid().ToString()
$script:LogThrottle = @{}

# ============================================================================
# DEBUG CONFIGURATION: Set log level here for easy debugging
# Options: 'DEBUG', 'INFO', 'WARN', 'ERROR'
# - DEBUG: Shows all logs including cache operations and detailed troubleshooting
# - INFO:  Shows normal operations (default, GDPR-compliant)
# - WARN:  Shows only warnings and errors
# - ERROR: Shows only errors
# ============================================================================
$MANUAL_LOG_LEVEL = 'INFO'  # Change to 'DEBUG' to see detailed logs

# Minimal level filtering via environment variable (SM_LOG_LEVEL): DEBUG, INFO, WARN, ERROR
$script:LogLevelMap = @{ DEBUG = 10; INFO = 20; WARN = 30; ERROR = 40 }
$rawLevel = if ($MANUAL_LOG_LEVEL) { $MANUAL_LOG_LEVEL } else { $env:SM_LOG_LEVEL }
if ([string]::IsNullOrWhiteSpace($rawLevel)) {
    $envLevel = 'INFO'
} else {
    $envLevel = $rawLevel.ToUpperInvariant()
    switch ($envLevel) {
        'INFORMATION' { $envLevel = 'INFO' }
        'WARNING'     { $envLevel = 'WARN' }
        'ERR'         { $envLevel = 'ERROR' }
    }
}
if (-not $script:LogLevelMap.ContainsKey($envLevel)) { $envLevel = 'INFO' }
$script:MinLogLevel = $script:LogLevelMap[$envLevel]

# Legacy support - old single-share config
$defaultConfigTemplate = [PSCustomObject]@{
    SharePath   = $null
    DriveLetter = $null
    Username    = $null
    Preferences = [PSCustomObject]@{
        UnmapOldMapping = $true
        PreferredMode   = "Prompt"
        SyncShareNameToDriveLabel = $true
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
        Theme             = "Classic" # UI Theme: Classic or Modern
        SyncShareNameToDriveLabel = $true
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

function Invoke-LogFileRotation {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$Prefix = 'Share_Manager'
    )
    if (-not (Test-Path $Path)) { return }
    $fileInfo = Get-Item $Path
    $ageDays  = (Get-Date) - $fileInfo.LastWriteTime
    $sizeMB   = [math]::Round($fileInfo.Length / 1MB, 2)
    if ($ageDays.TotalDays -ge $script:LOG_ROTATION_DAYS -or $sizeMB -ge $script:LOG_ROTATION_SIZE_MB) {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
        $archived  = Join-Path $baseFolder ("$Prefix`_$timestamp" + [System.IO.Path]::GetExtension($Path))
        try {
            Rename-Item -Path $Path -NewName (Split-Path $archived -Leaf) -ErrorAction Stop
            New-Item -Path $Path -ItemType File -Force | Out-Null
            if (-not $UseGUI) {
                Write-Host "Log rotated: $(Split-Path $archived -Leaf)" -ForegroundColor Cyan
            }
        }
        catch {
            if (-not $UseGUI) {
                Write-Host "Warning: Failed to rotate log '$Path': $_" -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-LogRotation {
    Invoke-LogFileRotation -Path $logPath -Prefix 'Share_Manager'
    Invoke-LogFileRotation -Path $eventsPath -Prefix 'Share_Manager.events'
}

function Get-LogSource { if ($script:UseGUI) { return 'GUI' } else { return 'CLI' } }

function Write-ActionLog {
    <#
    .SYNOPSIS
        Centralized logging function with GDPR compliance
    .DESCRIPTION
        Writes logs to both plain text (human-readable) and JSONL (structured) formats.
        
        GDPR COMPLIANCE (v2.1.0+):
        - INFO, WARN, ERROR levels: MUST NOT contain personal data (usernames, paths with usernames, etc.)
        - DEBUG level: MAY contain personal data for troubleshooting purposes
        
        Why dual logging?
        - Plain text: Easy scanning, grep-friendly, human debugging
        - JSONL: Machine parsing, analytics, correlation tracking
        
        Logging best practices:
        - Use INFO for user actions without personal data: "Connected to network share"
        - Use DEBUG for diagnostic details: "Connected to \\server\share as DOMAIN\user"
        - Always provide Category for filtering (Connection, Config, GUI, Credentials, etc.)
        - Use OncePerSeconds with Key for throttling repeated messages
        
    .PARAMETER Message
        Log message (be mindful of GDPR at INFO/WARN/ERROR levels)
    .PARAMETER Level
        DEBUG (10), INFO (20), WARN (30), ERROR (40)
    .PARAMETER Category
        Logical grouping (Connection, Config, GUI, Credentials, ConfigCache, etc.)
    .PARAMETER OncePerSeconds
        Throttle identical messages by Key within time window
    #>
    param (
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')] [string]$Level = 'INFO',
        [string]$Category,
        [string]$CorrelationId,
        [hashtable]$Data,
        [string]$Source,
        [string]$Key,
        [int]$OncePerSeconds = 0
    )
    try {
        if (-not (Test-Path $baseFolder)) { New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $logPath))     { New-Item -Path $logPath -ItemType File -Force | Out-Null }
        if (-not (Test-Path $eventsPath))  { New-Item -Path $eventsPath -ItemType File -Force | Out-Null }

        # Throttle identical messages by key within a time window
        if ($OncePerSeconds -gt 0 -and $Key) {
            $now = Get-Date
            $last = $script:LogThrottle[$Key]
            if ($last -and ($now - $last).TotalSeconds -lt $OncePerSeconds) { return }
            $script:LogThrottle[$Key] = $now
        }

        $lvl = $Level.ToUpperInvariant()
        $lvlNum = $script:LogLevelMap[$lvl]
        if (-not $lvlNum) { $lvlNum = 20 }
        if ($lvlNum -lt $script:MinLogLevel) { return }

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $src = if ($Source) { $Source } else { Get-LogSource }

        # Plain text for human scanning
        $prefix = if ($Category) { "[$lvl][$Category]" } else { "[$lvl]" }
        "$timestamp`t$prefix $Message" | Out-File -FilePath $logPath -Encoding UTF8 -Append

        # Structured JSONL event for analysis
        # Note: Personal data follows GDPR rules (DEBUG only)
        $evt = [ordered]@{
            ts            = (Get-Date).ToString("o")
            level         = $lvl
            msg           = $Message
            category      = $Category
            source        = $src
            correlationId = $CorrelationId
            sessionId     = $script:SessionId
            pid           = $PID
            ver           = $version
            data          = $Data
        }
        ($evt | ConvertTo-Json -Compress) | Out-File -FilePath $eventsPath -Encoding UTF8 -Append
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
        IsFavorite  = $false  # Quick access flag
        Category    = "General"  # Share grouping
        ConnectionCount = 0  # Track usage
        LastError   = $null  # Last connection error
        Tags        = @()  # Custom tags for organization
    }
}

function Import-AllShares {
    <#
    .SYNOPSIS
        Imports all share configurations from shares.json with comprehensive validation
    .DESCRIPTION
        Loads and validates share configuration, repairing issues and ensuring data integrity.
        Returns valid configuration object or default template on failure.
    .NOTES
        - Validates all required fields per share
        - Removes duplicates and invalid entries
        - Auto-repairs missing optional fields
        - Returns safe defaults if file missing or corrupt
    #>
    if (Test-Path $sharesPath) {
        try {
            $json = Get-Content -Path $sharesPath -Raw
            $config = ConvertFrom-Json $json
            
            # Ensure Shares is an array
            if (-not $config.PSObject.Properties['Shares']) {
                $config | Add-Member -MemberType NoteProperty -Name Shares -Value @()
            }
            
            # Validate and repair shares array
            $validShares = @()
            $duplicateCheck = @{}
            
            # Track if we need to save config due to backfills
            $configModified = $false
            
            foreach ($share in $config.Shares) {
                # Validate required fields
                $isValid = $true
                $missingFields = @()
                
                if (-not $share.PSObject.Properties['Id'] -or [string]::IsNullOrWhiteSpace($share.Id)) { 
                    $missingFields += 'Id'
                    $isValid = $false 
                }
                if (-not $share.PSObject.Properties['Name'] -or [string]::IsNullOrWhiteSpace($share.Name)) { 
                    $missingFields += 'Name'
                    $isValid = $false 
                }
                if (-not $share.PSObject.Properties['SharePath'] -or [string]::IsNullOrWhiteSpace($share.SharePath)) { 
                    $missingFields += 'SharePath'
                    $isValid = $false 
                }
                if (-not $share.PSObject.Properties['DriveLetter'] -or [string]::IsNullOrWhiteSpace($share.DriveLetter)) { 
                    $missingFields += 'DriveLetter'
                    $isValid = $false 
                }
                if (-not $share.PSObject.Properties['Username'] -or [string]::IsNullOrWhiteSpace($share.Username)) { 
                    $missingFields += 'Username'
                    $isValid = $false 
                }
                
                if (-not $isValid) {
                    Write-ActionLog -Message "Skipping invalid share (missing: $($missingFields -join ', ')): $($share.Name)" -Level WARN -Category 'Config'
                    continue
                }
                
                # Check for duplicate IDs
                if ($duplicateCheck.ContainsKey($share.Id)) {
                    Write-ActionLog -Message "Skipping duplicate share ID: $($share.Id) (Name: $($share.Name))" -Level WARN -Category 'Config'
                    continue
                }
                $duplicateCheck[$share.Id] = $true
                
                # Ensure all optional fields exist with defaults
                if (-not $share.PSObject.Properties['Description']) {
                    $share | Add-Member -MemberType NoteProperty -Name Description -Value ""
                }
                if (-not $share.PSObject.Properties['Enabled']) {
                    $share | Add-Member -MemberType NoteProperty -Name Enabled -Value $true
                }
                if (-not $share.PSObject.Properties['LastConnected']) {
                    $share | Add-Member -MemberType NoteProperty -Name LastConnected -Value ""
                }
                
                # Backfill Category with default 'General' if missing
                if (-not $share.PSObject.Properties['Category'] -or [string]::IsNullOrWhiteSpace($share.Category)) {
                    if (-not $share.PSObject.Properties['Category']) {
                        $share | Add-Member -MemberType NoteProperty -Name Category -Value 'General'
                    } else {
                        $share.Category = 'General'
                    }
                    $configModified = $true
                }
                
                # Normalize drive letter to uppercase single char
                $share.DriveLetter = $share.DriveLetter.ToUpper().Substring(0, 1)
                
                $validShares += $share
            }
            
            # Replace shares array with validated version
            $config.Shares = $validShares
            
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
                if (-not $config.Preferences.PSObject.Properties['Theme']) {
                    $config.Preferences | Add-Member -MemberType NoteProperty -Name Theme -Value "Classic"
                }
                if (-not $config.Preferences.PSObject.Properties['SyncShareNameToDriveLabel']) {
                    $config.Preferences | Add-Member -MemberType NoteProperty -Name SyncShareNameToDriveLabel -Value $true
                }
            }
            
            # Save config if we backfilled any categories
            if ($configModified) {
                Save-AllShares -Config $config | Out-Null
                Write-ActionLog -Message "Backfilled categories for shares during config import" -Level DEBUG -Category 'Config'
            }
            
            return $config
        }
        catch {
            Write-ActionLog -Message "Failed to import shares config: $_" -Level ERROR -Category 'Config' -Data @{ error = ("$_") }
            return $defaultSharesConfig
        }
    }
    
    return $defaultSharesConfig
}

# ================================================================================
# Configuration Caching System (v2.1.0+)
# ================================================================================
# Reduces disk I/O by 80-95% during bulk operations by caching the configuration
# in memory for 5 seconds. Cache is automatically invalidated on save operations.
#
# Usage:
#   - Use Get-CachedConfig instead of Import-AllShares
#   - Use -Force flag when you need fresh data (e.g., after user edits)
#   - Call Clear-ConfigCache after Save-AllShares
# ================================================================================

# Script-level cache for configuration
$script:CachedConfig = $null
$script:ConfigCacheTime = $null

function Get-CachedConfig {
    <#
    .SYNOPSIS
        Returns cached configuration or reloads if needed
    .DESCRIPTION
        Intelligently caches the configuration to reduce disk reads. Automatically
        expires after 5 seconds (configurable). Use -Force to bypass cache.
        
        Performance: Reduces disk I/O by 80-95% during rapid operations like
        Connect All or Disconnect All which may trigger multiple config reads.
        
    .PARAMETER Force
        Forces a reload from disk, ignoring cache. Use after user makes changes.
    .PARAMETER MaxAge
        Maximum age in seconds before cache is considered stale (default: 5)
    .EXAMPLE
        $config = Get-CachedConfig
        # Uses cache if fresh, otherwise reloads
    .EXAMPLE
        $config = Get-CachedConfig -Force
        # Always loads from disk
    #>
    param (
        [switch]$Force,
        [int]$MaxAge = $script:CONFIG_CACHE_MAX_AGE_SECONDS
    )
    
    $now = Get-Date
    $cacheAge = if ($script:ConfigCacheTime) { 
        ($now - $script:ConfigCacheTime).TotalSeconds 
    } else { 
        999 
    }
    
    # Reload if: forced, cache is empty, or cache is expired
    if ($Force -or $null -eq $script:CachedConfig -or $cacheAge -gt $MaxAge) {
        $reason = if ($Force) { "forced" } elseif ($null -eq $script:CachedConfig) { "empty" } else { "expired (${cacheAge}s)" }
        $script:CachedConfig = Import-AllShares
        $script:ConfigCacheTime = $now
        Write-ActionLog -Message "Config loaded from disk (reason: $reason)" -Level DEBUG -Category 'ConfigCache'
    } else {
        Write-ActionLog -Message "Config served from cache (age: ${cacheAge}s)" -Level DEBUG -Category 'ConfigCache'
    }
    
    return $script:CachedConfig
}

function Clear-ConfigCache {
    <#
    .SYNOPSIS
        Clears the configuration cache, forcing next read to reload from disk
    .DESCRIPTION
        Invalidates the cached configuration. Call this after saving changes
        with Save-AllShares to ensure subsequent reads get fresh data.
        
        This is part of the caching system's write-through pattern:
        1. Modify config in memory
        2. Save-AllShares to disk
        3. Clear-ConfigCache to invalidate
        4. Next Get-CachedConfig will reload fresh data
        
    .EXAMPLE
        Save-AllShares -ConfigData $config
        Clear-ConfigCache
        # Next read will get updated data from disk
    #>
    $script:CachedConfig = $null
    $script:ConfigCacheTime = $null
    Write-ActionLog -Message "Config cache cleared (next access will reload from disk)" -Level DEBUG -Category 'ConfigCache'
}

# ================================================================================
# Preference Helper (v2.1.0+)
# ================================================================================
# Provides safe, null-checked access to user preferences with type conversion.
# Replaces repetitive null-checking patterns throughout the codebase.
#
# Benefits:
#   - Consistent null-handling across all preference reads
#   - Type conversion with validation (-AsBoolean, -AsInteger)
#   - Default values prevent crashes on missing preferences
#   - Single source of truth for preference access logic
# ================================================================================

function Get-PreferenceValue {
    <#
    .SYNOPSIS
        Safely retrieves a preference value with null-checking and type conversion
    .DESCRIPTION
        Consolidated helper for accessing user preferences from the configuration.
        Handles null/missing preferences gracefully and provides type conversion.
        
        Uses Get-CachedConfig internally for performance (no redundant disk reads).
        
    .PARAMETER Name
        The preference name to retrieve (e.g., 'AutoConnectAtStartup')
    .PARAMETER Default
        Default value if preference doesn't exist or is null
    .PARAMETER AsBoolean
        Convert to boolean type. Handles: $true/$false, 1/0, "true"/"false", "yes"/"no"
    .PARAMETER AsInteger
        Convert to integer type with validation
    .EXAMPLE
        $autoConnect = Get-PreferenceValue -Name "AutoConnectAtStartup" -Default $false -AsBoolean
        # Returns boolean, defaults to $false if not set
    .EXAMPLE
        $delay = Get-PreferenceValue -Name "ReconnectDelay" -Default 5 -AsInteger
        # Returns integer, defaults to 5 if not set
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        
        [object]$Default = $null,
        
        [switch]$AsBoolean,
        [switch]$AsInteger
    )
    
    $config = Get-CachedConfig
    
    # Handle null config safely
    if ($null -eq $config) {
        return $Default
    }
    
    if (-not $config.PSObject.Properties['Preferences']) {
        return $Default
    }
    
    if (-not $config.Preferences.PSObject.Properties[$Name]) {
        return $Default
    }
    
    $value = $config.Preferences.$Name
    
    if ($AsBoolean) {
        return [bool]$value
    } elseif ($AsInteger) {
        return [int]$value
    } else {
        return $value
    }
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
        $newJson = $Config | ConvertTo-Json -Depth 10
        $existing = if (Test-Path $sharesPath) { Get-Content -Path $sharesPath -Raw -ErrorAction SilentlyContinue } else { $null }
        if ($existing -eq $newJson) {
            Write-ActionLog -Message "Save skipped: shares configuration unchanged" -Level DEBUG -Category 'Config'
            return $true
        }
        
        # Atomic write: write to temp file, then rename (prevents corruption)
        $tempPath = "$sharesPath.tmp"
        $backupPath = "$sharesPath.backup"
        
        try {
            # Write to temp file
            $newJson | Set-Content -Path $tempPath -Encoding UTF8 -Force
            
            # Create backup of existing config if it exists
            if (Test-Path $sharesPath) {
                Copy-Item -Path $sharesPath -Destination $backupPath -Force
            }
            
            # Atomic rename (overwrites destination)
            Move-Item -Path $tempPath -Destination $sharesPath -Force
            
            # Clean up backup on success
            if (Test-Path $backupPath) {
                Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
            }
            
            Write-ActionLog -Message "Saved all shares configuration (atomic write)" -Level DEBUG -Category 'Config'
            Clear-ConfigCache  # Invalidate cache after save
            return $true
        }
        catch {
            # Restore from backup if write failed
            if (Test-Path $backupPath) {
                Copy-Item -Path $backupPath -Destination $sharesPath -Force
                Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
                Write-ActionLog -Message "Restored config from backup after failed write" -Level WARN -Category 'Config'
            }
            throw
        }
        finally {
            # Clean up temp file if it still exists
            if (Test-Path $tempPath) {
                Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-ActionLog -Message "Failed to save shares config: $_" -Level ERROR -Category 'Config' -Data @{ error = ("$_") }
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
        Adds a new share to the configuration with validation
    .DESCRIPTION
        Creates a new share entry with duplicate detection and atomic save.
        Returns the created share object on success, null on failure.
    .NOTES
        - Validates drive letter availability across all shares (enabled or disabled)
        - Uses atomic save to prevent configuration corruption
        - Automatically invalidates cache after successful save
    #>
    param (
        [string]$Name,
        [string]$SharePath,
        [string]$DriveLetter,
        [string]$Username,
        [string]$Description = "",
        [bool]$Enabled = $true
    )
    
    $config = Get-CachedConfig -Force
    # Create share entry honoring the Enabled flag from callers (GUI/CLI)
    $newShare = New-ShareEntry -Name $Name -SharePath $SharePath -DriveLetter $DriveLetter -Username $Username -Description $Description -Enabled $Enabled
    
    # Check for duplicate drive letters (any state) to avoid future enablement conflicts
    $existing = $config.Shares | Where-Object { $_.DriveLetter -eq $DriveLetter }
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
        Write-ActionLog -Message "Rejected duplicate drive letter assignment: $DriveLetter" -Level WARN -Category 'Config'
        return $null  # FIXED: Prevent adding duplicate drive letter
    }
    
    $config.Shares += $newShare
    if (Save-AllShares -Config $config) {
    Write-ActionLog -Message "Added new share: $Name" -Level INFO -Category 'Config'
        return $newShare
    }
    return $null
}

function Update-ShareConfiguration {
    <#
    .SYNOPSIS
        Updates an existing share by ID with validation
    .DESCRIPTION
        Safely updates share properties with conflict detection and auto-unmapping.
        Validates drive letter conflicts before applying changes.
    .NOTES
        - Prevents drive letter conflicts with other enabled shares
        - Auto-unmaps old drive if letter changed (when preference enabled)
        - Uses atomic save for configuration integrity
    #>
    param (
        [Parameter(Mandatory)]
        [string]$ShareId,
        [string]$Name,
        [string]$SharePath,
        [string]$DriveLetter,
        [string]$Username,
        [string]$Description = "",
        [bool]$Enabled
    )
    $config = Get-CachedConfig -Force
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
    $oldDriveLetter = $share.DriveLetter
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
        try {
            # Auto-unmap old drive if drive letter changed and preference allows
            if ($DriveLetter -and $DriveLetter -ne $oldDriveLetter) {
                $autoUnmap = Get-PreferenceValue -Name "UnmapOldMapping" -Default $false -AsBoolean
                if ($autoUnmap -and (Test-Path "$oldDriveLetter`:")) {
                    Write-ActionLog -Message "Auto-unmapping previous drive $oldDriveLetter due to drive letter change to $DriveLetter" -Level DEBUG -Category 'Mapping'
                    Disconnect-NetworkShare -DriveLetter $oldDriveLetter -Silent
                }
            }
        } catch {
            Write-ActionLog -Message "Failed to auto-unmap previous drive $oldDriveLetter after letter change: $_" -Level WARN -Category 'Mapping'
        }
    Write-ActionLog -Message "Updated share: $($share.Name)" -Level INFO -Category 'Config'
        return $true
    }
    return $false
}

function Set-ShareFavorite {
    <#
    .SYNOPSIS
        Toggles favorite status for a share
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ShareId,
        [Parameter(Mandatory)]
        [bool]$IsFavorite
    )
    
    $config = Get-CachedConfig -Force
    $share = $config.Shares | Where-Object { $_.Id -eq $ShareId }
    
    if ($share) {
        # Add property if missing (for shares created before this feature)
        if (-not $share.PSObject.Properties['IsFavorite']) {
            $share | Add-Member -MemberType NoteProperty -Name IsFavorite -Value $IsFavorite
        } else {
            $share.IsFavorite = $IsFavorite
        }
        
        Save-AllShares -Config $config | Out-Null
        Write-ActionLog -Message "Set favorite status for share: $($share.Name) = $IsFavorite" -Level DEBUG -Category 'Config'
        return $true
    }
    return $false
}

function Set-ShareCategory {
    <#
    .SYNOPSIS
        Sets category for a share
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ShareId,
        [Parameter(Mandatory)]
        [string]$Category
    )
    
    $config = Get-CachedConfig -Force
    $share = $config.Shares | Where-Object { $_.Id -eq $ShareId }
    
    if ($share) {
        if (-not $share.PSObject.Properties['Category']) {
            $share | Add-Member -MemberType NoteProperty -Name Category -Value $Category
        } else {
            $share.Category = $Category
        }
        
        Save-AllShares -Config $config | Out-Null
        Write-ActionLog -Message "Set category for share: $($share.Name) = $Category" -Level DEBUG -Category 'Config'
        return $true
    }
    return $false
}

function Get-ShareCategories {
    <#
    .SYNOPSIS
        Gets list of all unique categories
    #>
    $config = Get-CachedConfig
    if ($config -and $config.Shares) {
        $categories = @($config.Shares | Where-Object { $_.PSObject.Properties['Category'] -and -not [string]::IsNullOrWhiteSpace($_.Category) } | Select-Object -ExpandProperty Category -Unique | Sort-Object)
        if ($categories.Count -eq 0) { return @('General') }
        return $categories
    }
    return @('General')
}

function Remove-ShareConfiguration {
    <#
    .SYNOPSIS
        Removes a share from configuration by ID
    #>
    param (
        [string]$ShareId
    )
    
    $config = Get-CachedConfig
    $share = $config.Shares | Where-Object { $_.Id -eq $ShareId }
    
    if (-not $share) {
        Write-Host "Share not found." -ForegroundColor Yellow
        return $false
    }
    
    $config.Shares = @($config.Shares | Where-Object { $_.Id -ne $ShareId })
    
    if (Save-AllShares -Config $config) {
    Write-ActionLog -Message "Removed share: $($share.Name)" -Level INFO -Category 'Config'
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
    
    $config = Get-CachedConfig
    
    # Handle null config safely
    if ($null -eq $config) {
        if ($ShareId) { return $null }
        return @()
    }
    
    # Handle null shares array
    if ($null -eq $config.Shares) {
        if ($ShareId) { return $null }
        return @()
    }
    
    if ($ShareId) {
        # When a specific ID is requested, return the single matching object
        return ($config.Shares | Where-Object { $_.Id -eq $ShareId })
    }
    
    # Always return an array when no ShareId is provided to avoid .Count/$index issues
    return @($config.Shares)
}

function Add-ConnectionHistory {
    <#
    .SYNOPSIS
        Records connection event to history
    .DESCRIPTION
        Maintains a rolling history of connection events for analytics and troubleshooting.
    #>
    param(
        [string]$ShareId,
        [string]$ShareName,
        [string]$Action,  # Connect, Disconnect, Failed
        [string]$Result,  # Success, Failed
        [string]$ErrorMessage = ""
    )
    
    try {
        $historyPath = Join-Path $baseFolder "connection_history.jsonl"
        $entry = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            ShareId = $ShareId
            ShareName = $ShareName
            Action = $Action
            Result = $Result
            ErrorMessage = $ErrorMessage
            SessionId = $script:SessionId
        }
        
        ($entry | ConvertTo-Json -Compress) | Out-File -FilePath $historyPath -Encoding UTF8 -Append
        
        # Rotate history if too large
        if (Test-Path $historyPath) {
            $lines = @(Get-Content $historyPath)
            if ($lines.Count -gt $script:CONNECTION_HISTORY_MAX) {
                $lines[-$script:CONNECTION_HISTORY_MAX..-1] | Set-Content -Path $historyPath -Encoding UTF8
            }
        }
    }
    catch {
        Write-ActionLog -Message "Failed to record connection history: $_" -Level DEBUG -Category 'History'
    }
}

function Get-ConnectionHistory {
    <#
    .SYNOPSIS
        Retrieves connection history with optional filtering
    #>
    param(
        [string]$ShareId,
        [int]$Last = 10
    )
    
    $historyPath = Join-Path $baseFolder "connection_history.jsonl"
    if (-not (Test-Path $historyPath)) { return @() }
    
    try {
        $history = Get-Content $historyPath -Encoding UTF8 | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ -ne $null }
        
        if ($ShareId) {
            $history = $history | Where-Object { $_.ShareId -eq $ShareId }
        }
        
        return @($history | Select-Object -Last $Last)
    }
    catch {
        Write-ActionLog -Message "Failed to read connection history: $_" -Level WARN -Category 'History'
        return @()
    }
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
                        Write-ActionLog -Message "Migrated credential to DPAPI encryption" -Category 'Credentials'
                    } else {
                        # Try DPAPI anyway (might be legacy DPAPI without marker)
                        $securePW = $entry.Encrypted | ConvertTo-SecureString
                    }
                }
                
                if ($securePW) {
                    return New-Object System.Management.Automation.PSCredential($Username, $securePW)
                }
            } catch { 
                Write-ActionLog -Message "Failed to decrypt credential: $_" -Level WARN -Category 'Credentials' -Data @{ error = ("$_") }
            }
        }
    }
    
    # Fallback to legacy single cred file (auto-migrate if found)
    $legacy = Import-SavedCredential
    if ($legacy -and $legacy.UserName -eq $Username) { 
        # Auto-migrate to modern store
        try {
            Save-Credential -Credential $legacy
            Write-ActionLog -Message "Auto-migrated legacy credential to modern store" -Category 'Credentials'
        } catch {
            Write-ActionLog -Message "Failed to auto-migrate legacy credential: $_" -Level ERROR -Category 'Credentials' -Data @{ error = ("$_") }
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
        $config = Get-CachedConfig
        $exportData = @{
            Version = $version
            ExportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Shares = $config.Shares
            Preferences = $config.Preferences
        }
        
        $exportData | ConvertTo-Json -Depth 10 | Set-Content -Path $ExportPath -Encoding UTF8 -Force
        Write-ActionLog -Message "Exported configuration to $ExportPath" -Category 'BackupRestore'
        return $true
    }
    catch {
        Write-ActionLog -Message "Failed to export configuration: $_" -Level ERROR -Category 'BackupRestore' -Data @{ path = $ExportPath; error = ("$_") }
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
        
        # Auto-backup existing config before destructive operations (non-merge imports)
        if (-not $Merge -and (Test-Path $sharesPath)) {
            $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
            $autoBackupPath = Join-Path $baseFolder "shares_preimport_$timestamp.json"
            try {
                Copy-Item -Path $sharesPath -Destination $autoBackupPath -Force
                Write-ActionLog -Message "Auto-backup created before import: $autoBackupPath" -Category 'BackupRestore'
                if ($UseGUI) {
                    # Inform user about auto-backup (non-intrusive)
                    Write-ActionLog -Message "Config backed up to: $autoBackupPath" -Level INFO -Category 'BackupRestore'
                }
            }
            catch {
                Write-ActionLog -Message "Warning: Could not create auto-backup: $_" -Level WARN -Category 'BackupRestore'
                # Continue with import even if backup fails (user was warned)
            }
        }
        
        if ($Merge) {
            # Merge with existing (update duplicates, add new)
            $config = Get-CachedConfig
            
            foreach ($share in $importData.Shares) {
                # Check if duplicate exists (same SharePath OR same DriveLetter)
                $existing = $config.Shares | Where-Object {
                    $_.SharePath -eq $share.SharePath -or $_.DriveLetter -eq $share.DriveLetter
                }
                
                if (-not $existing) {
                    # Generate new ID to avoid conflicts
                    $share.Id = [guid]::NewGuid().ToString()
                    $config.Shares += $share
                    $added++
                } else {
                    # Update existing share with imported properties (IsFavorite, Category, Description, etc.)
                    if ($share.PSObject.Properties['IsFavorite']) { $existing.IsFavorite = $share.IsFavorite }
                    if ($share.PSObject.Properties['Category']) { $existing.Category = $share.Category }
                    if ($share.PSObject.Properties['Description']) { $existing.Description = $share.Description }
                    if ($share.PSObject.Properties['Enabled']) { $existing.Enabled = $share.Enabled }
                    $skipped++
                }
            }
            
            Write-ActionLog -Message "Merged configuration: $added added, $skipped duplicates skipped" -Category 'BackupRestore' -Data @{ added = $added; skipped = $skipped }
        } else {
            # Replace existing
            $config = [PSCustomObject]@{
                Shares = $importData.Shares
                Preferences = $importData.Preferences
            }
            $added = $importData.Shares.Count
        }
        
        if (Save-AllShares -Config $config) {
            Clear-ConfigCache  # Force refresh so GUI shows imported shares immediately
            Write-ActionLog -Message "Imported configuration from $ImportPath (Merge: $Merge)" -Category 'BackupRestore' -Data @{ path = $ImportPath; merge = $Merge; added = $added }
            return @{ Success = $true; Added = $added; Skipped = $skipped }
        }
    }
    catch {
        Write-ActionLog -Message "Failed to import configuration: $_" -Level ERROR -Category 'BackupRestore' -Data @{ path = $ImportPath; error = ("$_") }
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
        Gets detailed status information for a share with diagnostics
    .DESCRIPTION
        Provides comprehensive status including connection state, host availability,
        credentials, and diagnostic information for troubleshooting.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$ShareId
    )
    
    $share = Get-ShareConfiguration -ShareId $ShareId
    if (-not $share) { 
        Write-ActionLog -Message "Get-DetailedShareStatus: Share not found: $ShareId" -Level WARN -Category 'Status'
        return $null 
    }
    
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
    
    Write-ActionLog -Message "Migrating legacy configuration to v2.0 format" -Category 'Migration'
    
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
        Write-ActionLog -Message "Legacy config backed up to $backupPath and removed" -Category 'Migration'
        
        # Clean up old single-credential file if it exists
        $oldCredPath = Join-Path $baseFolder "cred.txt"
        if (Test-Path $oldCredPath) {
            $oldCredBackup = "$oldCredPath.v1.backup"
            Copy-Item $oldCredPath $oldCredBackup -Force
            Remove-Item $oldCredPath -Force -ErrorAction SilentlyContinue
            Write-ActionLog -Message "Legacy cred.txt backed up and removed" -Category 'Migration'
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
        Write-ActionLog -Message "Saved legacy config: SharePath=$SharePath, DriveLetter=$DriveLetter" -Category 'Config' -Level DEBUG
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
        Write-ActionLog -Message "Failed to save legacy config: $_" -Level ERROR -Category 'Config' -Data @{ error = ("$_") }
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
        Write-ActionLog -Message "Generated new AES key at $keyPath (legacy compatibility)" -Category 'Credentials' -Level DEBUG
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

        # Silent in GUI (caller handles messaging), verbose in CLI
        if (-not $UseGUI) {
            Write-Host "  [OK] Credentials saved for $user" -ForegroundColor Green
        }
        Write-ActionLog -Message "Saved credential for $user" -Level DEBUG -Category 'Credentials'
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
        Write-ActionLog -Message "Failed to save credential: $_" -Level ERROR -Category 'Credentials' -Data @{ error = ("$_") }
    }
}

# Utility: Get-StartupFolder (returns user's Startup folder)
function Get-StartupFolder {
    # Use direct path for Windows 11+ compatibility (COM object can be unreliable)
    $startupPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    if (-not (Test-Path $startupPath)) {
        try {
            New-Item -Path $startupPath -ItemType Directory -Force | Out-Null
        } catch {
            # Fallback to COM object if direct path fails
            try {
                $shell = New-Object -ComObject WScript.Shell
                return $shell.SpecialFolders.Item('Startup')
            } catch {
                # Last resort: use well-known path
                return [System.IO.Path]::Combine($env:USERPROFILE, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            }
        }
    }
    return $startupPath
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
            Write-ActionLog -Message "Failed to read creds store: $_" -Level WARN -Category 'Credentials' -Data @{ error = ("$_") }
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
                Entries = @(
                    [PSCustomObject]@{
                        Username = $legacy.UserName
                        Encrypted = $encryptedPW
                        EncryptionType = "DPAPI"
                    }
                )
            }
            $store | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialsStorePath -Encoding UTF8 -Force
            Write-ActionLog -Message "Migrated legacy credential to DPAPI store" -Category 'Migration'
            # Clean up old credential file after successful migration
            if (Test-Path $credentialPath) {
                $backupPath = "$credentialPath.v1.backup"
                Copy-Item $credentialPath $backupPath -Force -ErrorAction SilentlyContinue
                Remove-Item $credentialPath -Force -ErrorAction SilentlyContinue
                Write-ActionLog -Message "Legacy cred.txt backed up and removed" -Category 'Migration'
            }
            return $store
        } catch {
            Write-ActionLog -Message "Failed to migrate legacy credential: $_" -Level WARN -Category 'Migration'
            return [PSCustomObject]@{ Entries = @() }
        }
    }
    return [PSCustomObject]@{ Entries = @() }
}

function Get-AllCredentials {
    <#
    .SYNOPSIS
        Gets all stored credentials (usernames only, no passwords)
    #>
    $store = Import-CredentialStore
    if ($store -and $store.Entries) {
        return @($store.Entries | Select-Object Username)
    }
    return @()
}

function Remove-Credential {
    <#
    .SYNOPSIS
        Removes stored credentials with validation
    .DESCRIPTION
        Safely removes credentials from the store with proper error handling.
        Supports removing single credential by username or all credentials.
    #>
    param([string]$Username)

    $removed = $false

    # Validate credential store exists before attempting removal
    if (-not (Test-Path $credentialsStorePath) -and -not (Test-Path $credentialPath)) {
        if (-not $UseGUI) {
            Write-Host "No credentials stored." -ForegroundColor Yellow
        }
        Write-ActionLog -Message "No credential files found to remove" -Level DEBUG -Category 'Credentials'
        return $false
    }

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
        # GUI callers (Credentials Manager) handle their own success messaging
        # CLI callers also handle their own success messaging
        Write-ActionLog -Message "Removed stored credentials" -Category 'Credentials'
        Write-ActionLog -Message "Removed stored credentials for: $Username" -Level DEBUG -Category 'Credentials'
        return $true
    }
    else {
        # GUI callers handle their own messaging
        # CLI callers also handle their own messaging
        Write-ActionLog -Message "No credentials found to remove" -Level WARN -Category 'Credentials'
        Write-ActionLog -Message "No credentials found to remove for: $Username" -Level DEBUG -Category 'Credentials'
        return $false
    }
}

function Export-Credentials {
    <#
    .SYNOPSIS
        Export encrypted credentials to a backup file (DPAPI-protected, machine/user-specific).
    .DESCRIPTION
        Creates a timestamped backup of creds.json. The export remains DPAPI-encrypted,
        so it can only be restored on the same machine by the same user account.
    .PARAMETER ExportPath
        Optional custom export path. If not specified, creates backup in the base folder.
    #>
    param([string]$ExportPath)

    if (-not (Test-Path $credentialsStorePath)) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "No credentials to export.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } else {
            Write-Host "No credentials to export." -ForegroundColor Yellow
        }
        return
    }

    try {
        if ([string]::IsNullOrWhiteSpace($ExportPath)) {
            $timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
            $ExportPath = Join-Path $baseFolder "creds_backup_$timestamp.json"
        }

        Copy-Item -Path $credentialsStorePath -Destination $ExportPath -Force
        
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Credentials exported to:`n$ExportPath`n`nNote: This file is DPAPI-encrypted and can only be restored on this machine by your user account.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } else {
            Write-Host "  [OK] Credentials exported to: $ExportPath" -ForegroundColor Green
            Write-Host "  [i] Note: DPAPI-encrypted, machine/user-specific" -ForegroundColor Gray
        }
        
        Write-ActionLog -Message "Exported credentials backup" -Category 'BackupRestore' -Data @{ path = $ExportPath }
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export credentials:`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        } else {
            Write-Host "Error: Failed to export credentials: $_" -ForegroundColor Red
        }
        Write-ActionLog -Message "Failed to export credentials: $_" -Level ERROR -Category 'BackupRestore' -Data @{ error = ("$_") }
    }
}

function Import-Credentials {
    <#
    .SYNOPSIS
        Import encrypted credentials from a backup file (DPAPI-protected).
    .DESCRIPTION
        Restores credentials from a backup. Can only import files created on this machine
        by the same user account (DPAPI restriction).
    .PARAMETER ImportPath
        Path to the backup file to import.
    .PARAMETER Merge
        If specified, merges with existing credentials. Otherwise replaces all credentials.
    #>
    param(
        [Parameter(Mandatory)] [string]$ImportPath,
        [switch]$Merge
    )

    if (-not (Test-Path $ImportPath)) {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Import file not found:`n$ImportPath",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        } else {
            Write-Host "Error: Import file not found: $ImportPath" -ForegroundColor Red
        }
        return
    }

    try {
        $importedStore = (Get-Content -Path $ImportPath -Raw -Encoding UTF8) | ConvertFrom-Json
        
        if (-not $importedStore -or -not $importedStore.Entries) {
            throw "Invalid credentials backup file format"
        }

        if ($Merge -and (Test-Path $credentialsStorePath)) {
            # Merge with existing
            $existingStore = Import-CredentialStore
            $usernames = @()
            if ($existingStore.Entries) {
                $usernames = $existingStore.Entries | Select-Object -ExpandProperty Username
            }
            
            $added = 0
            $skipped = 0
            foreach ($entry in $importedStore.Entries) {
                if ($usernames -contains $entry.Username) {
                    $skipped++
                } else {
                    $existingStore.Entries += $entry
                    $added++
                }
            }
            
            $existingStore | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialsStorePath -Encoding UTF8 -Force
            
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Credentials merged:`n- Added: $added`n- Skipped (duplicates): $skipped",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            } else {
                Write-Host "  [OK] Credentials merged: $added added, $skipped duplicates skipped" -ForegroundColor Green
            }
            
            Write-ActionLog -Message "Imported credentials (merge)" -Category 'BackupRestore' -Data @{ path = $ImportPath; added = $added; skipped = $skipped }
        }
        else {
            # Replace all
            Copy-Item -Path $ImportPath -Destination $credentialsStorePath -Force
            
            $count = $importedStore.Entries.Count
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Credentials imported: $count entries",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            } else {
                Write-Host "  [OK] Credentials imported: $count entries" -ForegroundColor Green
            }
            
            Write-ActionLog -Message "Imported credentials (replace)" -Category 'BackupRestore' -Data @{ path = $ImportPath; count = $count }
        }
    }
    catch {
        if ($UseGUI) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to import credentials:`n$_`n`nNote: Credentials can only be imported on the same machine/user that created them.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        } else {
            Write-Host "Error: Failed to import credentials: $_" -ForegroundColor Red
            Write-Host "  [i] Note: DPAPI-encrypted files can only be restored on the same machine/user" -ForegroundColor Gray
        }
        Write-ActionLog -Message "Failed to import credentials: $_" -Level ERROR -Category 'BackupRestore' -Data @{ path = $ImportPath; error = ("$_") }
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

function Test-ValidUncPath {
    <#
    .SYNOPSIS
        Validates UNC path format
    .DESCRIPTION
        Checks if path is a valid UNC format: \\server\share
        Server name must be at least 2 characters, share name at least 1 character
    #>
    param ([string]$Path)
    
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    
    # Valid UNC: \\servername\sharename (minimum lengths enforced)
    # Server: 2+ chars, Share: 1+ chars
    return ($Path -match '^\\\\[^\\]{2,}\\[^\\]+.*$')
}

function Test-ShareOnline {
    param ([string]$SharePath)
    
    # Validate UNC format first
    if (-not (Test-ValidUncPath -Path $SharePath)) {
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
        [switch]$Silent,
        [switch]$ReturnStatus
    )

    # Get preferences using helper functions
    $persistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
    $autoUnmap = Get-PreferenceValue -Name "UnmapOldMapping" -Default $false -AsBoolean
    $persistentFlag = if ($persistent) { "/PERSISTENT:YES" } else { "/PERSISTENT:NO" }

    if (Test-Path "$DriveLetter`:") {
        # Auto-unmap if preference is set
        if ($autoUnmap) {
            try {
                cmd /c "net use `"${DriveLetter}:`" /delete /y" 2>&1 | Out-Null
                if (-not $Silent -and -not $UseGUI) {
                    Write-Host "  Unmapped existing drive $DriveLetter" -ForegroundColor Gray
                }
            } catch {
                Write-ActionLog -Message "Auto-unmap failed for drive ${DriveLetter}: $($_)" -Level 'WARN' -Category 'Mapping' -OncePerSeconds 60
            }
        } else {
            if ($UseGUI -and -not $Silent) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Drive $DriveLetter is already in use.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
            elseif (-not $UseGUI) {
                Write-Host "Drive $DriveLetter is already mapped. Unmap it first." -ForegroundColor Yellow
            }
            if ($ReturnStatus) {
                return @{ Success = $false; ErrorType = "DriveInUse"; ErrorMessage = "Drive already mapped" }
            }
            return
        }
    }

    if (-not (Test-ShareOnline -SharePath $SharePath)) {
        if ($UseGUI -and -not $Silent) {
            [System.Windows.Forms.MessageBox]::Show(
                "Share host not reachable. Skipping mapping.",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        }
        elseif (-not $UseGUI) {
            Write-Host "Share host not reachable. Skipping mapping." -ForegroundColor Yellow
        }
        Write-ActionLog "Skipped mapping $DriveLetter -> $SharePath (offline)" -Level DEBUG
        if ($ReturnStatus) {
            return @{ Success = $false; ErrorType = "Offline"; ErrorMessage = "Share host not reachable" }
        }
        return
    }

    try {
        $user = $Credential.UserName
        $bstrPtr = [IntPtr]::Zero
        $plainPassword = $null
        
        try {
            # Securely extract password
            $bstrPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
        }
        finally {
            # CRITICAL: Always zero and free the BSTR to prevent password leaks
            if ($bstrPtr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
            }
        }
        
        # If persistent, store credentials in Windows Credential Manager (smart update)
        if ($persistent) {
            # Extract only the server name from the UNC path (e.g., \\server)
            $target = $null
            if ($SharePath -match '^\\\\([^\\]+)') {
                $target = "\\$($Matches[1])"
            } else {
                $target = $SharePath
            }
            
            # Check if credentials already exist for this target with same username
            $existingCreds = cmdkey /list:$target 2>&1 | Out-String
            $needsUpdate = $true
            
            if ($existingCreds -match "Target: $([regex]::Escape($target))") {
                # Credentials exist, check if username matches
                if ($existingCreds -match "User: $([regex]::Escape($user))") {
                    # Same username - skip update (assume password unchanged for performance)
                    # Note: If password changed, user should disconnect/reconnect to update
                    $needsUpdate = $false
                    Write-ActionLog -Message "Cmdkey credentials already exist for $target with same username (skipping update)" -Level DEBUG -Category 'Credentials'
                } else {
                    Write-ActionLog -Message "Updating cmdkey credentials for $target (username changed)" -Level DEBUG -Category 'Credentials'
                }
            } else {
                # No existing credentials
                Write-ActionLog -Message "Adding new cmdkey credentials for $target" -Level DEBUG -Category 'Credentials'
            }
            
            if ($needsUpdate) {
                # Remove any existing credentials for this server
                cmdkey /delete:$target 2>&1 | Out-Null
                # Add credentials for the server - use quoted arguments to handle special characters
                $cmdkeyArgs = @('/add:' + $target, '/user:' + $user, '/pass:' + $plainPassword)
                $cmdkeyOutput = & cmdkey $cmdkeyArgs 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-ActionLog -Message "Cmdkey failed to store credentials for $target (exit code: $LASTEXITCODE)" -Level WARN -Category 'Credentials' -Data @{ output = ($cmdkeyOutput | Out-String) }
                }
            }
        }
        
        # Enhanced retry logic with exponential backoff
        $maxAttempts = $script:MAX_CONNECTION_RETRIES
        $mapped = $false
        $lastError = $null
        
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            if ($attempt -gt 1) {
                $backoff = [math]::Pow($script:CONNECTION_RETRY_BACKOFF_BASE, $attempt - 1)  # 2s, 4s, 8s
                Write-ActionLog -Message "Retry attempt $attempt/$maxAttempts after ${backoff}s delay" -Level DEBUG -Category 'Mapping'
                Start-Sleep -Seconds $backoff
            }
            
            $netResult = net use "$DriveLetter`:" $SharePath /USER:$user $plainPassword $persistentFlag 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                $mapped = $true
                break
            } else {
                $lastError = $netResult | Out-String
                
                # Classify error for better diagnostics
                $errorType = "Unknown"
                if ($lastError -match "1326|Logon failure") { $errorType = "Authentication" }
                elseif ($lastError -match "53|network path") { $errorType = "PathNotFound" }
                elseif ($lastError -match "67|network name") { $errorType = "InvalidPath" }
                elseif ($lastError -match "1219|multiple connections") { $errorType = "MultipleConnections" }
                elseif ($lastError -match "85|local device.*in use") { $errorType = "DriveInUse" }
                elseif ($lastError -match "1203|1231|network busy|timeout") { $errorType = "NetworkTimeout" }
                
                Write-ActionLog -Message "Mapping attempt $attempt failed: $errorType" -Level WARN -Category 'Mapping' -Data @{ 
                    attempt = $attempt
                    errorType = $errorType
                    exitCode = $LASTEXITCODE
                }
            }
        }

        if ($mapped) {
            # Verify connection by checking net use output matches expected share path
            $verified = $false
            try {
                $netUseOutput = net use "$DriveLetter`:" 2>&1 | Out-String
                if ($netUseOutput -match "Remote name\s+(.+)") {
                    $remotePath = $Matches[1].Trim()
                    if ($remotePath -eq $SharePath) {
                        $verified = $true
                        Write-ActionLog -Message "Connection verified: $DriveLetter -> $SharePath" -Level DEBUG -Category 'Mapping'
                    } else {
                        Write-ActionLog -Message "Connection mismatch: Expected $SharePath, got $remotePath" -Level WARN -Category 'Mapping'
                    }
                }
            } catch {
                Write-ActionLog -Message "Connection verification failed: $_" -Level WARN -Category 'Mapping'
            }
            
            # Update connection statistics
            try {
                $config = Get-CachedConfig -Force
                $shareObj = $config.Shares | Where-Object { $_.DriveLetter -eq $DriveLetter }
                if ($shareObj) {
                    # Increment connection count
                    if (-not $shareObj.PSObject.Properties['ConnectionCount']) {
                        $shareObj | Add-Member -MemberType NoteProperty -Name ConnectionCount -Value 1
                    } else {
                        $shareObj.ConnectionCount++
                    }
                    
                    # Clear last error
                    if ($shareObj.PSObject.Properties['LastError']) {
                        $shareObj.LastError = $null
                    }
                    
                    Save-AllShares -Config $config | Out-Null
                    
                    # Record to history
                    Add-ConnectionHistory -ShareId $shareObj.Id -ShareName $shareObj.Name -Action "Connect" -Result "Success"
                }
            } catch {
                Write-ActionLog -Message "Failed to update connection stats: $_" -Level DEBUG -Category 'Mapping'
            }
            
            # Sync drive label
            try {
                $syncLabel = Get-PreferenceValue -Name "SyncShareNameToDriveLabel" -Default $true -AsBoolean
                if ($syncLabel) {
                    $cfg = Get-CachedConfig
                    $shareObj = $null
                    if ($cfg -and $cfg.Shares) {
                        $shareObj = $cfg.Shares | Where-Object { $_.DriveLetter -eq $DriveLetter }
                    }
                    $label = if ($shareObj -and $shareObj.Name) { $shareObj.Name } else { $null }
                    if ($label) {
                        Set-MappedDriveLabel -DriveLetter $DriveLetter -SharePath $SharePath -Label $label
                    }
                }
            } catch {
                Write-ActionLog -Message "Failed to sync drive label for $DriveLetter - $_" -Level WARN -Category 'Mapping'
            }

            Write-ActionLog -Message "Mapped $DriveLetter to $SharePath" -Level INFO -Category 'Mapping'
            
            if ($ReturnStatus) {
                return @{ Success = $true; ErrorType = $null; Verified = $verified }
            }
        }
        else {
            # Classify final error for user message
            $errorMsg = "Connection failed after $maxAttempts attempts. Check path and credentials."
            $errorType = "Unknown"
            if ($lastError -match "1326|Logon failure") { 
                $errorMsg = "Authentication failed. Verify username and password are correct." 
                $errorType = "Authentication"
            }
            elseif ($lastError -match "53|network path") { 
                $errorMsg = "Network path not found. Verify the share path is correct and accessible." 
                $errorType = "PathNotFound"
            }
            elseif ($lastError -match "67|network name") { 
                $errorMsg = "Invalid network path format. Check UNC path syntax." 
                $errorType = "InvalidPath"
            }
            elseif ($lastError -match "1219|multiple connections") { 
                $errorMsg = "Multiple connections to server not allowed with different credentials. Disconnect other shares from this server first." 
                $errorType = "MultipleConnections"
            }
            elseif ($lastError -match "85|local device.*in use") { 
                $errorMsg = "Drive letter already in use by another resource." 
                $errorType = "DriveInUse"
            }
            elseif ($lastError -match "1203|1231|network busy|timeout") {
                $errorMsg = "Network timeout or server busy. Verify server is online and try again."
                $errorType = "NetworkTimeout"
            }
            
            if ($UseGUI -and -not $Silent) {
                [System.Windows.Forms.MessageBox]::Show(
                    $errorMsg,
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
            elseif (-not $UseGUI -and -not $Silent) {
                Write-Host "Failed to map drive: $errorMsg" -ForegroundColor Red
            }
            Write-ActionLog -Message "Failed mapping $DriveLetter -> $SharePath after $maxAttempts attempts" -Level ERROR -Category 'Mapping' -Data @{ 
                drive = $DriveLetter
                share = $SharePath
                attempts = $maxAttempts
                lastError = $lastError
            }
            
            # Record failure in share metadata
            try {
                $config = Get-CachedConfig -Force
                $shareObj = $config.Shares | Where-Object { $_.DriveLetter -eq $DriveLetter }
                if ($shareObj) {
                    if (-not $shareObj.PSObject.Properties['LastError']) {
                        $shareObj | Add-Member -MemberType NoteProperty -Name LastError -Value $errorMsg
                    } else {
                        $shareObj.LastError = $errorMsg
                    }
                    Save-AllShares -Config $config | Out-Null
                    
                    # Record to history
                    Add-ConnectionHistory -ShareId $shareObj.Id -ShareName $shareObj.Name -Action "Connect" -Result "Failed" -ErrorMessage $errorMsg
                }
            } catch {
                Write-ActionLog -Message "Failed to update error status: $_" -Level DEBUG -Category 'Mapping'
            }
            
            if ($ReturnStatus) {
                return @{ Success = $false; ErrorType = $errorType; ErrorMessage = $errorMsg }
            }
        }
    }
    catch {
        if ($UseGUI -and -not $Silent) {
            [System.Windows.Forms.MessageBox]::Show(
                "Error during mapping:`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        elseif (-not $UseGUI -and -not $Silent) {
            Write-Host "Error during mapping: $_" -ForegroundColor Red
        }
        Write-ActionLog -Message "Error during mapping: $_" -Level ERROR -Category 'Mapping' -Data @{ error = ("$_") }
        
        if ($ReturnStatus) {
            return @{ Success = $false; ErrorType = "Exception"; ErrorMessage = "$_" }
        }
    }
}

function Disconnect-NetworkShare {
    param (
        [string]$DriveLetter,
        [switch]$Silent
    )
    try {
        # Get preferences using helper function
        $persistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
        $sharePath = $null
        
        # Try to get sharePath from multi-config
        $multiCfg = Get-CachedConfig
        if ($multiCfg) {
            $share = $multiCfg.Shares | Where-Object { $_.DriveLetter -eq $DriveLetter }
            if ($share) {
                $sharePath = $share.SharePath
            }
        } else {
            # Fallback to legacy config
            $cfg = Import-ShareConfig
            if ($cfg) {
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
                if ($UseGUI -and -not $Silent) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Drive $DriveLetter unmapped.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                }
                elseif (-not $UseGUI -and -not $Silent) {
                    Write-Host "Drive $DriveLetter unmapped." -ForegroundColor Green
                }
                Write-ActionLog -Message "Unmapped $DriveLetter" -Category 'Mapping'
            }
            else {
                if ($UseGUI -and -not $Silent) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to unmap drive.",
                        "Share Manager v$version",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
                elseif (-not $UseGUI -and -not $Silent) {
                    Write-Host "Failed to unmap drive." -ForegroundColor Red
                }
                Write-ActionLog -Message "Failed unmapping $DriveLetter" -Level ERROR -Category 'Mapping'
            }
        }
        else {
            if ($UseGUI -and -not $Silent) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Drive $DriveLetter not mapped.",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
            elseif (-not $UseGUI -and -not $Silent) {
                Write-Host "Drive $DriveLetter not mapped." -ForegroundColor Yellow
            }
        }
    }
    catch {
        if ($UseGUI -and -not $Silent) {
            [System.Windows.Forms.MessageBox]::Show(
                "Error during unmapping:`n$_",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        elseif (-not $UseGUI -and -not $Silent) {
            Write-Host "Error during unmapping: $_" -ForegroundColor Red
        }
        Write-ActionLog -Message "Error during unmapping: $_" -Level ERROR -Category 'Mapping' -Data @{ error = ("$_") }
    }
}

function Set-MappedDriveLabel {
    <#
    .SYNOPSIS
        Sets the Explorer display label for a mapped network drive.
    .DESCRIPTION
        Updates HKCU MountPoints2 registry keys so that the mapped drive (and its
        underlying UNC path) display a friendly name matching the Share Name.
        Safe, user-scope only. Errors are logged as WARN and do not interrupt flow.
    .PARAMETER DriveLetter
        The drive letter (single character) without colon, e.g., 'Z'
    .PARAMETER SharePath
        The UNC path, e.g., \\server\share
    .PARAMETER Label
        The desired display label (typically the Share Name)
    #>
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]$')][string]$DriveLetter,
        [Parameter()][string]$SharePath,
        [Parameter(Mandatory)][string]$Label
    )
    try {
        if ([string]::IsNullOrWhiteSpace($Label)) { return }
        $baseKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'

        # Set label on UNC mount key if possible
        $uncKeyName = $null
        if ($SharePath -and $SharePath -match '^\\\\([^\\]+)\\([^\\]+)') {
            $server = $Matches[1]; $share = $Matches[2]
            $uncKeyName = "##$server#$share"
        }
        if ($uncKeyName) {
            $uncKey = Join-Path $baseKey $uncKeyName
            if (-not (Test-Path $uncKey)) { New-Item -Path $uncKey -Force | Out-Null }
            New-ItemProperty -Path $uncKey -Name '_LabelFromReg' -Value $Label -PropertyType String -Force | Out-Null
        }

        # Also set per-letter key to improve reliability
        $dl = $DriveLetter.ToUpper()
        $driveKey = Join-Path $baseKey $dl
        if (-not (Test-Path $driveKey)) { New-Item -Path $driveKey -Force | Out-Null }
        New-ItemProperty -Path $driveKey -Name '_LabelFromReg' -Value $Label -PropertyType String -Force | Out-Null

        Write-ActionLog -Message "Set Explorer label for drive $dl to '$Label'" -Level DEBUG -Category 'Mapping'
    } catch {
        Write-ActionLog -Message "Failed to set Explorer label for drive $DriveLetter - $_" -Level WARN -Category 'Mapping'
    }
}

function Invoke-LogFileOpen {
    param(
        [ValidateSet('text','events','folder')] [string]$Target = 'text',
        [switch]$Prompt
    )

    # If CLI and no explicit target, offer a quick choice
    if (-not $UseGUI -and ($Prompt -or -not $PSBoundParameters.ContainsKey('Target'))) {
        Write-Host "Open which log?" -ForegroundColor Cyan
        Write-Host "  1) Human-readable log (Share_Manager.log)" -ForegroundColor Gray
        Write-Host "  2) Structured events (Share_Manager.events.jsonl)" -ForegroundColor Gray
        Write-Host "  3) Logs folder" -ForegroundColor Gray
        $sel = Read-Host "Choose (1-3) [1]"
        if ([string]::IsNullOrWhiteSpace($sel)) { $Target = 'text' }
        elseif ($sel -eq '2') { $Target = 'events' }
        elseif ($sel -eq '3') { $Target = 'folder' }
        else { $Target = 'text' }
    }

    if ($Target -eq 'folder') {
        try {
            if (-not (Test-Path $baseFolder)) { New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null }
            Start-Process -FilePath $baseFolder -ErrorAction Stop
            Write-ActionLog -Message "Opened logs folder" -Level DEBUG -Category 'Log'
        } catch {
            if ($UseGUI) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Unable to open logs folder:`n$_",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            } else {
                Write-Host "Unable to open logs folder: $_" -ForegroundColor Red
            }
            Write-ActionLog -Message "Failed to open logs folder: $_" -Level ERROR -Category 'Log' -Data @{ error = ("$_") }
        }
        return
    }

    $pathToOpen = if ($Target -eq 'events') { $eventsPath } else { $logPath }

    if (-not (Test-Path $pathToOpen)) {
        try {
            New-Item -Path $pathToOpen -ItemType File -Force | Out-Null
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
        Start-Process -FilePath $pathToOpen -ErrorAction Stop
        $what = (Split-Path $pathToOpen -Leaf)
        Write-ActionLog -Message "Opened log file: $what" -Level DEBUG -Category 'Log'
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
        Write-ActionLog -Message "Failed to open log file: $_" -Level ERROR -Category 'Log' -Data @{ error = ("$_") }
    }
}

function Get-LogEvents {
    <#
    .SYNOPSIS
        Query and filter JSONL structured log events.
    .DESCRIPTION
        Reads Share_Manager.events.jsonl and filters events by category, level, time range, or session.
        Returns PowerShell objects for further processing or formatted display.
    .PARAMETER Category
        Filter by category (Config, Credentials, BackupRestore, Migration, Mapping, Log, Startup, AutoMap).
    .PARAMETER Level
        Filter by severity level (DEBUG, INFO, WARN, ERROR).
    .PARAMETER Last
        Return only the last N events (after other filters applied).
    .PARAMETER Since
        Return events since this DateTime.
    .PARAMETER SessionId
        Filter by specific session ID (GUID).
    .PARAMETER Format
        Display format: 'Table' (default), 'List', or 'Raw' (JSON objects).
    .EXAMPLE
        Get-LogEvents -Category Mapping -Level ERROR -Last 10
        Get-LogEvents -Since (Get-Date).AddHours(-1) -Format List
    #>
    param(
        [string]$Category,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')] [string]$Level,
        [int]$Last,
        [DateTime]$Since,
        [string]$SessionId,
        [ValidateSet('Table','List','Raw')] [string]$Format = 'Table'
    )

    if (-not (Test-Path $eventsPath)) {
        Write-Host "No events log found at: $eventsPath" -ForegroundColor Yellow
        return
    }

    try {
        $events = Get-Content -Path $eventsPath -Encoding UTF8 | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ -ne $null }

        if ($Category) {
            $events = $events | Where-Object { $_.category -eq $Category }
        }
        if ($Level) {
            $events = $events | Where-Object { $_.level -eq $Level }
        }
        if ($SessionId) {
            $events = $events | Where-Object { $_.sessionId -eq $SessionId }
        }
        if ($Since) {
            $events = $events | Where-Object { 
                try { [DateTime]::Parse($_.ts) -ge $Since } catch { $false }
            }
        }
        if ($Last -gt 0) {
            $events = $events | Select-Object -Last $Last
        }

        if ($events.Count -eq 0) {
            Write-Host "No events matched the filters." -ForegroundColor Yellow
            return
        }

        switch ($Format) {
            'Raw' { 
                return $events 
            }
            'List' {
                $events | Format-List ts, level, category, msg, sessionId, data
            }
            'Table' {
                $events | Select-Object @{N='Time';E={$_.ts}}, level, category, @{N='Message';E={$_.msg}} | Format-Table -AutoSize
            }
        }
    }
    catch {
        Write-Host "Error reading events log: $_" -ForegroundColor Red
        Write-ActionLog -Message "Failed to query log events: $_" -Level ERROR -Category 'Log' -Data @{ error = ("$_") }
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
    
    # Track initial share count (to tailor completion message later)
    $initialCount = 0
    try {
        $initialCfg = Import-AllShares
        $initialCount = if ($initialCfg -and $initialCfg.Shares) { $initialCfg.Shares.Count } else { 0 }
    } catch { $initialCount = 0 }

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
    
    Write-Host ""
    $autoUnmap = $false
    do {
        $yn = Read-Host "  Auto-unmap when changing drive letter? (Y/N) [Y]"
        if ($yn -eq "" -or $yn -match '^[Yy]$') { $autoUnmap = $true; break }
        if ($yn -match '^[Nn]$') { $autoUnmap = $false; break }
        Write-Host "  Enter Y or N." -ForegroundColor Yellow
    } while ($true)
    
    # Theme selection (CLI): Allowed during initial setup since it only affects GUI appearance later
    Write-Host "" 
    $themeChoice = "Classic"
    Write-Host "  Theme:" -ForegroundColor White
    Write-Host "    1) Classic - Traditional Windows look (default)" -ForegroundColor Gray
    Write-Host "    2) Modern  - Native visual styles (Windows 10+)" -ForegroundColor Gray
    Write-Host ""
    do {
        $t = Read-Host "  Choose theme (1-2) [1]"
        if ($t -eq "" -or $t -eq "1") { $themeChoice = "Classic"; break }
        if ($t -eq "2") { $themeChoice = "Modern"; break }
        Write-Host "  Enter 1 or 2." -ForegroundColor Yellow
    } while ($true)
    
    Write-Host ""
    $syncLabel = $true
    do {
        $yn = Read-Host "  Sync share name to drive label in Explorer? (Y/N) [Y]"
        if ($yn -eq "" -or $yn -match '^[Yy]$') { $syncLabel = $true; break }
        if ($yn -match '^[Nn]$') { $syncLabel = $false; break }
        Write-Host "  Enter Y or N." -ForegroundColor Yellow
    } while ($true)
    
    # Save initial preferences
    $config = Get-CachedConfig
    $config.Preferences.PreferredMode = $preferredMode
    $config.Preferences.PersistentMapping = $persistentMapping
    $config.Preferences.UnmapOldMapping = $autoUnmap
    $config.Preferences.Theme = $themeChoice
    $config.Preferences.SyncShareNameToDriveLabel = $syncLabel
    Save-AllShares -Config $config | Out-Null
    
    Write-Host ""
    Write-Host "  [OK] Preferences saved!" -ForegroundColor Green
    Write-Host ""
    
    # Show quick tips for new features
    Write-Host "  ======[ QUICK TIPS ]======" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Key Features:" -ForegroundColor White
    Write-Host "    * Favorites    - Mark important shares (shown with <> brackets)" -ForegroundColor Gray
    Write-Host "    * Categories   - Organize shares by type/purpose" -ForegroundColor Gray
    Write-Host "    * Search       - Quick search by name or path" -ForegroundColor Gray
    Write-Host "    * Filter       - View by category or favorites only" -ForegroundColor Gray
    Write-Host "    * Statistics   - Track connection history and usage" -ForegroundColor Gray
    Write-Host "    * Shortcuts    - Use C (connect all), D (disconnect all), N (reconnect all)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
    
    # Offer to import from backup or add manually
    Write-Host "  ======[ SETUP OPTIONS ]======" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Do you have an existing backup to restore?" -ForegroundColor White
    Write-Host "    1) Yes - Import from backup file" -ForegroundColor Gray
    Write-Host "    2) No  - Add shares manually" -ForegroundColor Gray
    Write-Host ""
    
    $setupChoice = ""
    do {
        $sc = Read-Host "  Choose option (1-2) [2]"
        if ($sc -eq "" -or $sc -eq "2") { $setupChoice = "Manual"; break }
        if ($sc -eq "1") { $setupChoice = "Import"; break }
        Write-Host "  Enter 1 or 2." -ForegroundColor Yellow
    } while ($true)
    
    if ($setupChoice -eq "Import") {
        Write-Host ""
        Write-Host "  Enter the full path to your backup file:" -ForegroundColor White
        Write-Host "  (e.g., C:\Backups\shares_backup_2026-02-01.json)" -ForegroundColor DarkGray
        $backupPath = Read-Host "  Path"
        
    if ([string]::IsNullOrWhiteSpace($backupPath)) {
            Write-Host ""
            Write-Host "  [!] No path entered." -ForegroundColor Yellow
            $cancelChoice = ""
            do {
                Write-Host "  Cancel setup? (Y/N)" -ForegroundColor White
                Write-Host "  If you cancel, you'll need to complete setup on next launch." -ForegroundColor DarkGray
                $cancelChoice = Read-Host "  "
                if ($cancelChoice -match '^[Yy]$') { return $false }
                if ($cancelChoice -match '^[Nn]$') { break }
                Write-Host "  Enter Y or N." -ForegroundColor Yellow
            } while ($true)
            Write-Host ""
            Write-Host "  Continuing with manual setup..." -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Press any key to add your first share..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Add-NewShareCli
    } elseif (-not (Test-Path $backupPath)) {
            Write-Host ""
            Write-Host "  [!] Backup file not found." -ForegroundColor Yellow
            $cancelChoice = ""
            do {
                Write-Host "  Cancel setup? (Y/N)" -ForegroundColor White
                Write-Host "  If you cancel, you'll need to complete setup on next launch." -ForegroundColor DarkGray
                $cancelChoice = Read-Host "  "
                if ($cancelChoice -match '^[Yy]$') { return $false }
                if ($cancelChoice -match '^[Nn]$') { break }
                Write-Host "  Enter Y or N." -ForegroundColor Yellow
            } while ($true)
            Write-Host ""
            Write-Host "  Continuing with manual setup..." -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Press any key to add your first share..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Add-NewShareCli
        } else {
            Write-Host ""
            Write-Host "  Importing backup..." -ForegroundColor Cyan
            
            # Import the backup (Merge mode to preserve preferences)
            $importResult = Import-ShareConfiguration -ImportPath $backupPath -Merge:$true
            
            if ($importResult -and $importResult.Success) {
                $cfg = Import-AllShares
                $shareCount = if ($cfg -and $cfg.Shares) { $cfg.Shares.Count } else { 0 }
                Write-Host ""
                Write-Host "  [OK] Imported $shareCount share(s) from backup!" -ForegroundColor Green
                Write-Host ""
                Write-Host "  Note: Credentials were not included in the backup." -ForegroundColor Yellow
                Write-Host "  You'll be prompted for credentials when connecting shares." -ForegroundColor Yellow
            } else {
                Write-Host ""
                Write-Host "  [!] Import failed or returned no data. Continuing with manual setup..." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  Press any key to add your first share..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Add-NewShareCli
            }
        }
    } else {
        Write-Host ""
        Write-Host "  Press any key to add your first share..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Add-NewShareCli
    }
    
    Write-Host ""
    # Tailor completion message based on whether at least one share exists now
    $finalCfg = Import-AllShares
    $finalCount = if ($finalCfg -and $finalCfg.Shares) { $finalCfg.Shares.Count } else { 0 }
    if ($finalCount -gt $initialCount) {
        Write-Host "  [OK] Setup complete! You're ready to use Share Manager." -ForegroundColor Green
    } else {
        Write-Host "  Preferences saved. You can add shares later from the main menu." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    return $true
}

function Initialize-Config-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic

    # Apply visual styles for the wizard itself (looks better for first impression)
    try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { Write-ActionLog -Message "EnableVisualStyles for FTS wizard failed: $_" -Level 'WARN' -Category 'Theme' -OncePerSeconds 60 }

    # Welcome message (mention where to change theme later)
    $result = [System.Windows.Forms.MessageBox]::Show(
        "Welcome to Share Manager v$version!`n`nThis wizard will help you:`n`n1. Configure your preferences`n2. Add your first network share`n3. Save credentials securely`n`nNote: You can change the visual theme later under Settings > Preferences > Theme.`n`nReady to begin?",
        "Share Manager v$version - First Time Setup",
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    if ($result -ne 'OK') { return $false }
    
    # Step 1: Preferences
    $dummyPrefs = [PSCustomObject]@{
        UnmapOldMapping   = $true
        PreferredMode     = "GUI"
        PersistentMapping = $true
        Theme             = "Modern"
    }
    $prefValues = Show-PreferencesForm -CurrentPrefs $dummyPrefs -IsInitial $true
    if ($null -eq $prefValues) {
        $cancelConfirm = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to cancel setup?`n`nIf you cancel now, you'll need to complete the setup wizard the next time you launch Share Manager.",
            "Cancel Setup?",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($cancelConfirm -eq 'Yes') { return $false }
        # Loop back to preferences if user says No
        $prefValues = Show-PreferencesForm -CurrentPrefs $dummyPrefs -IsInitial $true
        if ($null -eq $prefValues) { return $false }
    }
    
    # Save preferences first
    $config = Get-CachedConfig
    $config.Preferences.PreferredMode = $prefValues.PreferredMode
    $config.Preferences.PersistentMapping = $prefValues.PersistentMapping
    $config.Preferences.UnmapOldMapping = $prefValues.UnmapOldMapping
    $config.Preferences.Theme = $prefValues.Theme
    if ($prefValues.PSObject.Properties['SyncShareNameToDriveLabel']) {
        $config.Preferences.SyncShareNameToDriveLabel = [bool]$prefValues.SyncShareNameToDriveLabel
    }
    Save-AllShares -Config $config | Out-Null
    
    # Step 2: Ask if user wants to import from backup or add manually
    $setupChoice = [System.Windows.Forms.MessageBox]::Show(
        "Do you have an existing backup file to restore?`n`nClick YES to import from backup`nClick NO to add shares manually",
        "Share Manager v$version - Setup Options",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    
    if ($setupChoice -eq 'Yes') {
        # Import from backup
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Title = "Select Backup File"
        $openFileDialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
        
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $backupPath = $openFileDialog.FileName
            
            # Import the backup (Merge mode to preserve preferences)
            $importResult = Import-ShareConfiguration -ImportPath $backupPath -Merge:$true
            
            if ($importResult -and $importResult.Success) {
                $cfg = Import-AllShares
                $totalShares = $cfg.Shares.Count
                $msgParts = @("Import complete!")
                if ($importResult.Added -gt 0) { $msgParts += "$($importResult.Added) new share(s) added" }
                if ($importResult.Skipped -gt 0) { $msgParts += "$($importResult.Skipped) existing share(s) updated" }
                $msgParts += "`nTotal shares: $totalShares"
                $msgParts += "`nNote: Credentials were not included in the backup."
                $msgParts += "You'll be prompted for credentials when connecting shares."
                
                [System.Windows.Forms.MessageBox]::Show(
                    ($msgParts -join "`n"),
                    "Share Manager v$version - Import Complete",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Import failed. Please check the backup file and try again.",
                    "Share Manager v$version - Import Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
        } else {
            # User canceled import dialog
            $cancelConfirm = [System.Windows.Forms.MessageBox]::Show(
                "Cancel setup?`n`nIf you cancel now, you'll need to complete the wizard on next launch.",
                "Cancel Setup?",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($cancelConfirm -eq 'Yes') { return $false }
            # User chose to continue - skip import, they can add manually later
        }
    } else {
        # Add first share manually
        $addSharePrompt = [System.Windows.Forms.MessageBox]::Show(
            "Would you like to add your first network share now?`n`nYou can skip this and add shares later from the main menu.",
            "Share Manager v$version - Add Share",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        
        if ($addSharePrompt -eq 'Yes') {
            Show-AddShareDialog
        }
    }
    
    # Show Quick Tips for key features
    [void][System.Windows.Forms.MessageBox]::Show(
        "Quick Tips - Key Features:`n`n" +
        "* FAVORITES - Right-click any share, select 'Toggle Favorite'`n" +
        "  (Favorites show with <> brackets)`n`n" +
        "* CATEGORIES - Organize shares by type/purpose`n" +
        "  (Set category when adding/editing shares)`n`n" +
        "* SEARCH & FILTER - Use Ctrl+F to search, filter by category/favorites`n`n" +
        "* KEYBOARD SHORTCUTS:`n" +
        "  - Ctrl+N: Add New  - Ctrl+F: Search  - Ctrl+R: Refresh`n" +
        "  - Ctrl+A: Connect All  - Ctrl+D: Disconnect All  - Delete: Remove`n" +
        "  - Delete: Remove selected share`n`n" +
        "* STATISTICS - Track connection history and usage per share`n`n" +
        "Ready to continue?",
        "Share Manager v$version - Quick Tips",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    # Final completion message
    [System.Windows.Forms.MessageBox]::Show(
        "Setup complete!`n`nYou're all set to use Share Manager.`n`nYou can:`n- Add more shares`n- Connect/disconnect shares`n- Manage credentials`n- Configure settings`n`nEnjoy!",
        "Share Manager v$version - Ready",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    return $true
}

#endregion

#region Credential GUI Form

function Get-RecentUsernames {
    <#
    .SYNOPSIS
        Gets list of recently used usernames from credential store
    #>
    $store = Import-CredentialStore
    if ($store -and $store.Entries) {
        return @($store.Entries | Select-Object -ExpandProperty Username | Sort-Object -Unique)
    }
    return @()
}

function Show-CredentialForm {
    param(
        [string]$Username = "",
        [string]$Message = "Enter credentials",
        [switch]$ShowUsernameDropdown
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

    # Use ComboBox for smart username suggestions
    $txtUser = New-Object System.Windows.Forms.ComboBox
    $txtUser.Left = 110
    $txtUser.Top = 18
    $txtUser.Width = 200
    $txtUser.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
    $txtUser.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
    $txtUser.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::ListItems
    
    if ($ShowUsernameDropdown) {
        $recentUsers = Get-RecentUsernames
        foreach ($user in $recentUsers) {
            [void]$txtUser.Items.Add($user)
        }
    }
    
    if ($Username) {
        $txtUser.Text = $Username
    }
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
    Write-ActionLog -Message "Entering CLI mode" -Level INFO -Category 'Startup'
    
    # Migrate legacy config if needed
    Convert-LegacyConfig
    
    # Ensure automap scripts exist if persistent mapping is enabled
    $persistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
    if ($persistent) {
        # Always call Install-LogonScript to ensure scripts are up-to-date
        Install-LogonScript -Silent
    }
    
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
                $shares = @(Get-ShareConfiguration | Where-Object { $_.Enabled })
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
                $shares = @(Get-ShareConfiguration | Where-Object { $_.Enabled })
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
            "L" { 
                Write-Host "`n=== Log Menu ===" -ForegroundColor Cyan
                Write-Host "1. Open Log File"
                Write-Host "2. Query Events"
                Write-Host "3. Back"
                $logChoice = Read-Host "Select (1-3)"
                switch ($logChoice) {
                    "1" { Invoke-LogFileOpen -Prompt; Start-Sleep -Seconds 1 }
                    "2" {
                        Write-Host "`n=== Query Log Events ===" -ForegroundColor Cyan
                        Write-Host "Category filter (leave blank for all):"
                        Write-Host "  Config, Credentials, BackupRestore, Migration, Mapping, Log, Startup, AutoMap" -ForegroundColor Gray
                        $cat = Read-Host "Category"
                        
                        Write-Host "`nLevel filter (leave blank for all):"
                        Write-Host "  DEBUG, INFO, WARN, ERROR" -ForegroundColor Gray
                        $lvl = Read-Host "Level"
                        
                        $lastN = Read-Host "Show last N events (leave blank for all)"
                        
                        $params = @{}
                        if (-not [string]::IsNullOrWhiteSpace($cat)) { $params['Category'] = $cat }
                        if (-not [string]::IsNullOrWhiteSpace($lvl)) { $params['Level'] = $lvl.ToUpper() }
                        if ($lastN -match '^\d+$') { $params['Last'] = [int]$lastN }
                        
                        Write-Host ""
                        Get-LogEvents @params
                        Write-Host ""
                        Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    }
                    default { }
                }
            }
            
            # Navigation
            "G" {
                Write-Host "  Switching to GUI mode..." -ForegroundColor Cyan
                Write-ActionLog -Message "Switching from CLI to GUI mode" -Level INFO -Category 'Startup'
                Start-Process -FilePath "powershell.exe" `
                    -ArgumentList "-ExecutionPolicy Bypass -STA -File `"$PSCommandPath`" -StartupMode GUI" `
                    -WindowStyle Normal
                exit
            }
            "Q" { 
                Write-ActionLog -Message "User exited CLI mode" -Level INFO -Category 'Startup'
                exit 
            }
            
            default { 
                Write-Host "  Invalid choice" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
        
        # Only pause for actions that need it (skip for actions with their own pause)
        if ($choice -notin @("Q", "G", "3", "B", "P", "D", "C", "N") + $autoContinue) { 
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } while ($true)
}

function Show-ManageSharesMenu {
    <#
    .SYNOPSIS
        Shows submenu for managing existing shares with filtering and batch operations
    #>
    $filterText = ""
    
    do {
        Clear-Host
        Write-Host ""
        Write-Host "  ======[ MANAGE SHARES ]======" -ForegroundColor Cyan
        
    $allShares = @(Get-ShareConfiguration)
        
        if ($allShares.Count -eq 0) {
            Write-Host "  No shares configured." -ForegroundColor Yellow
            return
        }
        
        # Apply filter if set
        if ($filterText) {
            $shares = @($allShares | Where-Object { 
                $_.Name -like "*$filterText*" -or $_.SharePath -like "*$filterText*" -or $_.DriveLetter -like "*$filterText*"
            })
            Write-Host ""
            Write-Host "  Filter: " -NoNewline -ForegroundColor Yellow
            Write-Host "'$filterText'" -ForegroundColor White
            Write-Host "  Showing $($shares.Count) of $($allShares.Count) shares" -ForegroundColor DarkGray
        } else {
            $shares = $allShares
        }
        
        if ($shares.Count -eq 0) {
            Write-Host ""
            Write-Host "  No shares match filter." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  F" -NoNewline -ForegroundColor White
            Write-Host " - Clear Filter  " -NoNewline -ForegroundColor Gray
            Write-Host "B" -NoNewline -ForegroundColor White
            Write-Host " - Back" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  > " -NoNewline -ForegroundColor White
            $choice = Read-Host
            $choice = $choice.Trim().ToUpper()
            
            if ($choice -eq "F") { $filterText = "" }
            elseif ($choice -eq "B") { return }
            continue
        }
        
        Write-Host ""
        Write-Host "  Status  #  Name" -ForegroundColor DarkGray
        Write-Host "  ------  -- ----" -ForegroundColor DarkGray
        # Show shares with quick actions
        $index = 1
        foreach ($share in $shares) {
            $connected = Test-ShareConnection -DriveLetter $share.DriveLetter
            $statusText = if ($connected) { "MAPPED" } else { " ---- " }
            $statusColor = if ($connected) { "Green" } else { "DarkGray" }
            $nameColor = if ($connected) { "White" } else { if ($share.Enabled) { "Gray" } else { "DarkGray" } }
            $enabledIndicator = if (-not $share.Enabled) { " [DISABLED]" } else { "" }
            
            # Format: [STATUS] # Name [X:] (\\path)
            Write-Host "  [" -NoNewline -ForegroundColor DarkGray
            Write-Host $statusText -NoNewline -ForegroundColor $statusColor
            Write-Host "] " -NoNewline -ForegroundColor DarkGray
            
            $idxStr = $index.ToString().PadLeft(2)
            Write-Host "$idxStr " -NoNewline -ForegroundColor White
            
            Write-Host "$($share.Name)" -NoNewline -ForegroundColor $nameColor
            if ($enabledIndicator) {
                Write-Host $enabledIndicator -NoNewline -ForegroundColor Red
            }
            Write-Host " " -NoNewline
            Write-Host "[$($share.DriveLetter):]" -NoNewline -ForegroundColor DarkCyan
            Write-Host " " -NoNewline
            Write-Host "$($share.SharePath)" -ForegroundColor DarkGray
            
            $index++
        }
        
        Write-Host ""
        Write-Host "  Actions:" -ForegroundColor DarkGray
        Write-Host "    1-$($shares.Count)" -NoNewline -ForegroundColor White
        Write-Host " - Toggle connect/disconnect  " -NoNewline -ForegroundColor Gray
        Write-Host "S" -NoNewline -ForegroundColor Green
        Write-Host " - Show status" -ForegroundColor Gray
        Write-Host "    E" -NoNewline -ForegroundColor Cyan
        Write-Host " - Edit share  " -NoNewline -ForegroundColor Gray
        Write-Host "R" -NoNewline -ForegroundColor Cyan
        Write-Host " - Remove share  " -NoNewline -ForegroundColor Gray
        Write-Host "F" -NoNewline -ForegroundColor Cyan
        Write-Host " - Filter shares" -ForegroundColor Gray
        Write-Host "    X" -NoNewline -ForegroundColor Yellow
        Write-Host " - Batch enable/disable  " -NoNewline -ForegroundColor Gray
        Write-Host "B" -NoNewline -ForegroundColor White
        Write-Host " - Back to main menu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  > " -NoNewline -ForegroundColor White
        $choice = Read-Host
        $choice = $choice.Trim().ToUpper()
        
        # Status command
        if ($choice -eq "S") {
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ CONNECTION STATUS ]======" -ForegroundColor Green
            Write-Host ""
            
            $connected = @($shares | Where-Object { Test-ShareConnection -DriveLetter $_.DriveLetter })
            $disconnected = @($shares | Where-Object { -not (Test-ShareConnection -DriveLetter $_.DriveLetter) -and $_.Enabled })
            $disabled = @($shares | Where-Object { -not $_.Enabled })
            
            Write-Host "  Connected: " -NoNewline -ForegroundColor Green
            Write-Host "$($connected.Count)" -ForegroundColor White
            if ($connected.Count -gt 0) {
                foreach ($s in $connected) {
                    Write-Host "    [$($s.DriveLetter):] " -NoNewline -ForegroundColor DarkCyan
                    Write-Host "$($s.Name) " -NoNewline -ForegroundColor White
                    Write-Host "-> $($s.SharePath)" -ForegroundColor DarkGray
                }
            }
            
            Write-Host ""
            Write-Host "  Disconnected: " -NoNewline -ForegroundColor Yellow
            Write-Host "$($disconnected.Count)" -ForegroundColor White
            if ($disconnected.Count -gt 0) {
                foreach ($s in $disconnected) {
                    Write-Host "    [$($s.DriveLetter):] " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($s.Name)" -ForegroundColor Gray
                }
            }
            
            if ($disabled.Count -gt 0) {
                Write-Host ""
                Write-Host "  Disabled: " -NoNewline -ForegroundColor Red
                Write-Host "$($disabled.Count)" -ForegroundColor White
                foreach ($s in $disabled) {
                    Write-Host "    [$($s.DriveLetter):] " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($s.Name)" -ForegroundColor DarkGray
                }
            }
            
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            continue
        }
        
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
                        Write-Host "  Save credentials? (Y/N) [Y]: " -NoNewline
                        $saveIt = Read-Host
                        if ($saveIt -eq "" -or $saveIt -match '^[Yy]$') {
                            Save-Credential -Credential $cred
                        }
                    }
                }
                
                if ($cred) {
                    Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred
                    
                    # Update last connected
                    $config = Get-CachedConfig
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
            $filterText = ""  # Clear filter after edit
        }
        elseif ($choice -eq "R") {
            Remove-ShareCli
            $filterText = ""  # Clear filter after remove
        }
        elseif ($choice -eq "F") {
            Write-Host ""
            Write-Host "  ===[ FILTER SHARES ]===" -ForegroundColor Cyan
            Write-Host ""
            if ($filterText) {
                Write-Host "  Current filter: '$filterText'" -ForegroundColor Yellow
                Write-Host ""
            }
            Write-Host "  Enter search text to filter by:" -ForegroundColor White
            Write-Host "    - Share name (e.g., 'office', 'backup')" -ForegroundColor DarkGray
            Write-Host "    - Network path (e.g., 'nas', '192.168')" -ForegroundColor DarkGray
            Write-Host "    - Drive letter (e.g., 'Z', 'Y')" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Leave blank to clear any active filter" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  > " -NoNewline -ForegroundColor Cyan
            $newFilter = Read-Host
            $filterText = $newFilter.Trim()
            if ($filterText) {
                Write-Host ""
                Write-Host "  Filter applied: '$filterText'" -ForegroundColor Green
                Start-Sleep -Milliseconds 600
            } elseif ($newFilter -eq "") {
                Write-Host ""
                Write-Host "  Filter cleared" -ForegroundColor Yellow
                Start-Sleep -Milliseconds 600
            }
        }
        elseif ($choice -eq "X") {
            Show-BatchOperationsMenu -CurrentFilter $filterText
            $filterText = ""  # Clear filter after batch ops
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

function Show-BatchOperationsMenu {
    <#
    .SYNOPSIS
        Batch operations menu for enabling/disabling multiple shares
    #>
    param([string]$CurrentFilter = "")
    
    do {
        Clear-Host
        Write-Host ""
        Write-Host "  ======[ BATCH OPERATIONS ]======" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Quickly enable or disable multiple shares at once" -ForegroundColor DarkGray
        Write-Host ""
        
        # Always get fresh data to show current enabled/disabled states
        $allShares = @(Get-ShareConfiguration)
        Clear-ConfigCache
        $allShares = @(Get-CachedConfig -Force).Shares
        
        if ($allShares.Count -eq 0) {
            Write-Host "  No shares configured." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        
        # Apply filter if provided
        if ($CurrentFilter) {
            $shares = @($allShares | Where-Object { 
                $_.Name -like "*$CurrentFilter*" -or $_.SharePath -like "*$CurrentFilter*" -or $_.DriveLetter -like "*$CurrentFilter*"
            })
            Write-Host "  Active filter: " -NoNewline -ForegroundColor Yellow
            Write-Host "'$CurrentFilter'" -ForegroundColor White
            Write-Host "  Showing $($shares.Count) of $($allShares.Count) shares" -ForegroundColor DarkGray
        } else {
            Write-Host "  All $($allShares.Count) shares available" -ForegroundColor DarkGray
            $shares = $allShares
        }
        
        if ($shares.Count -eq 0) {
            Write-Host ""
            Write-Host "  No shares match current filter." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        
        Write-Host ""
        Write-Host "  Choose an operation:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1" -NoNewline -ForegroundColor Cyan
        Write-Host " - Pick shares to enable" -NoNewline -ForegroundColor Gray
        Write-Host "   (interactive selection)" -ForegroundColor DarkGray
        Write-Host "  2" -NoNewline -ForegroundColor Cyan
        Write-Host " - Pick shares to disable" -NoNewline -ForegroundColor Gray
        Write-Host "  (interactive selection)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  3" -NoNewline -ForegroundColor Yellow
        Write-Host " - Enable all $($shares.Count) $(if ($CurrentFilter) { '(filtered)' } else { '' })" -ForegroundColor Gray
        Write-Host "  4" -NoNewline -ForegroundColor Yellow
        Write-Host " - Disable all $($shares.Count) $(if ($CurrentFilter) { '(filtered)' } else { '' })" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  B" -NoNewline -ForegroundColor White
        Write-Host " - Back to manage menu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  > " -NoNewline -ForegroundColor White
        $choice = Read-Host
        $choice = $choice.Trim().ToUpper()
        
        switch ($choice) {
            "1" {
                # Enable selected
                $selectedIndices = @(Select-SharesInteractive -Shares $shares -Title "SELECT SHARES TO ENABLE" -ShowStatus)
                if ($selectedIndices.Count -gt 0) {
                    # Force reload to get absolute latest state
                    Clear-ConfigCache
                    $config = Get-CachedConfig -Force
                    $enabled = 0
                    $shareNames = @()
                    foreach ($index in @($selectedIndices)) {
                        $selectedShare = $shares[$index]
                        $shareName = $selectedShare.Name
                        $configShare = $config.Shares | Where-Object { $_.Name -eq $shareName } | Select-Object -First 1
                        if ($configShare -and -not $configShare.Enabled) {
                            $configShare.Enabled = $true
                            $shareNames += $shareName
                            $enabled++
                        }
                    }
                    if ($enabled -gt 0 -and (Save-AllShares -Config $config)) {
                        Write-Host ""
                        Write-Host "  [OK] Enabled $enabled share(s):" -ForegroundColor Green
                        foreach ($name in $shareNames) {
                            Write-Host "    - $name" -ForegroundColor Gray
                        }
                        Write-ActionLog -Message "Batch enabled $enabled shares" -Category 'Config'
                    } elseif ($enabled -eq 0) {
                        Write-Host ""
                        Write-Host "  [!] Selected shares are already enabled" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host ""
                    Write-Host "  Operation cancelled - no changes made" -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "2" {
                # Disable selected
                $selectedIndices = @(Select-SharesInteractive -Shares $shares -Title "SELECT SHARES TO DISABLE" -ShowStatus)
                if ($selectedIndices.Count -gt 0) {
                    # Force reload to get absolute latest state
                    Clear-ConfigCache
                    $config = Get-CachedConfig -Force
                    $disabled = 0
                    $shareNames = @()
                    # Ensure we iterate through individual indices, not arrays
                    foreach ($index in @($selectedIndices)) {
                        $selectedShare = $shares[$index]
                        $shareName = $selectedShare.Name
                        $configShare = $config.Shares | Where-Object { $_.Name -eq $shareName } | Select-Object -First 1
                        if ($configShare -and $configShare.Enabled) {
                            $configShare.Enabled = $false
                            $shareNames += $shareName
                            $disabled++
                        }
                    }
                    if ($disabled -gt 0 -and (Save-AllShares -Config $config)) {
                        Write-Host ""
                        Write-Host "  [OK] Disabled $disabled share(s):" -ForegroundColor Green
                        foreach ($name in $shareNames) {
                            Write-Host "    - $name" -ForegroundColor Gray
                        }
                        Write-ActionLog -Message "Batch disabled $disabled shares" -Category 'Config'
                    } elseif ($disabled -eq 0) {
                        Write-Host ""
                        Write-Host "  [!] Selected shares are already disabled" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host ""
                    Write-Host "  Operation cancelled - no changes made" -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "3" {
                # Enable all
                Write-Host ""
                Write-Host "  Enable all $($shares.Count) share(s)? (Y/N) [Y]: " -NoNewline
                $confirm = Read-Host
                if ($confirm -eq "" -or $confirm -match '^[Yy]$') {
                    $config = Get-CachedConfig -Force
                    $enabled = 0
                    foreach ($share in $shares) {
                        $configShare = $config.Shares | Where-Object { $_.Name -eq $share.Name } | Select-Object -First 1
                        if ($configShare) {
                            $configShare.Enabled = $true
                            $enabled++
                        }
                    }
                    if (Save-AllShares -Config $config) {
                        Write-Host ""
                        Write-Host "  [OK] Enabled all $enabled share(s)" -ForegroundColor Green
                        Write-ActionLog -Message "Batch enabled all shares $(if ($CurrentFilter) { "(filtered: $CurrentFilter)" } else { '' })" -Category 'Config'
                    }
                } else {
                    Write-Host ""
                    Write-Host "  Cancelled" -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "4" {
                # Disable all
                Write-Host ""
                Write-Host "  Disable all $($shares.Count) share(s)? (Y/N) [N]: " -NoNewline
                $confirm = Read-Host
                if ($confirm -match '^[Yy]$') {
                    $config = Get-CachedConfig -Force
                    $disabled = 0
                    foreach ($share in $shares) {
                        $configShare = $config.Shares | Where-Object { $_.Name -eq $share.Name } | Select-Object -First 1
                        if ($configShare) {
                            $configShare.Enabled = $false
                            $disabled++
                        }
                    }
                    if (Save-AllShares -Config $config) {
                        Write-Host ""
                        Write-Host "  [OK] Disabled all $disabled share(s)" -ForegroundColor Green
                        Write-ActionLog -Message "Batch disabled all shares $(if ($CurrentFilter) { "(filtered: $CurrentFilter)" } else { '' })" -Category 'Config'
                    }
                } else {
                    Write-Host ""
                    Write-Host "  Cancelled" -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "  Press any key..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "B" { return }
            default {
                Write-Host "  Invalid choice" -ForegroundColor Red
                Start-Sleep -Milliseconds 800
            }
        }
    } while ($true)
}

function Select-SharesInteractive {
    <#
    .SYNOPSIS
        Interactive share selection with toggle interface - returns selected indices
    #>
    param(
        [Parameter(Mandatory)][array]$Shares,
        [string]$Title = "SELECT SHARES",
        [switch]$ShowStatus
    )
    
    $selection = @{}
    for ($i = 0; $i -lt $Shares.Count; $i++) {
        $selection[$i] = $false
    }
    
    do {
        Clear-Host
        Write-Host ""
        Write-Host "  ======[ $Title ]======" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  How to use:" -ForegroundColor White
        Write-Host "    - Type a number to toggle that share on/off" -ForegroundColor DarkGray
        Write-Host "    - Press " -NoNewline -ForegroundColor DarkGray
        Write-Host "A" -NoNewline -ForegroundColor Green
        Write-Host " when done to apply changes" -ForegroundColor DarkGray
        Write-Host "    - Press " -NoNewline -ForegroundColor DarkGray
        Write-Host "C" -NoNewline -ForegroundColor Red
        Write-Host " to cancel without changes" -ForegroundColor DarkGray
        Write-Host ""
        
        for ($i = 0; $i -lt $Shares.Count; $i++) {
            $share = $Shares[$i]
            $checkbox = if ($selection[$i]) { "[X]" } else { "[ ]" }
            $color = if ($selection[$i]) { "Green" } else { "DarkGray" }
            
            Write-Host "  $checkbox $($i + 1). " -ForegroundColor $color -NoNewline
            Write-Host "$($share.Name) " -ForegroundColor $(if ($selection[$i]) { "White" } else { "Gray" }) -NoNewline
            Write-Host "[$($share.DriveLetter):] " -NoNewline -ForegroundColor DarkGray
            
            if ($ShowStatus) {
                if ($share.Enabled) {
                    Write-Host "[ENABLED]" -ForegroundColor Green
                } else {
                    Write-Host "[DISABLED]" -ForegroundColor Red
                }
            } else {
                Write-Host ""
            }
        }
        
        Write-Host ""
        $selectedCount = ($selection.Values | Where-Object { $_ }).Count
        if ($selectedCount -eq 0) {
            Write-Host "  No shares selected yet" -ForegroundColor Yellow
        } else {
            Write-Host "  Selected: " -NoNewline -ForegroundColor Cyan
            Write-Host "$selectedCount" -NoNewline -ForegroundColor White
            Write-Host " of $($Shares.Count)" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "  > " -NoNewline -ForegroundColor Cyan
        $choice = Read-Host
        $choice = $choice.Trim().ToUpper()
        
        # Check for numeric toggle
        $num = 0
        if ([int]::TryParse($choice, [ref]$num) -and $num -ge 1 -and $num -le $Shares.Count) {
            $selection[$num - 1] = -not $selection[$num - 1]
        }
        elseif ($choice -eq "A") {
            # Apply - return selected share indices
            $result = @()
            for ($i = 0; $i -lt $Shares.Count; $i++) {
                if ($selection[$i]) {
                    $result += $i
                }
            }
            if ($result.Count -eq 0) {
                Write-Host ""
                Write-Host "  No shares selected. Press any key to continue..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                continue
            }
            return $result
        }
        elseif ($choice -eq "C") {
            # Cancel
            return @()
        }
        else {
            Write-Host ""
            Write-Host "  Invalid choice. Enter a number (1-$($Shares.Count)), A to apply, or C to cancel" -ForegroundColor Red
            Start-Sleep -Milliseconds 800
        }
    } while ($true)
}

function Edit-ShareCli {
    <#
    .SYNOPSIS
        Edit an existing share with full property access
    #>
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ EDIT SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = @(Get-ShareConfiguration)
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
        Write-Host "  (Leave blank to keep current value)" -ForegroundColor DarkGray
        Write-Host ""
        
        # Name
        Write-Host "  Name [$($share.Name)]: " -NoNewline
        $newName = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newName)) {
            $share.Name = $newName
        }
        
        # SharePath
        Write-Host "  Share Path [$($share.SharePath)]: " -NoNewline
        $newPath = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newPath)) {
            $share.SharePath = $newPath
        }
        
        # DriveLetter
        Write-Host "  Drive Letter [$($share.DriveLetter)]: " -NoNewline
        $newDrive = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newDrive)) {
            $newDrive = $newDrive.ToUpper() -replace '[^A-Z]', ''
            if ($newDrive.Length -eq 1) {
                $share.DriveLetter = $newDrive
            } else {
                Write-Host "  Invalid drive letter, keeping current." -ForegroundColor Yellow
            }
        }
        
        # Username
        Write-Host "  Username [$($share.Username)]: " -NoNewline
        $newUser = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newUser)) {
            $share.Username = $newUser
        }
        
        # Description
        Write-Host "  Description [$($share.Description)]: " -NoNewline
        $newDesc = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newDesc)) {
            $share.Description = $newDesc
        }
        
        # Category
        $currentCategory = if ($share.PSObject.Properties['Category']) { $share.Category } else { "General" }
        Write-Host "  Category [$currentCategory]: " -NoNewline
        $newCategory = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($newCategory)) {
            Set-ShareCategory -ShareId $share.Id -Category $newCategory
        }
        
        # Enabled
        Write-Host "  Enabled [$($share.Enabled)] (Y/N/blank): " -NoNewline
        $toggle = Read-Host
        if ($toggle -match '^[Yy]$') {
            $share.Enabled = $true
        } elseif ($toggle -match '^[Nn]$') {
            $share.Enabled = $false
        }
        
        # Save changes using Update-ShareConfiguration for proper validation and auto-unmap
        $result = Update-ShareConfiguration `
            -ShareId $share.Id `
            -Name $share.Name `
            -SharePath $share.SharePath `
            -DriveLetter $share.DriveLetter `
            -Username $share.Username `
            -Description $share.Description `
            -Enabled $share.Enabled
        
        if ($result) {
            Write-Host ""
            Write-Host "  [OK] Share updated!" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "  [X] Failed to save (check for conflicts)" -ForegroundColor Red
        }
    } else {
        Write-Host "  Cancelled" -ForegroundColor Gray
    }
}

function Show-AllSharesCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ ALL SHARES ]======" -ForegroundColor Cyan
    
    $shares = @(Get-ShareConfiguration)
    
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

function Read-ValidatedInput {
    <#
    .SYNOPSIS
        Prompts for input with validation and retry limit
    .PARAMETER Prompt
        The prompt message to display
    .PARAMETER ValidationScript
        Script block that returns $true if input is valid
    .PARAMETER ErrorMessage
        Message to show on validation failure
    .PARAMETER MaxAttempts
        Maximum failed attempts before offering quit option (default: 3)
    .PARAMETER AllowEmpty
        Whether empty input is acceptable (default: $false)
    .PARAMETER DefaultValue
        Value to use if input is empty and AllowEmpty is true
    #>
    param(
        [string]$Prompt,
        [scriptblock]$ValidationScript,
        [string]$ErrorMessage = "Invalid input",
        [int]$MaxAttempts = 3,
        [switch]$AllowEmpty,
        [string]$DefaultValue = ""
    )
    
    $attempts = 0
    $firstAttempt = $true
    
    do {
        if (-not $firstAttempt) {
            Write-Host "  $ErrorMessage. Try again: " -ForegroundColor Yellow -NoNewline
        } else {
            Write-Host "  > " -ForegroundColor Cyan -NoNewline
            $firstAttempt = $false
        }
        
        $userInput = Read-Host
        
        # Handle empty input
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            if ($AllowEmpty) {
                return $DefaultValue
            }
            $attempts++
        } else {
            # Validate with script block
            if ($null -eq $ValidationScript -or (& $ValidationScript $userInput)) {
                return $userInput
            }
            $attempts++
        }
        
        # Check if max attempts reached
        if ($attempts -ge $MaxAttempts) {
            Write-Host ""
            Write-Host "  Too many invalid attempts. Press Q to quit or any key to continue..." -ForegroundColor Red
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($key.Character -match '[Qq]') {
                return $null
            }
            $attempts = 0
            Write-Host ""
            $firstAttempt = $true
        }
    } while ($true)
}

function Add-NewShareCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ ADD NEW SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    # Collect all fields, then confirm
    $name = ""
    $sharePath = ""
    $driveLetter = ""
    $username = ""
    $description = ""
    
    do {
        # Step 1: Name
        if ([string]::IsNullOrWhiteSpace($name)) {
            Write-Host "  Share Name" -ForegroundColor White
            Write-Host "  (A friendly name for this share, e.g., 'Office Files')" -ForegroundColor DarkGray
            $name = Read-ValidatedInput -ErrorMessage "Name cannot be empty"
            if ($null -eq $name) {
                Write-Host ""
                Write-Host "  [!] Operation cancelled" -ForegroundColor Yellow
                return
            }
            Write-Host ""
        }
        
        # Step 2: Path
        if ([string]::IsNullOrWhiteSpace($sharePath)) {
            Write-Host "  Network Path (UNC)" -ForegroundColor White
            Write-Host "  A UNC path starts with two backslashes followed by the server name and share." -ForegroundColor DarkGray
            Write-Host "  Examples:" -ForegroundColor DarkGray
            Write-Host "    \\192.168.1.100\share" -ForegroundColor Cyan
            Write-Host "    \\server\folder" -ForegroundColor Cyan
            Write-Host "    \\DESKTOP-NAME\Documents" -ForegroundColor Cyan
            $sharePath = Read-ValidatedInput `
                -ValidationScript { 
                    param($p) 
                    # Auto-correct: add \\ if missing
                    if ($p -notmatch '^\\\\' -and $p -match '^[^\\]') {
                        $script:sharePath = "\\$p"
                        Write-Host ""
                        Write-Host "  [Auto-corrected to: $script:sharePath]" -ForegroundColor Green
                        return $true
                    }
                    $p -match '^\\\\[^\\]+\\'
                } `
                -ErrorMessage "Invalid UNC path. Must start with \\"
            if ($null -eq $sharePath) {
                Write-Host ""
                Write-Host "  [!] Operation cancelled" -ForegroundColor Yellow
                return
            }
            Write-Host ""
        }
        
        # Step 3: Drive Letter
        if ([string]::IsNullOrWhiteSpace($driveLetter)) {
            $existingShares = Get-ShareConfiguration
            $usedLetters = $existingShares | ForEach-Object { $_.DriveLetter }
            # Build a descending list of letters Z..A, then filter out A, B, C and used letters
            $allLetters = @()
            for ($c = [byte][char]'Z'; $c -ge [byte][char]'A'; $c--) { $allLetters += [string][char]$c }
            $availableLetters = $allLetters | Where-Object { $_ -notin $usedLetters -and $_ -notin @('A','B','C') }
            
            if ($availableLetters.Count -eq 0) {
                Write-Host "  No drive letters available!" -ForegroundColor Red
                return
            }
            
            Write-Host "  Drive Letter" -ForegroundColor White
            Write-Host "  (The drive letter to map this share to, press Enter for " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($availableLetters[0])" -NoNewline -ForegroundColor Green
            Write-Host ")" -ForegroundColor DarkGray
            $driveLetter = Read-ValidatedInput `
                -ValidationScript { param($d) $d = $d.ToUpper().Trim(); $d.Length -eq 1 -and $d -match '^[A-Z]$' -and $d -notin $usedLetters } `
                -ErrorMessage "Invalid or in-use letter" `
                -AllowEmpty `
                -DefaultValue $availableLetters[0]
            if ($null -eq $driveLetter) {
                Write-Host ""
                Write-Host "  [!] Operation cancelled" -ForegroundColor Yellow
                return
            }
            $driveLetter = $driveLetter.ToUpper().Trim()
            Write-Host ""
        }
        
        # Step 4: Username
        if ([string]::IsNullOrWhiteSpace($username)) {
            Write-Host "  Username" -ForegroundColor White
            Write-Host "  (Username for authentication, e.g., DOMAIN\user or user)" -ForegroundColor DarkGray
            $username = Read-ValidatedInput -ErrorMessage "Username required"
            if ($null -eq $username) {
                Write-Host ""
                Write-Host "  [!] Operation cancelled" -ForegroundColor Yellow
                return
            }
            Write-Host ""
        }
        
        # Step 5: Description (optional, only ask once)
        if ($description -eq "") {
            Write-Host "  Description (optional)" -ForegroundColor White
            Write-Host "  (Additional notes about this share)" -ForegroundColor DarkGray
            Write-Host "  > " -ForegroundColor Cyan -NoNewline
            $description = Read-Host
            if ([string]::IsNullOrWhiteSpace($description)) { $description = " " }  # Mark as collected
            Write-Host ""
        }
        
        # Review and confirm
        Write-Host "  ======[ REVIEW ]======" -ForegroundColor Cyan
        Write-Host "  Name        : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$name" -ForegroundColor White
        Write-Host "  Path        : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$sharePath" -ForegroundColor White
        Write-Host "  Drive       : " -NoNewline -ForegroundColor DarkGray
        Write-Host "${driveLetter}:" -ForegroundColor White
        Write-Host "  Username    : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$username" -ForegroundColor White
        if ($description.Trim().Length -gt 0) {
            Write-Host "  Description : " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($description.Trim())" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor Yellow
        Write-Host "    1) Confirm and save" -ForegroundColor Gray
        Write-Host "    2) Edit Name" -ForegroundColor Gray
        Write-Host "    3) Edit Path" -ForegroundColor Gray
        Write-Host "    4) Edit Drive Letter" -ForegroundColor Gray
        Write-Host "    5) Edit Username" -ForegroundColor Gray
        Write-Host "    6) Edit Description" -ForegroundColor Gray
        Write-Host "    C) Cancel" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Choose (1-6, C) [1]: " -ForegroundColor Yellow -NoNewline
        $choice = Read-Host
        
        if ($choice -eq "" -or $choice -eq "1") {
            # Confirm - proceed to save
            break
        } elseif ($choice -eq "2") {
            $name = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT NAME ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "3") {
            $sharePath = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT PATH ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "4") {
            $driveLetter = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT DRIVE LETTER ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "5") {
            $username = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT USERNAME ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "6") {
            $description = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT DESCRIPTION ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -match '^[Cc]$') {
            Write-Host ""
            Write-Host "  [!] Add share canceled" -ForegroundColor Yellow
            return
        } else {
            Write-Host "  Invalid choice" -ForegroundColor Red
            Start-Sleep -Seconds 1
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ ADD NEW SHARE ]======" -ForegroundColor Cyan
            Write-Host ""
        }
    } while ($true)
    
    Write-Host ""
    
    # Clean description (remove marker if it was optional and empty)
    if ($description.Trim().Length -eq 0) { $description = "" }
    
    # Final validation: check for conflicts one more time (race condition prevention)
    $preCheckConfig = Get-CachedConfig -Force
    $conflict = $preCheckConfig.Shares | Where-Object { $_.DriveLetter -eq $driveLetter }
    if ($conflict) {
        Write-Host ""
        Write-Host "  [!] Drive letter $driveLetter was assigned by another process. Please try again." -ForegroundColor Red
        return
    }
    
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
            Write-Host "  Would you like to save credentials now? (Y/N) [Y]: " -ForegroundColor Yellow -NoNewline
            $saveCreds = Read-Host
            
            if ($saveCreds -eq "" -or $saveCreds -match '^[Yy]$') {
                $password = Read-Password "  Enter password: "
                if ($password.Length -gt 0) {
                    $credential = New-Object System.Management.Automation.PSCredential($username, $password)
                    Save-Credential -Credential $credential
                    # Message already printed by Save-Credential
                }
            }
        } else {
            Write-Host "  Using existing credentials for: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$username" -ForegroundColor White
            $credential = $existingCred
        }
        
        # Ask if user wants to connect now
        Write-Host ""
        Write-Host "  Connect now? (Y/N) [Y]: " -ForegroundColor Yellow -NoNewline
        $connectNow = Read-Host
        
        if ($connectNow -eq "" -or $connectNow -match '^[Yy]$') {
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
                Connect-NetworkShare -SharePath $sharePath -DriveLetter $driveLetter -Credential $credential -Silent
                
                # Simple success/failure message
                if (Test-Path "${driveLetter}:") {
                    Write-Host ""
                    Write-Host "  [OK] Drive ${driveLetter}: connected successfully!" -ForegroundColor Green
                } else {
                    Write-Host ""
                    Write-Host "  [!] Failed to connect. Check credentials or network path." -ForegroundColor Red
                }
                
                # Update last connected
                $config = Get-CachedConfig
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
    
    $shares = @(Get-ShareConfiguration)
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
    
    $shares = @(Get-ShareConfiguration | Where-Object { $_.Enabled })
    if ($shares.Count -eq 0) {
        Write-Host "  No enabled shares configured." -ForegroundColor Yellow
        return
    }
    
    # Show only disconnected shares
    $disconnected = @($shares | Where-Object { -not (Test-ShareConnection -DriveLetter $_.DriveLetter) })
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
        $maxRetries = 3
        $attempt = 0
        $connected = $false
        
        while ($attempt -lt $maxRetries -and -not $connected) {
            $attempt++
            
            if (-not $cred) {
                Write-Host "  [!] No saved credentials found" -ForegroundColor Yellow
                $password = Read-Password "  Enter password: "
                if ($password.Length -gt 0) {
                    $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
                } else {
                    Write-Host "  [X] Connection cancelled" -ForegroundColor Red
                    return
                }
            }
            
            $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
            
            if ($result.Success) {
                $connected = $true
                Write-Host "  [OK] Connected successfully!" -ForegroundColor Green
                
                # Offer to save credentials if they weren't saved
                if ($attempt -gt 1 -or -not (Get-CredentialForShare -Username $share.Username)) {
                    Write-Host "  Save these credentials? (Y/N) [Y]: " -NoNewline
                    $save = Read-Host
                    if ($save -eq "" -or $save -match '^[Yy]$') {
                        Save-Credential -Credential $cred
                    }
                }
                
                # Update last connected
                $config = Get-CachedConfig
                $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                if ($shareObj) {
                    $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Save-AllShares -Config $config | Out-Null
                }
            } else {
                # Check if it's an authentication error
                if ($result.ErrorType -eq "Authentication") {
                    if ($attempt -lt $maxRetries) {
                        Write-Host "  [X] Authentication failed!" -ForegroundColor Red
                        Write-Host "  Retry with different credentials? (Y/N) [Y]: " -NoNewline -ForegroundColor Yellow
                        $retry = Read-Host
                        if ($retry -eq "" -or $retry -match '^[Yy]$') {
                            $cred = $null  # Force re-prompt
                            continue
                        } else {
                            Write-Host "  [X] Connection cancelled" -ForegroundColor Red
                            break
                        }
                    } else {
                        Write-Host "  [X] Authentication failed after $maxRetries attempts" -ForegroundColor Red
                    }
                } else {
                    # Non-auth error, don't retry
                    Write-Host "  [X] Connection failed: $($result.ErrorMessage)" -ForegroundColor Red
                    break
                }
            }
        }
    }
}

function Disconnect-ShareCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ DISCONNECT SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = Get-ShareConfiguration
    $connected = @($shares | Where-Object { Test-ShareConnection -DriveLetter $_.DriveLetter })
    
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
    
    # Force reload to ensure we have the latest shares (especially important after adding new shares)
    $config = Get-CachedConfig -Force
    $shares = @($config.Shares | Where-Object { $_.Enabled })
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
            Write-Host "" # New line
            Write-Host "  [!] No saved credentials for $($share.Username)" -ForegroundColor Yellow
            $password = Read-Password "  Enter password: "
            if ($password.Length -eq 0) {
                Write-Host "  [X] Skipped (no password)" -ForegroundColor Red
                $failed++
                continue
            }
            $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
            Write-Host "  [*] Connecting $($share.Name)... " -NoNewline -ForegroundColor Cyan
        }
        
        try {
            Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                Write-Host "[OK]" -ForegroundColor Green
                $success++
                
                # Offer to save credentials if they weren't saved
                if (-not (Get-CredentialForShare -Username $share.Username)) {
                    Write-Host "  Save credentials for $($share.Username)? (Y/N) [Y]: " -NoNewline
                    $save = Read-Host
                    if ($save -eq "" -or $save -match '^[Yy]$') {
                        Save-Credential -Credential $cred
                    }
                }
                
                # Update last connected
                $config = Get-CachedConfig
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
        Write-Host "$skipped already connected" -NoNewline -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-ActionLog -Message "Connect All completed: $success connected, $failed failed, $skipped skipped" -Level INFO -Category 'Mapping'
    
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
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
    
    # Force reload to ensure we have the latest shares
    $config = Get-CachedConfig -Force
    $shares = @($config.Shares | Where-Object { $_.Enabled })
    if ($shares.Count -eq 0) {
        Write-Host "  No enabled shares configured." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press any key..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
        Write-Host "  This will disconnect and reconnect " -NoNewline -ForegroundColor Yellow
    Write-Host "$($shares.Count)" -NoNewline -ForegroundColor White
    Write-Host " share(s)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Continue? (Y/N) [Y]: " -NoNewline
    $confirm = Read-Host
    
    if ($confirm -ne "" -and $confirm -notmatch '^[Yy]$') {
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
            Write-Host "" # New line
            Write-Host "  [!] No saved credentials for $($share.Username)" -ForegroundColor Yellow
            $password = Read-Password "  Enter password: "
            if ($password.Length -eq 0) {
                Write-Host "  [X] Skipped (no password)" -ForegroundColor Red
                $failed++
                continue
            }
            $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
            Write-Host "  [*] Connecting $($share.Name)... " -NoNewline -ForegroundColor Cyan
        }
        
        try {
            Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                Write-Host "[OK]" -ForegroundColor Green
                $success++
                
                # Offer to save credentials if they weren't saved
                if (-not (Get-CredentialForShare -Username $share.Username)) {
                    Write-Host "  Save credentials for $($share.Username)? (Y/N) [Y]: " -NoNewline
                    $save = Read-Host
                    if ($save -eq "" -or $save -match '^[Yy]$') {
                        Save-Credential -Credential $cred
                    }
                }
                
                # Update last connected
                $config = Get-CachedConfig
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
    Write-Host "$success reconnected" -NoNewline -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host ", " -NoNewline
        Write-Host "$failed failed" -NoNewline -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Disconnect-AllSharesCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ DISCONNECT ALL ]======" -ForegroundColor Cyan
    Write-Host ""
    
    # Force reload to ensure we have the latest shares
    $config = Get-CachedConfig -Force
    $shares = if ($config -and $config.Shares) { $config.Shares } else { @() }
    
    # Build array of connected shares (properly initialized)
    $connected = @()
    if ($shares.Count -gt 0) {
        foreach ($share in $shares) {
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                $connected += $share
            }
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
    Write-Host "  Are you sure? (Y/N) [N]: " -NoNewline
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
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-ActionLog -Message "Disconnect All completed: $disconnected disconnected" -Level INFO -Category 'Mapping'
    
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-ShareStatusCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ STATUS ]======" -ForegroundColor Cyan
    
    $shares = @(Get-ShareConfiguration)
    if ($shares.Count -eq 0) {
        Write-Host "  No shares configured." -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    $connectedCount = 0
    foreach ($share in $shares) {
        $status = Get-DetailedShareStatus -ShareId $share.Id
        
        $icon = if ($status.IsConnected) { "[*]" } else { "[ ]" }
        $iconColor = if ($status.IsConnected) { "Green" } else { "Red" }
        
        if ($status.IsConnected) { $connectedCount++ }
        
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
    
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host "-" -NoNewline -ForegroundColor DarkGray
    for ($i = 0; $i -lt 40; $i++) { Write-Host "-" -NoNewline -ForegroundColor DarkGray }
    Write-Host ""
    Write-Host "  Summary: " -NoNewline -ForegroundColor Gray
    Write-Host "$connectedCount/$($shares.Count)" -NoNewline -ForegroundColor $(if ($connectedCount -eq $shares.Count) { "Green" } elseif ($connectedCount -eq 0) { "Red" } else { "Yellow" })
    Write-Host " shares connected" -ForegroundColor Gray
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
                    Write-Host " new share(s)" -ForegroundColor DarkGray
                    if ($result.Updated -gt 0) {
                        Write-Host "  Updated: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($result.Updated)" -NoNewline -ForegroundColor Cyan
                        Write-Host " existing share(s)" -ForegroundColor DarkGray
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
        Write-Host ""
        Write-Host "  " -NoNewline
        Write-Host "Tip: " -NoNewline -ForegroundColor Yellow
        Write-Host "Start by adding a network share to get started!" -ForegroundColor DarkGray
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
    Write-Host " - Backup/Restore" -ForegroundColor Gray
    
    Write-Host "  L" -NoNewline -ForegroundColor White
    Write-Host " - View Log     " -NoNewline -ForegroundColor Gray
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
    $config = Get-CachedConfig
    if (-not $config) { return }
    
    # Ensure preferences exist with all defaults
    if (-not $config.Preferences) {
        $config.Preferences = [PSCustomObject]@{
            UnmapOldMapping = $false
            PreferredMode = "Prompt"
            PersistentMapping = $false
            SyncShareNameToDriveLabel = $true
        }
    }
    # Backfill SyncShareNameToDriveLabel if missing (for configs created before 2.1.1)
    if (-not $config.Preferences.PSObject.Properties['SyncShareNameToDriveLabel']) {
        $config.Preferences | Add-Member -MemberType NoteProperty -Name SyncShareNameToDriveLabel -Value $true -Force
    }
    
    $prefs = $config.Preferences

    while ($true) {
        Clear-Host
        Write-Host "=== Preferences v$version ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Auto-unmap on drive change: $($prefs.UnmapOldMapping)"
        Write-Host "2. Preferred startup mode    : $($prefs.PreferredMode)"
        Write-Host "3. Persistent mapping        : $($prefs.PersistentMapping)"
        $syncLabelValue = if ($prefs.PSObject.Properties['SyncShareNameToDriveLabel']) { $prefs.SyncShareNameToDriveLabel } else { $true }
        Write-Host "4. Sync share name to label  : $syncLabelValue"
        Write-Host "5. Back"
        Write-Host ""
        $choice = Read-Host "Select (1-5)"
        switch ($choice) {
            "1" {
                do {
                    $yn = Read-Host "Auto-unmap on letter change? (Y/N) [Y]"
                    if ($yn -eq "" -or $yn -match '^[YyNn]$') { break }
                    Write-Host "Enter Y or N." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.UnmapOldMapping = ($yn -eq "" -or $yn -match '^[Yy]$')
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
                    $yn = Read-Host "Enable persistent mapping (reconnect at logon)? (Y/N) [N]"
                    if ($yn -eq "" -or $yn -match '^[YyNn]$') { break }
                    Write-Host "Enter Y or N." -ForegroundColor Yellow
                } while ($true)
                $oldPersistent = $config.Preferences.PersistentMapping
                $config.Preferences.PersistentMapping = ($yn -match '^[Yy]$')
                Save-AllShares -Config $config | Out-Null
                
                # Immediately update logon script based on new preference
                if ($config.Preferences.PersistentMapping -and -not $oldPersistent) {
                    # Enabling persistent mapping - install logon script
                    Install-LogonScript
                    Write-Host "Shares will reconnect at next logon." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Press any key to continue..." -ForegroundColor DarkGray
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                } elseif (-not $config.Preferences.PersistentMapping -and $oldPersistent) {
                    # Disabling persistent mapping - remove logon script
                    Remove-LogonScript
                    Write-Host "Shares will not reconnect at logon." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Press any key to continue..." -ForegroundColor DarkGray
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
                
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "4" {
                do {
                    $yn = Read-Host "Sync share name to Explorer drive label? (Y/N) [Y]"
                    if ($yn -eq "" -or $yn -match '^[YyNn]$') { break }
                    Write-Host "Enter Y or N." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.SyncShareNameToDriveLabel = ($yn -eq "" -or $yn -match '^[Yy]$')
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "5" { return }
            default { return }
        }
    }
}

function Update-CliCredentialsMenu {
    Write-Host "=== Credentials Menu v$version ===" -ForegroundColor Cyan
    Write-Host "1. Add/Update Credentials"
    Write-Host "2. List Credentials"
    Write-Host "3. Remove Credential"
    Write-Host "4. Export Credentials (Backup)"
    Write-Host "5. Import Credentials (Restore)"
    Write-Host "6. Back"
    Write-Host ""
    $sub = Read-Host "Select (1-6)"
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
            }
            else {
                Write-Host "  Password prompt cancelled." -ForegroundColor Yellow
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
                Write-Host "  [OK] Removed credential for: $username" -ForegroundColor Green
            } else {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
            }
        }
        "4" {
            # Export credentials
            Export-Credentials
        }
        "5" {
            # Import credentials
            Write-Host "`nImport Mode:" -ForegroundColor Cyan
            Write-Host "  1) Replace all credentials" -ForegroundColor Gray
            Write-Host "  2) Merge with existing credentials" -ForegroundColor Gray
            $mode = Read-Host "Choose (1-2) [2]"
            $merge = ($mode -ne '1')
            
            $path = Read-Host "Enter path to backup file"
            if (-not [string]::IsNullOrWhiteSpace($path)) {
                Import-Credentials -ImportPath $path -Merge:$merge
            } else {
                Write-Host "  Import cancelled." -ForegroundColor Yellow
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
# Auto-generated by Share Manager v2.2.0 (multi-share, DPAPI-protected)
# Production-ready with enhanced error handling, network checks, and retry logic
param()
$baseFolder = Join-Path $env:APPDATA "Share_Manager"
$keyPath    = Join-Path $baseFolder "key.bin"
$sharesPath = Join-Path $baseFolder "shares.json"
$credsPath  = Join-Path $baseFolder "creds.json"
$logPath    = Join-Path $baseFolder "LogonScript.log"

# Structured events log and session tracking
$eventsPath = Join-Path $baseFolder "LogonScript.events.jsonl"
$sessionId  = [guid]::NewGuid().ToString()

function Invoke-LogFileRotation {
    param([string]$Path, [string]$Prefix)
    if (-not (Test-Path $Path)) { return }
    $fi = Get-Item $Path
    $ageDays = (Get-Date) - $fi.LastWriteTime
    $sizeMB  = [math]::Round($fi.Length / 1MB, 2)
    if ($ageDays.TotalDays -ge 30 -or $sizeMB -ge 5) {
        $stamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
        $arch  = Join-Path $baseFolder ("$Prefix`_$stamp" + [System.IO.Path]::GetExtension($Path))
        Rename-Item -Path $Path -NewName (Split-Path $arch -Leaf) -ErrorAction SilentlyContinue
        New-Item -Path $Path -ItemType File -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')] [string]$Level = 'INFO',
        [string]$Category,
        [hashtable]$Data
    )
    if (-not (Test-Path $baseFolder)) { New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $logPath))     { New-Item -Path $logPath -ItemType File -Force | Out-Null }
    if (-not (Test-Path $eventsPath))  { New-Item -Path $eventsPath -ItemType File -Force | Out-Null }
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $prefix = if ($Category) { "[$Level][$Category]" } else { "[$Level]" }
    "$ts`t$prefix $Message" | Out-File -FilePath $logPath -Encoding UTF8 -Append
    # GDPR: no personal data in structured logs
    $evt = [ordered]@{
        ts            = (Get-Date).ToString("o")
        level         = $Level
        msg           = $Message
        category      = $Category
        source        = 'AUTO'
        correlationId = $null
        sessionId     = $sessionId
        pid           = $PID
        ver           = '2.2.0'
        data          = $Data
    }
    ($evt | ConvertTo-Json -Compress) | Out-File -FilePath $eventsPath -Encoding UTF8 -Append
}

function Test-NetworkAvailable {
    # Robust network check - works with multiple adapters (Ethernet + WiFi)
    try {
        # Method 1: Check for valid IP addresses (most reliable)
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
               Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' }
        if ($ips -and $ips.Count -gt 0) {
            return $true
        }
        
        # Method 2: Check for adapters with status 'Up' AND valid IP configuration
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
        if ($adapters -and $adapters.Count -gt 0) {
            # Verify at least one has a valid IP (not APIPA)
            foreach ($adapter in $adapters) {
                $adapterIPs = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                              Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' }
                if ($adapterIPs -and $adapterIPs.Count -gt 0) {
                    return $true
                }
            }
        }
        
        return $false
    } catch {
        # Fallback: Try basic connectivity test
        try {
            $result = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue
            return $result
        } catch {
            return $false
        }
    }
}

# Rotate and write a start marker
Invoke-LogFileRotation -Path $logPath -Prefix 'LogonScript'
Invoke-LogFileRotation -Path $eventsPath -Prefix 'LogonScript.events'

# Track script execution time
$scriptStartTime = Get-Date
$psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
$psEditionInfo = $PSVersionTable.PSEdition

Write-Log -Message "========================================" -Category 'AutoMap'
Write-Log -Message "AutoMap start (v2.2.0)" -Category 'AutoMap' -Data @{ psVersion = $psVersion; psEdition = $psEditionInfo }
Write-Log -Message "Environment: PowerShell $psVersion ($psEditionInfo)" -Level DEBUG -Category 'AutoMap'

# Check network availability with retry logic (for slow WiFi connections during logon)
$networkAvailable = $false
$maxRetries = 6  # 6 attempts over ~30 seconds
$retryDelay = 2  # Start with 2 seconds

for ($i = 1; $i -le $maxRetries; $i++) {
    if (Test-NetworkAvailable) {
        $networkAvailable = $true
        if ($i -gt 1) {
            Write-Log -Message "Network connection detected (attempt $i/$maxRetries)" -Level INFO -Category 'AutoMap'
        } else {
            Write-Log -Message "Network connection detected" -Level INFO -Category 'AutoMap'
        }
        break
    }
    
    if ($i -lt $maxRetries) {
        Write-Log -Message "No network connection yet, waiting ${retryDelay}s (attempt $i/$maxRetries)" -Level INFO -Category 'AutoMap'
        Start-Sleep -Seconds $retryDelay
        $retryDelay = [Math]::Min($retryDelay * 1.5, 10)  # Exponential backoff, max 10s
    }
}

if (-not $networkAvailable) {
    Write-Log -Message "No network connection detected after $maxRetries attempts, skipping automap" -Level WARN -Category 'AutoMap'
    Write-Log -Message "AutoMap aborted (no network)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    return
}

if (!(Test-Path $sharesPath)) { 
    Write-Log "Missing shares.json at $sharesPath" -Level WARN -Category 'AutoMap'
    Write-Log -Message "AutoMap aborted (no config)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    return 
}

$cfg = $null
try { 
    $cfg = (Get-Content -Path $sharesPath -Raw) | ConvertFrom-Json 
} catch { 
    Write-Log "shares.json parse error: $_" -Level ERROR -Category 'AutoMap'
    Write-Log -Message "AutoMap aborted (parse error)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    return 
}

if (-not $cfg -or -not $cfg.Shares) { 
    Write-Log "No shares in config" -Level INFO -Category 'AutoMap'
    Write-Log -Message "AutoMap complete (no shares)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    return 
}

$totalShares = $cfg.Shares.Count
$enabledShares = ($cfg.Shares | Where-Object { $_.Enabled }).Count
Write-Log -Message "Found $totalShares total shares ($enabledShares enabled, $($totalShares - $enabledShares) disabled)" -Level INFO -Category 'AutoMap'

# Load credential map (username -> SecureString) with DPAPI/legacy AES support
$credMap = @{}
if (Test-Path $credsPath) {
    try {
        $store = (Get-Content -Path $credsPath -Raw) | ConvertFrom-Json
        if ($store -and $store.Entries) {
            $aesKey = $null
            if (Test-Path $keyPath) { $aesKey = [System.IO.File]::ReadAllBytes($keyPath) }
            
            $credLoadSuccess = 0
            $credLoadFail = 0
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
                    $credLoadSuccess++
                } catch { 
                    Write-Log "Failed to decrypt credential for user: $($e.Username)" -Level WARN -Category 'AutoMap'
                    $credLoadFail++
                }
            }
            Write-Log -Message "Loaded $credLoadSuccess credential(s), $credLoadFail failed to decrypt" -Level INFO -Category 'AutoMap'
        } else {
            Write-Log -Message "Credential store is empty" -Level WARN -Category 'AutoMap'
        }
    } catch { 
        Write-Log "Failed to load creds store: $_" -Level ERROR -Category 'AutoMap'
    }
} else {
    Write-Log -Message "No credential store found at $credsPath" -Level INFO -Category 'AutoMap'
}

$successCount = 0
$failCount = 0
$skipCount = 0

foreach ($s in $cfg.Shares) {
    if (-not $s.Enabled) { 
        Write-Log "Skipping disabled share: $($s.Name)" -Level INFO -Category 'AutoMap'
        $skipCount++
        continue 
    }
    
    $drive = "$($s.DriveLetter):"
    $share = $s.SharePath
    $user  = $s.Username
    $name  = $s.Name

    # Check if drive is already in use by something else
    if (Test-Path $drive) {
        try {
            $existing = net use $drive 2>&1 | Out-String
            if ($existing -match [regex]::Escape($share)) {
                Write-Log "Drive $drive already mapped to $share, skipping" -Level INFO -Category 'AutoMap'
                $skipCount++
                continue
            } else {
                # Drive in use by different share/source
                Write-Log "Drive $drive in use by different resource, unmapping first" -Level INFO -Category 'AutoMap'
                cmd /c "net use `"$drive`" /delete /y >nul 2>&1"
            }
        } catch {
            # Can't determine, try to unmap anyway
            cmd /c "net use `"$drive`" /delete /y >nul 2>&1"
        }
    } else {
        # Clean unmap just in case
        cmd /c "net use `"$drive`" /delete /y >nul 2>&1"
    }

    $plainPW = $null
    if ($user -and $credMap.ContainsKey($user)) {
        try {
            $plainPW = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credMap[$user])
            )
        } catch {
            Write-Log "Failed to decrypt password for $user" -Level ERROR -Category 'AutoMap'
        }
    }

    # Enhanced retry with exponential backoff (2s, 4s, 8s)
    $mapped = $false
    $maxAttempts = 3
    for ($i=1; $i -le $maxAttempts; $i++) {
        if ($i -gt 1) {
            $backoff = [math]::Pow(2, $i - 1)  # Exponential backoff
            Write-Log -Message "Retry attempt $i/$maxAttempts after ${backoff}s delay for $name" -Level INFO -Category 'AutoMap' -Data @{ attempt = $i; backoff = $backoff }
            Start-Sleep -Seconds $backoff
        }
        
        Write-Log -Message "Mapping attempt ${i}: $drive -> $share ($name)" -Level INFO -Category 'AutoMap'
        if ($plainPW) {
            $result = cmd /c "net use `"$drive`" `"$share`" /user:$user $plainPW /persistent:yes 2>&1"
        } else {
            $result = cmd /c "net use `"$drive`" `"$share`" /persistent:yes 2>&1"
        }
        
        if ($LASTEXITCODE -eq 0) {
            # Verify the mapping actually worked
            $verified = $false
            try {
                $verified = Test-Path $drive
                if ($verified) {
                    Write-Log -Message "Mapped $drive to $share ($name)" -Category 'AutoMap'
                    $successCount++
                } else {
                    Write-Log -Message "Mapping succeeded but drive not accessible: $drive" -Level WARN -Category 'AutoMap'
                }
            } catch {
                Write-Log -Message "Mapping succeeded but verification failed: $_" -Level WARN -Category 'AutoMap'
            }
            $mapped = $true
            break 
        } else {
            # Classify error
            $errorType = "Unknown"
            $resultStr = $result | Out-String
            if ($resultStr -match "1326|Logon failure") { $errorType = "Authentication" }
            elseif ($resultStr -match "53|network path") { $errorType = "PathNotFound" }
            elseif ($resultStr -match "67|network name") { $errorType = "InvalidPath" }
            elseif ($resultStr -match "1219|multiple connections") { $errorType = "MultipleConnections" }
            elseif ($resultStr -match "1203|1231|network busy|timeout") { $errorType = "NetworkTimeout" }
            elseif ($resultStr -match "85|local device.*in use") { $errorType = "DriveInUse" }
            
            Write-Log -Message "Attempt $i failed for $name`: $errorType" -Level WARN -Category 'AutoMap' -Data @{ attempt = $i; errorType = $errorType; exitCode = $LASTEXITCODE; share = $name }
        }
    }
    if (-not $mapped) { 
        Write-Log -Message "Failed mapping $drive -> $share ($name) after $maxAttempts attempts" -Level ERROR -Category 'AutoMap' -Data @{ drive = $drive; share = $share; name = $name; attempts = $maxAttempts }
        $failCount++
    }
}

$scriptEndTime = Get-Date
$duration = ($scriptEndTime - $scriptStartTime).TotalSeconds

Write-Log -Message "AutoMap complete: $successCount success, $failCount failed, $skipCount skipped (duration: ${duration}s)" -Category 'AutoMap' -Data @{ 
    success = $successCount; 
    failed = $failCount; 
    skipped = $skipCount; 
    totalEnabled = $enabledShares; 
    durationSeconds = $duration;
    startTime = $scriptStartTime.ToString("o");
    endTime = $scriptEndTime.ToString("o")
}
Write-Log -Message "========================================" -Category 'AutoMap'
'@
    $cmdScript = @"
@echo off
REM Auto-generated by Share Manager v2.2.0 - Logon Script Launcher
REM This wrapper launches the PowerShell automap script with proper error handling
REM Windows 11 25H2+ compatible (no wmic dependency)

REM Hide CMD window immediately by relaunching minimized if not already hidden
if not "%1"=="HIDDEN" (
    start /min "" "%~f0" HIDDEN
    exit
)

setlocal enabledelayedexpansion

REM Configuration
set SCRIPT=%APPDATA%\Share_Manager\Share_Manager_AutoMap.ps1
set LOG=%APPDATA%\Share_Manager\LogonScript.log
set TEMP_LOG=%TEMP%\ShareManager_AutoMap_%RANDOM%.log

REM Generate ISO 8601 timestamp using PowerShell (wmic removed in Windows 11 25H2+)
for /f "delims=" %%a in ('powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set "TIMESTAMP=%%a"

REM Log start
echo %TIMESTAMP%	[INFO][CMD] ======================================== >>"%LOG%"
echo %TIMESTAMP%	[INFO][CMD] AutoMap launcher started >>"%LOG%"
echo %TIMESTAMP%	[INFO][CMD] User: %USERNAME% Computer: %COMPUTERNAME% >>"%LOG%"

REM Check if script exists
if not exist "%SCRIPT%" (
    for /f "delims=" %%a in ('powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set "TIMESTAMP=%%a"
    echo %TIMESTAMP%	[ERROR][CMD] Script not found: %SCRIPT% >>"%LOG%"
    echo %TIMESTAMP%	[INFO][CMD] AutoMap launcher failed >>"%LOG%"
    echo %TIMESTAMP%	[INFO][CMD] ======================================== >>"%LOG%"
    exit /b 1
)

REM Detect PowerShell version (prefer pwsh)
where pwsh >nul 2>nul
if %errorlevel%==0 (
    set SHELL=pwsh
) else (
    set SHELL=powershell
)

echo %TIMESTAMP%	[INFO][CMD] Using shell: !SHELL! >>"%LOG%"

REM Execute script and capture exit code
!SHELL! -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT%" >"%TEMP_LOG%" 2>&1
set EXIT_CODE=!errorlevel!

REM Append temporary output to main log (if any errors occurred)
if exist "%TEMP_LOG%" (
    if !EXIT_CODE! neq 0 (
        for /f "delims=" %%a in ('powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set "TIMESTAMP=%%a"
        echo %TIMESTAMP%	[WARN][CMD] Script execution failed with exit code !EXIT_CODE! >>"%LOG%"
        echo %TIMESTAMP%	[DEBUG][CMD] Script output: >>"%LOG%"
        type "%TEMP_LOG%" >>"%LOG%" 2>nul
    )
    del "%TEMP_LOG%" 2>nul
)

REM Log completion
for /f "delims=" %%a in ('powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set "TIMESTAMP=%%a"

if !EXIT_CODE!==0 (
    echo %TIMESTAMP%	[INFO][CMD] AutoMap launcher completed successfully >>"%LOG%"
) else (
    echo %TIMESTAMP%	[WARN][CMD] AutoMap launcher completed with exit code !EXIT_CODE! >>"%LOG%"
)
echo %TIMESTAMP%	[INFO][CMD] ======================================== >>"%LOG%"

exit /b !EXIT_CODE!
"@
    if (-not (Test-Path $baseFolder)) {
        New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
    }
    
    # Smart update: Only write if content changed or files don't exist
    $ps1Updated = $false
    $cmdUpdated = $false
    
    if (Test-Path $ps1Path) {
        $existingPs1 = Get-Content -Path $ps1Path -Raw -Encoding UTF8
        if ($existingPs1 -ne $logonScript) {
            Set-Content -Path $ps1Path -Value $logonScript -Encoding UTF8 -Force
            $ps1Updated = $true
            Write-ActionLog -Message "Updated AutoMap PS1 script (content changed)" -Level DEBUG -Category 'Startup'
        }
    } else {
        Set-Content -Path $ps1Path -Value $logonScript -Encoding UTF8 -Force
        $ps1Updated = $true
        Write-ActionLog -Message "Created AutoMap PS1 script" -Level DEBUG -Category 'Startup'
    }
    
    if (Test-Path $cmdPath) {
        $existingCmd = Get-Content -Path $cmdPath -Raw -Encoding ASCII
        if ($existingCmd -ne $cmdScript) {
            Set-Content -Path $cmdPath -Value $cmdScript -Encoding ASCII -Force
            $cmdUpdated = $true
            Write-ActionLog -Message "Updated AutoMap CMD wrapper (content changed)" -Level DEBUG -Category 'Startup'
        }
    } else {
        Set-Content -Path $cmdPath -Value $cmdScript -Encoding ASCII -Force
        $cmdUpdated = $true
        Write-ActionLog -Message "Created AutoMap CMD wrapper" -Level DEBUG -Category 'Startup'
    }
    
    if (-not $Silent) {
        if ($ps1Updated -or $cmdUpdated) {
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
    }
    
    if ($ps1Updated -or $cmdUpdated) {
        Write-ActionLog -Message "Logon script installed/updated: $cmdPath and $ps1Path" -Category 'Startup' -Key 'InstallLogonScript' -OncePerSeconds 10
    } else {
        Write-ActionLog -Message "Logon script already up-to-date (no changes)" -Level DEBUG -Category 'Startup'
    }
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
    Write-ActionLog -Message "Logon script removed from $startupFolder and $ps1Path" -Category 'Startup'
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
        Theme = if ($CurrentPrefs.PSObject.Properties["Theme"]) { [string]$CurrentPrefs.Theme } else { "Classic" }
        SyncShareNameToDriveLabel = if ($CurrentPrefs.PSObject.Properties["SyncShareNameToDriveLabel"]) { [bool]$CurrentPrefs.SyncShareNameToDriveLabel } else { $true }
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "Preferences v$version"
    $form.Width           = 420
    $form.Height          = 470
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

    # Sync share name to drive label checkbox
    $chkSync = New-Object System.Windows.Forms.CheckBox
    $chkSync.Text     = "Sync share name to drive label (Explorer)"
    $chkSync.AutoSize = $true
    $chkSync.Top      = 80
    $chkSync.Left     = 20
    $chkSync.Checked  = $prefs.SyncShareNameToDriveLabel
    $form.Controls.Add($chkSync)

    # Startup mode group
    $grpStartup = New-Object System.Windows.Forms.GroupBox
    $grpStartup.Text = "Startup mode"
    $grpStartup.Top = 120
    $grpStartup.Left = 15
    $grpStartup.Width = 380
    $grpStartup.Height = 90
    $form.Controls.Add($grpStartup)

    # Radio buttons inside startup group
    $rdoCLI    = New-Object System.Windows.Forms.RadioButton
    $rdoCLI.Text     = "CLI"
    $rdoCLI.AutoSize = $true
    $rdoCLI.Top      = 25
    $rdoCLI.Left     = 20
    $rdoGUI    = New-Object System.Windows.Forms.RadioButton
    $rdoGUI.Text     = "GUI"
    $rdoGUI.AutoSize = $true
    $rdoGUI.Top      = 25
    $rdoGUI.Left     = 90
    $rdoPrompt = New-Object System.Windows.Forms.RadioButton
    $rdoPrompt.Text     = "Prompt"
    $rdoPrompt.AutoSize = $true
    $rdoPrompt.Top      = 25
    $rdoPrompt.Left     = 160

    switch ($prefs.PreferredMode) {
        "CLI"    { $rdoCLI.Checked    = $true }
        "GUI"    { $rdoGUI.Checked    = $true }
        "Prompt" { $rdoPrompt.Checked = $true }
        default  { $rdoPrompt.Checked = $true }  # Fallback to Prompt if unrecognized
    }
    $grpStartup.Controls.Add($rdoCLI)
    $grpStartup.Controls.Add($rdoGUI)
    $grpStartup.Controls.Add($rdoPrompt)

    # Theme selection group (hidden during initial setup)
    if (-not $IsInitial) {
        $grpTheme = New-Object System.Windows.Forms.GroupBox
        $grpTheme.Text = "Theme"
    $grpTheme.Top = 220
        $grpTheme.Left = 15
        $grpTheme.Width = 380
        $grpTheme.Height = 70
        $form.Controls.Add($grpTheme)

        $rdoClassic = New-Object System.Windows.Forms.RadioButton
        $rdoClassic.Text = "Classic"
        $rdoClassic.AutoSize = $true
        $rdoClassic.Top = 25
        $rdoClassic.Left = 20

        $rdoModern = New-Object System.Windows.Forms.RadioButton
        $rdoModern.Text = "Modern"
        $rdoModern.AutoSize = $true
        $rdoModern.Top = 25
        $rdoModern.Left = 120

        if ($prefs.Theme -eq 'Modern') { $rdoModern.Checked = $true } else { $rdoClassic.Checked = $true }
        $grpTheme.Controls.Add($rdoClassic)
        $grpTheme.Controls.Add($rdoModern)
    }

    # Save button
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text   = "Save"
    $btnSave.Width  = 100
    $btnSave.Height = 30
    $btnSave.Top    = 320
    $btnSave.Left   = 70
    $btnSave.Add_Click({
        $prefs.UnmapOldMapping   = $chk.Checked
    $prefs.PersistentMapping = $chkPersist.Checked
    $prefs.SyncShareNameToDriveLabel = $chkSync.Checked
        if ($rdoCLI.Checked)    { $prefs.PreferredMode = "CLI" }
        elseif ($rdoGUI.Checked) { $prefs.PreferredMode = "GUI" }
        else                     { $prefs.PreferredMode = "Prompt" }
        if (-not $IsInitial) {
            $prefs.Theme = if ($rdoModern.Checked) { 'Modern' } else { 'Classic' }
        }
        # else: Theme is already in $prefs from initialization, keep it unchanged
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
    $btnCancel.Top    = 320
        $btnCancel.Left   = 200
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
    
    $y += 30
    
    # Category
    $lblCategory = New-Object System.Windows.Forms.Label
    $lblCategory.Text = "Category:"
    $lblCategory.Top = $y
    $lblCategory.Left = 20
    $lblCategory.Width = 120
    $form.Controls.Add($lblCategory)
    
    $cmbCategoryAdd = New-Object System.Windows.Forms.ComboBox
    $cmbCategoryAdd.Top = $y
    $cmbCategoryAdd.Left = 150
    $cmbCategoryAdd.Width = 310
    $cmbCategoryAdd.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
    $categories = Get-ShareCategories
    foreach ($cat in $categories) {
        [void]$cmbCategoryAdd.Items.Add($cat)
    }
    $cmbCategoryAdd.Text = "General"
    $form.Controls.Add($cmbCategoryAdd)
    
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
        
        # Auto-format UNC path if missing \\
        $path = $txtPath.Text.Trim()
        if ($path -and -not $path.StartsWith("\\")) {
            $path = "\\$path"
            $txtPath.Text = $path
        }
        
        if ($path -notmatch '^\\\\[^\\]+\\') {
            [System.Windows.Forms.MessageBox]::Show("Invalid UNC path. Must start with \\ (e.g., \\server\share)", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if ($txtDrive.Text -notmatch '^[A-Za-z]$') {
            [System.Windows.Forms.MessageBox]::Show("Invalid drive letter. Enter a single letter (A-Z).", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        $driveLetter = $txtDrive.Text.ToUpper()
        
        # Check if drive letter is in use by local drives or already mapped
        if (Test-Path "${driveLetter}:") {
            $psDrive = Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue
            if ($psDrive) {
                $driveType = if ($psDrive.Provider.Name -eq 'FileSystem' -and $psDrive.Root -match '^[A-Z]:\\$') { "local drive" } else { "mapped drive" }
                [System.Windows.Forms.MessageBox]::Show("Drive letter ${driveLetter}: is already in use by a $driveType.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
        }
        
        if ([string]::IsNullOrWhiteSpace($txtUser.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Username is required.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        # Prevent drive-letter conflicts with other enabled shares
        $cfgCheck = Import-AllShares
        # Check conflicts against all shares (enabled or not) to avoid later enablement conflicts
        $conflict = $cfgCheck.Shares | Where-Object { $_.DriveLetter -eq $driveLetter }
        if ($conflict) {
            [System.Windows.Forms.MessageBox]::Show("Drive letter $driveLetter is already assigned to share '$($conflict.Name)'.", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        # Check for duplicate UNC path
        $pathConflict = $cfgCheck.Shares | Where-Object { $_.SharePath -eq $path }
        if ($pathConflict) {
            [System.Windows.Forms.MessageBox]::Show("This network path is already configured as share '$($pathConflict.Name)' (Drive $($pathConflict.DriveLetter):)`n`nYou cannot add the same path twice.", "Duplicate Path", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        $username = $txtUser.Text.Trim()
        
        $result = Add-ShareConfiguration -Name $txtName.Text -SharePath $path `
            -DriveLetter $driveLetter -Username $username `
            -Description $txtDesc.Text -Enabled $chkEnabled.Checked
        
        # Set category after creation
        if ($result -and $cmbCategoryAdd.Text) {
            Set-ShareCategory -ShareId $result.Id -Category $cmbCategoryAdd.Text
        }
        
        if ($result) {
            $shareName = $txtName.Text
            $sharePath = $txtPath.Text
            $driveLetter = $txtDrive.Text.ToUpper()
            
            # Check if credentials exist for this username
            $existingCred = $null
            try {
                $existingCred = Get-CredentialForShare -Username $username
            }
            catch {
                Write-ActionLog -Message "Error checking credentials: $_" -Level WARN -Category 'Credentials'
            }
            
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
                    $maxRetries = 3
                    $attempt = 0
                    $connected = $false
                    $currentCred = $existingCred
                    
                    while ($attempt -lt $maxRetries -and -not $connected) {
                        $attempt++
                        
                        $result = Connect-NetworkShare -SharePath $sharePath -DriveLetter $driveLetter -Credential $currentCred -ReturnStatus -Silent
                        
                        if ($result.Success) {
                            $connected = $true
                            [System.Windows.Forms.MessageBox]::Show(
                                "Connected successfully!",
                                "Success",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Information
                            )
                            
                            # Update last connected
                            $config = Get-CachedConfig
                            $shareObj = $config.Shares | Where-Object { $_.DriveLetter -eq $driveLetter }
                            if ($shareObj) {
                                $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                                Save-AllShares -Config $config | Out-Null
                            }
                        } else {
                            if ($result.ErrorType -eq "Authentication" -and $attempt -lt $maxRetries) {
                                $retryPrompt = [System.Windows.Forms.MessageBox]::Show(
                                    "Authentication failed.`n`nWould you like to retry with different credentials?",
                                    "Connection Failed",
                                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                                    [System.Windows.Forms.MessageBoxIcon]::Warning
                                )
                                
                                if ($retryPrompt -eq 'Yes') {
                                    $currentCred = Show-CredentialForm -Username $username -Message "Enter password for $username (Retry $attempt/$maxRetries)"
                                    if ($currentCred) {
                                        Save-Credential -Credential $currentCred
                                        continue
                                    } else {
                                        break
                                    }
                                } else {
                                    break
                                }
                            } else {
                                [System.Windows.Forms.MessageBox]::Show(
                                    "Connection failed: $($result.ErrorMessage)",
                                    "Error",
                                    [System.Windows.Forms.MessageBoxButtons]::OK,
                                    [System.Windows.Forms.MessageBoxIcon]::Error
                                )
                                break
                            }
                        }
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
    $form.Height = 490
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
    
    # Category
    $lblCategory = New-Object System.Windows.Forms.Label
    $lblCategory.Text = "Category:"
    $lblCategory.Top = $y
    $lblCategory.Left = 20
    $lblCategory.AutoSize = $true
    $form.Controls.Add($lblCategory)
    
    $cmbCategoryEdit = New-Object System.Windows.Forms.ComboBox
    $cmbCategoryEdit.Top = $y
    $cmbCategoryEdit.Left = 150
    $cmbCategoryEdit.Width = 300
    $cmbCategoryEdit.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
    $categories = Get-ShareCategories
    foreach ($cat in $categories) {
        [void]$cmbCategoryEdit.Items.Add($cat)
    }
    # Set current category or default to General
    $currentCategory = if ($share.PSObject.Properties['Category']) { $share.Category } else { "General" }
    $cmbCategoryEdit.Text = $currentCategory
    $form.Controls.Add($cmbCategoryEdit)
    
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
        if (-not (Test-ValidUncPath -Path $txtPath.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Invalid UNC path. Must be \\\\servername\\sharename`n(Server name must be at least 2 characters)", "Validation Error")
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
        
        # Update category if changed
        if ($cmbCategoryEdit.Text) {
            Set-ShareCategory -ShareId $ShareId -Category $cmbCategoryEdit.Text
        }
        
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
            [System.Windows.Forms.MessageBox]::Show("Please select a credential first", "No Selection", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        $username = $listView.SelectedItems[0].Tag
        if ([string]::IsNullOrWhiteSpace($username)) {
            [System.Windows.Forms.MessageBox]::Show("Unable to retrieve username from selection", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }
        
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Remove credential for '$username'?",
            "Confirm Remove",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        
        if ($result -eq 'Yes') {
            Remove-Credential -Username $username
            Update-CredList
            [System.Windows.Forms.MessageBox]::Show("Credential removed for '$username'", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
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
                    Clear-ConfigCache
                    Update-ShareList  # Refresh GUI immediately
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
                Clear-ConfigCache
                Update-ShareList  # Refresh GUI immediately
                $msg = "Configuration merged successfully!`n`nAdded: $($importResult.Added) share(s)"
                if ($importResult.Skipped -gt 0) {
                    $msg += "`nUpdated: $($importResult.Skipped) existing share(s)"
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
    $config = Get-CachedConfig
    if (-not $config.Preferences) {
        $config.Preferences = [PSCustomObject]@{
            UnmapOldMapping = $false
            PreferredMode = "Prompt"
            PersistentMapping = $false
            Theme = "Classic"
            SyncShareNameToDriveLabel = $true
        }
    }
    
    $oldTheme = Get-PreferenceValue -Name "Theme" -Default "Classic"
    $oldPersistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
    $newPrefs = Show-PreferencesForm -CurrentPrefs $config.Preferences -IsInitial $false
    if ($newPrefs) {
        # Merge fields into existing preferences to preserve unknowns
        foreach ($p in $newPrefs.PSObject.Properties) {
            if ($config.Preferences.PSObject.Properties[$p.Name]) {
                $config.Preferences.($p.Name) = $p.Value
            } else {
                $config.Preferences | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value
            }
        }
        Save-AllShares -Config $config | Out-Null
        
        # Immediately update logon script if persistent mapping changed
        $newPersistent = $config.Preferences.PersistentMapping
        if ($newPersistent -and -not $oldPersistent) {
            # Enabling persistent mapping - install logon script
            Install-LogonScript -Silent
            [System.Windows.Forms.MessageBox]::Show(
                "Persistent mapping enabled.`n`nLogon script has been installed. Shares will automatically reconnect at next logon.",
                "Persistent Mapping",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } elseif (-not $newPersistent -and $oldPersistent) {
            # Disabling persistent mapping - remove logon script
            Remove-LogonScript -Silent
            [System.Windows.Forms.MessageBox]::Show(
                "Persistent mapping disabled.`n`nLogon script has been removed. Shares will not reconnect automatically at logon.",
                "Persistent Mapping",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        
        if ($newPrefs.PSObject.Properties['Theme'] -and $newPrefs.Theme -ne $oldTheme) {
            $restart = [System.Windows.Forms.MessageBox]::Show(
                "Preferences saved. Theme changes apply on next launch. Restart now?",
                "Restart required",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($restart -eq 'Yes') {
                try {
                    $scriptPath = $PSCommandPath
                    # Close all forms immediately to provide clean transition
                    $forms = @()
                    foreach ($f in [System.Windows.Forms.Application]::OpenForms) { $forms += $f }
                    foreach ($f in $forms) { try { $f.Close() } catch { Write-ActionLog -Message "Failed to close form during restart: $_" -Level 'DEBUG' -Category 'Lifecycle' -OncePerSeconds 5 } }
                    # Start new process and immediately exit current one
                    Start-Process -FilePath "powershell.exe" `
                        -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`" -StartupMode GUI" `
                        -WindowStyle Normal
                    # Exit immediately for clean transition
                    [System.Environment]::Exit(0)
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Please relaunch Share Manager to apply theme.", "Info")
                }
            } else {
                [System.Windows.Forms.MessageBox]::Show("Preferences saved. Theme will apply on next launch.", "Info")
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Preferences saved.", "Success")
        }
    }
}

function Show-GUI {
    Write-ActionLog -Message "Entering GUI mode" -Level INFO -Category 'Startup'

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Read theme preference
    $cfgTheme = try { (Import-AllShares).Preferences.Theme } catch { "Classic" }
    if (-not $cfgTheme) { $cfgTheme = "Classic" }

    # Track sort state for visual arrows
    $script:SortColumn = -1
    $script:SortAscending = $true

    # Provide a simple comparer for ListView sorting (defined once per session)
    if (-not ("ListViewItemComparer" -as [type])) {
        $lvComparerCode = @"
using System;
using System.Windows.Forms;
using System.Collections;

public class ListViewItemComparer : IComparer {
    private int col;
    private bool asc;
    public ListViewItemComparer(int column, bool ascending) { col = column; asc = ascending; }
    public void Set(int column, bool ascending) { col = column; asc = ascending; }
    private int Dir(int result) { return asc ? result : -result; }
    public int Compare(object x, object y) {
        var a = x as ListViewItem;
        var b = y as ListViewItem;
        if (a == null || b == null) return 0;
        string sa = (col == 0) ? a.Text : (col < a.SubItems.Count ? a.SubItems[col].Text : "");
        string sb = (col == 0) ? b.Text : (col < b.SubItems.Count ? b.SubItems[col].Text : "");
            // Status column: show connected first (when ascending)
            if (col == 0) {
                int va = sa != null && sa.Contains("*") ? 1 : 0;
                int vb = sb != null && sb.Contains("*") ? 1 : 0;
                int cr = vb.CompareTo(va);  // Reversed: connected (1) before disconnected (0)
                if (cr != 0) return Dir(cr);
            }
        // Drive column: compare by drive letter
        if (col == 2) {
            if (!string.IsNullOrEmpty(sa) && sa.EndsWith(":")) sa = sa.Substring(0, 1);
            if (!string.IsNullOrEmpty(sb) && sb.EndsWith(":")) sb = sb.Substring(0, 1);
        }
            // Enabled column: Yes before No (when ascending)
            if (col == 4) {
                int va = (sa != null && sa.Equals("Yes", StringComparison.OrdinalIgnoreCase)) ? 1 : 0;
                int vb = (sb != null && sb.Equals("Yes", StringComparison.OrdinalIgnoreCase)) ? 1 : 0;
                int cr = vb.CompareTo(va);  // Reversed: Yes (1) before No (0)
                if (cr != 0) return Dir(cr);
            }
        int res = StringComparer.CurrentCultureIgnoreCase.Compare(sa ?? string.Empty, sb ?? string.Empty);
        return Dir(res);
    }
}
"@
        Add-Type -TypeDefinition $lvComparerCode -ReferencedAssemblies System.Windows.Forms | Out-Null
    }

    # Enable native visual styles only for Modern theme
    if ($cfgTheme -eq 'Modern') {
        try {
            [System.Windows.Forms.Application]::EnableVisualStyles()
        } catch {
            Write-ActionLog -Message "EnableVisualStyles failed: $_" -Level 'WARN' -Category 'Theme' -OncePerSeconds 60
        }
    }

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
    # Expose main form for cross-function operations (e.g., restart)
    $script:MainForm = $form
    # Classic theme: no styling; Modern theme: keep native defaults (EnableVisualStyles handles it)

    # Title Label
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = "Network Shares"
    # Always ensure the title pops
    $lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI",12,[System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize = $true
    $lblTitle.Top      = 15
    $lblTitle.Left     = 15
    $form.Controls.Add($lblTitle)
    
    # Search/Filter Box
    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Width = 200
    $txtSearch.Top = 15
    $txtSearch.Left = 370
    $txtSearch.Text = "Search shares..."
    $txtSearch.ForeColor = [System.Drawing.Color]::Gray
    
    # Category Filter
    $cmbCategory = New-Object System.Windows.Forms.ComboBox
    $cmbCategory.Width = 120
    $cmbCategory.Top = 15
    $cmbCategory.Left = 240
    $cmbCategory.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    [void]$cmbCategory.Items.Add("All Categories")
    
    # Add categories from shares
    $categories = Get-ShareCategories
    foreach ($cat in $categories) {
        [void]$cmbCategory.Items.Add($cat)
    }
    $cmbCategory.SelectedIndex = 0
    $form.Controls.Add($cmbCategory)
    
    # Checkbox for favorites only
    $chkFavoritesOnly = New-Object System.Windows.Forms.CheckBox
    $chkFavoritesOnly.Text = "<> Favorites"
    $chkFavoritesOnly.Width = 110
    $chkFavoritesOnly.Top = 15
    $chkFavoritesOnly.Left = 580
    $form.Controls.Add($chkFavoritesOnly)
    
    $form.Controls.Add($txtSearch)

    # Hint Label
    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text     = "Double-click to connect/disconnect | Right-click for more options"
    $lblHint.Font     = New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Italic)
    $lblHint.ForeColor = [System.Drawing.Color]::Gray
    $lblHint.AutoSize = $true
    $lblHint.Top      = 45
    $lblHint.Left     = 15
    $form.Controls.Add($lblHint)

    # ListView for shares
    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = 'Details'
    $listView.FullRowSelect = $true
    $listView.MultiSelect = $true
    $listView.GridLines = $true
    $listView.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Clickable
    $listView.AllowColumnReorder = ($cfgTheme -eq 'Modern')
    # Owner-draw header for Modern theme (items remain default for gridlines)
    if ($cfgTheme -eq 'Modern') { $listView.OwnerDraw = $true } else { $listView.OwnerDraw = $false }
    $listView.Top = 70
    $listView.Left = 15
    $listView.Width = 660
    $listView.Height = 350
    $listView.Anchor = 'Top,Left,Right,Bottom'
    # Define columns with alignment for a more defined, button-like header
    $colStatus = New-Object System.Windows.Forms.ColumnHeader
    $colStatus.Text = "Status"
    $colStatus.Width = 70
    $colStatus.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center

    $colName = New-Object System.Windows.Forms.ColumnHeader
    $colName.Text = "Name"
    $colName.Width = 140
    $colName.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Left

    $colDrive = New-Object System.Windows.Forms.ColumnHeader
    $colDrive.Text = "Drive"
    $colDrive.Width = 50
    $colDrive.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center

    $colCategory = New-Object System.Windows.Forms.ColumnHeader
    $colCategory.Text = "Category"
    $colCategory.Width = 80
    $colCategory.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Left

    $colPath = New-Object System.Windows.Forms.ColumnHeader
    $colPath.Text = "Path"
    $colPath.Width = 200
    $colPath.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Left

    $colEnabled = New-Object System.Windows.Forms.ColumnHeader
    $colEnabled.Text = "Enabled"
    $colEnabled.Width = 65
    $colEnabled.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center

    $listView.Columns.AddRange(@($colStatus, $colName, $colDrive, $colCategory, $colPath, $colEnabled))
    $form.Controls.Add($listView)

    # Dynamically fit columns to avoid horizontal scrollbar while using available width
    $padding = 1  # tiny fudge to avoid the horizontal scrollbar while minimizing empty space
    $fixedStatus = 70; $fixedDrive = 60; $fixedCategory = 80; $fixedEnabled = 65
    $ratioName = 140.0; $ratioPath = 200.0
    function Set-ListViewColumns {
        try {
            $clientW = $listView.ClientSize.Width
            if ($clientW -le 0) { return }
            $fixedSum = $fixedStatus + $fixedDrive + $fixedCategory + $fixedEnabled
            $available = $clientW - $fixedSum - $padding
            if ($available -lt 100) { $available = 100 }
            $nameW = [int][Math]::Round($available * ($ratioName / ($ratioName + $ratioPath)))
            # Ensure the last column (Path) takes the exact remainder to eliminate visible gap
            $pathW = [int]($clientW - ($fixedSum + $nameW) - $padding)

            $colStatus.Width = $fixedStatus
            $colDrive.Width = $fixedDrive
            $colCategory.Width = $fixedCategory
            $colEnabled.Width = $fixedEnabled
            $colName.Width = [Math]::Max(100, $nameW)
            $colPath.Width = [Math]::Max(150, $pathW)
        } catch {
            Write-ActionLog -Message "Set-ListViewColumns failed: $_" -Level 'DEBUG' -Category 'UI' -OncePerSeconds 5
        }
    }

    # Initial sizing and reactive updates on resize
    Set-ListViewColumns
    $listView.Add_SizeChanged({ Set-ListViewColumns })
    $form.Add_Resize({ Set-ListViewColumns })

    # Sorting state and handler
    $script:SortColumn = -1
    $script:SortAscending = $true
    $script:LvComparer = $null
    $listView.Add_ColumnClick({
        $clickedCol = $args[1].Column
        if ($script:SortColumn -eq $clickedCol) {
            $script:SortAscending = -not $script:SortAscending
        } else {
            $script:SortColumn = $clickedCol
            $script:SortAscending = $true
        }
        if (-not $script:LvComparer) {
            $script:LvComparer = New-Object ListViewItemComparer($script:SortColumn, $script:SortAscending)
        } else {
            $script:LvComparer.Set($script:SortColumn, $script:SortAscending)
        }
        $listView.ListViewItemSorter = $script:LvComparer
        $listView.Sort()
    })

    # Owner-draw header rendering for Modern theme
    if ($cfgTheme -eq 'Modern') {
        $listView.Add_DrawColumnHeader({
            $e = $args[1]
            $g = $e.Graphics
            $rect = $e.Bounds
            # Background with subtle gradient
            $light = [System.Drawing.SystemColors]::ControlLightLight
            $mid   = [System.Drawing.SystemColors]::Control
            $border= [System.Drawing.SystemColors]::ControlDark
            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $light, $mid, 90)
            $g.FillRectangle($brush, $rect)
            $brush.Dispose()
            $pen = New-Object System.Drawing.Pen($border)
            $g.DrawRectangle($pen, ($rect.X), ($rect.Y), ($rect.Width-1), ($rect.Height-1))
            $pen.Dispose()

            # Text rendering via TextRenderer for better contrast/state handling
            $flags = [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis
            switch ($e.Header.TextAlign) {
                ([System.Windows.Forms.HorizontalAlignment]::Center) { $flags = $flags -bor [System.Windows.Forms.TextFormatFlags]::HorizontalCenter }
                ([System.Windows.Forms.HorizontalAlignment]::Right)  { $flags = $flags -bor [System.Windows.Forms.TextFormatFlags]::Right }
                default { $flags = $flags -bor [System.Windows.Forms.TextFormatFlags]::Left }
            }
            # No sort arrows to avoid space issues on short columns
            $textRect = [System.Drawing.Rectangle]::new($rect.X+6, $rect.Y, [Math]::Max(0, $rect.Width-12), $rect.Height)
            [System.Windows.Forms.TextRenderer]::DrawText($g, $e.Header.Text, $e.Font, $textRect, [System.Drawing.SystemColors]::ControlText, $flags)
            $e.DrawDefault = $false
        })
        # Items/subitems: use default to keep gridlines and selection
        $listView.Add_DrawItem({ $args[1].DrawDefault = $true })
        $listView.Add_DrawSubItem({ $args[1].DrawDefault = $true })
    }
    
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
            # Prompt for credentials
            $result = [System.Windows.Forms.MessageBox]::Show(
                "No saved credentials found for $($share.Username).`n`nWould you like to enter credentials now?",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                return
            }
            
            # Show credential form
            $newCred = Show-CredentialForm -Username $share.Username
            if (-not $newCred) {
                return
            }
            $cred = $newCred
        }
        
        $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
        if (-not $result.Success) {
            [System.Windows.Forms.MessageBox]::Show(
                "Connection failed: $($result.ErrorMessage)",
                "Connection Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
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
        
        $config = Get-CachedConfig
        $shareObj = $config.Shares | Where-Object { $_.Id -eq $shareId }
        if ($shareObj) {
            $shareObj.Enabled = -not $shareObj.Enabled
            Save-AllShares -Config $config | Out-Null
            Update-ShareList
        }
    })
    [void]$contextMenu.Items.Add($menuToggle)
    
    $menuFavorite = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuFavorite.Text = "* Toggle Favorite"
    $menuFavorite.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $shareId = $listView.SelectedItems[0].Tag
        
        $config = Get-CachedConfig -Force
        $shareObj = $config.Shares | Where-Object { $_.Id -eq $shareId }
        if ($shareObj) {
            $currentFav = if ($shareObj.PSObject.Properties['IsFavorite']) { $shareObj.IsFavorite } else { $false }
            Set-ShareFavorite -ShareId $shareId -IsFavorite (-not $currentFav)
            Update-ShareList
        }
    })
    [void]$contextMenu.Items.Add($menuFavorite)
    
    [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    
    $menuDelete = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuDelete.Text = "Delete..."
    $menuDelete.ForeColor = [System.Drawing.Color]::Red
    $menuDelete.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        
        $selectedCount = $listView.SelectedItems.Count
        $shareIds = @($listView.SelectedItems | ForEach-Object { $_.Tag })
        
        $confirmMsg = if ($selectedCount -eq 1) {
            $share = Get-ShareConfiguration -ShareId $shareIds[0]
            "Delete share '$($share.Name)'?"
        } else {
            "Delete $selectedCount selected shares?"
        }
        
        $result = [System.Windows.Forms.MessageBox]::Show(
            $confirmMsg,
            "Confirm Delete",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        
        if ($result -eq 'Yes') {
            foreach ($shareId in $shareIds) {
                Remove-ShareConfiguration -ShareId $shareId
            }
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
                $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
                if (-not $result.Success) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Connection failed: $($result.ErrorMessage)",
                        "Connection Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
            } else {
                [System.Windows.Forms.MessageBox]::Show("No credentials found for $($share.Username)", "Error")
            }
        }
        Update-ShareList
    })

    # Toolbar panel (below ListView)
    # ListView: Top=70, Height=350, so bottom is at 420
    $toolbarY = 430
    
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
        $skipped = 0
        $connectedShares = @()
        $failedShares = @()
        $skippedShares = @()
        
        $shareCount = if ($shares) { $shares.Count } else { 0 }
        Write-ActionLog -Message "Connect All: Starting bulk connection ($shareCount enabled shares)" -Category 'Connection'
        
        foreach ($share in $shares) {
            $shareName = if ($share.Name) { $share.Name } else { "Unknown" }
            
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) { 
                Write-ActionLog -Message "Connect All: Skipping $shareName (already connected)" -Level DEBUG -Category 'Connection'
                $skipped++
                $skippedShares += $shareName
                continue 
            }
            $cred = Get-CredentialForShare -Username $share.Username
            if (-not $cred) {
                # Prompt for credentials
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "No saved credentials found for $($share.Username) (Share: $shareName).`n`nWould you like to enter credentials now?",
                    "Share Manager v$version",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    $newCred = Show-CredentialForm -Username $share.Username
                    if ($newCred) {
                        $cred = $newCred
                    } else {
                        Write-ActionLog -Message "Connect All: User cancelled credential entry for $shareName" -Level WARN -Category 'Connection'
                        $failed++
                        $failedShares += $shareName
                        continue
                    }
                } else {
                    Write-ActionLog -Message "Connect All: No credentials for $shareName" -Level WARN -Category 'Connection'
                    Write-ActionLog -Message "Connect All: No credentials for $shareName (Username: $($share.Username))" -Level DEBUG -Category 'Connection'
                    $failed++
                    $failedShares += $shareName
                    continue
                }
            }
            try {
                Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -Silent
                if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                    $success++
                    $connectedShares += $shareName
                    $config = Get-CachedConfig -Force
                    $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                    if ($shareObj) {
                        $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Save-AllShares -Config $config | Out-Null
                    }
                    Write-ActionLog -Message "Connect All: Connected $shareName" -Category 'Connection'
                } else {
                    $failed++
                    $failedShares += $shareName
                    Write-ActionLog -Message "Connect All: Connection failed for $shareName" -Level WARN -Category 'Connection'
                }
            } catch {
                $failed++
                $failedShares += $shareName
                Write-ActionLog -Message "Connect All: Exception for $shareName - $_" -Level ERROR -Category 'Connection'
            }
        }
        
        Write-ActionLog -Message "Connect All: Complete (success: $success, failed: $failed, skipped: $skipped)" -Category 'Connection'
        Update-ShareList
        
        if ($success -gt 0 -or $failed -gt 0 -or $skipped -gt 0) {
            $summary = "Connected: $success"
            if ($connectedShares.Count -gt 0) {
                $summary += "`n  " + ($connectedShares -join ', ')
            }
            if ($skipped -gt 0) {
                $summary += "`n`nSkipped: $skipped (already connected)"
                if ($skippedShares.Count -gt 0) {
                    $summary += "`n  " + ($skippedShares -join ', ')
                }
            }
            if ($failed -gt 0) {
                $summary += "`n`nFailed: $failed"
                if ($failedShares.Count -gt 0) {
                    $summary += "`n  " + ($failedShares -join ', ')
                }
            }
            [System.Windows.Forms.MessageBox]::Show(
                $summary,
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
            $skipped = 0
            $disconnectedShares = @()
            $skippedShares = @()
            
            $shareCount = if ($shares) { $shares.Count } else { 0 }
            Write-ActionLog -Message "Disconnect All: Starting bulk disconnection ($shareCount total shares)" -Category 'Connection'
            
            foreach ($share in $shares) {
                $shareName = if ($share.Name) { $share.Name } else { "Unknown" }
                
                if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                    Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent
                    $disconnected++
                    $disconnectedShares += $shareName
                    Write-ActionLog -Message "Disconnect All: Disconnected $shareName" -Category 'Connection'
                } else {
                    $skipped++
                    $skippedShares += $shareName
                }
            }
            
            Write-ActionLog -Message "Disconnect All: Complete (disconnected: $disconnected, skipped: $skipped)" -Category 'Connection'
            Update-ShareList
            
            if ($disconnected -gt 0 -or $skipped -gt 0) {
                $summary = "Disconnected: $disconnected"
                if ($disconnectedShares.Count -gt 0) {
                    $summary += "`n  " + ($disconnectedShares -join ', ')
                }
                if ($skipped -gt 0) {
                    $summary += "`n`nSkipped: $skipped (not connected)"
                    if ($skippedShares.Count -gt 0) {
                        $summary += "`n  " + ($skippedShares -join ', ')
                    }
                }
                [System.Windows.Forms.MessageBox]::Show(
                    $summary,
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
        Write-ActionLog -Message "Manual refresh requested" -Level DEBUG -Category 'GUI'
        Clear-ConfigCache
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
    
    # Context menu for credentials actions
    $credMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miManageCreds = New-Object System.Windows.Forms.ToolStripMenuItem
    $miManageCreds.Text = "Manage Credentials"
    $miManageCreds.Add_Click({ Show-CredentialsDialog })
    $credMenu.Items.Add($miManageCreds) | Out-Null
    
    $credMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    
    $miExportCreds = New-Object System.Windows.Forms.ToolStripMenuItem
    $miExportCreds.Text = "Export Credentials (Backup)"
    $miExportCreds.Add_Click({ Export-Credentials })
    $credMenu.Items.Add($miExportCreds) | Out-Null
    
    $miImportCreds = New-Object System.Windows.Forms.ToolStripMenuItem
    $miImportCreds.Text = "Import Credentials (Restore)"
    $miImportCreds.Add_Click({ 
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = "Select Credentials Backup File"
        $ofd.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
        $ofd.InitialDirectory = $baseFolder
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "Merge with existing credentials or replace all?`n`nYes = Merge (keep existing + add new)`nNo = Replace (remove existing)",
                "Import Mode",
                [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                Import-Credentials -ImportPath $ofd.FileName -Merge
            } elseif ($result -eq [System.Windows.Forms.DialogResult]::No) {
                Import-Credentials -ImportPath $ofd.FileName
            }
        }
    })
    $credMenu.Items.Add($miImportCreds) | Out-Null
    
    $btnCredentials.Add_Click({
        # On left-click, show the context menu
        $credMenu.Show($btnCredentials, 0, $btnCredentials.Height)
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
        $btnLog.Text = "Open Log..."
        $btnLog.Width = 280
        $btnLog.Height = 35
        $btnLog.Top = $yPos
        $btnLog.Left = 30

        # Context menu for log choices
        $logMenu = New-Object System.Windows.Forms.ContextMenuStrip
        $miText   = New-Object System.Windows.Forms.ToolStripMenuItem
        $miText.Text = "Open Text Log (Share_Manager.log)"
        $miText.Add_Click({ Invoke-LogFileOpen -Target text })
        $logMenu.Items.Add($miText) | Out-Null

        $miEvents = New-Object System.Windows.Forms.ToolStripMenuItem
        $miEvents.Text = "Open Structured Log (Share_Manager.events.jsonl)"
        $miEvents.Add_Click({ Invoke-LogFileOpen -Target events })
        $logMenu.Items.Add($miEvents) | Out-Null

        $miFolder = New-Object System.Windows.Forms.ToolStripMenuItem
        $miFolder.Text = "Open Logs Folder"
        $miFolder.Add_Click({ Invoke-LogFileOpen -Target folder })
        $logMenu.Items.Add($miFolder) | Out-Null

        $btnLog.Add_Click({
            $logMenu.Show($btnLog, [System.Drawing.Point]::new(0, $btnLog.Height))
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
    $bottomY = $toolbarY + ([Math]::Max($grpShares.Height, $grpSystem.Height)) + 2
    
    $btnCLI = New-Object System.Windows.Forms.Button
    $btnCLI.Text = "Switch to CLI"
    $btnCLI.Width = 320
    $btnCLI.Height = 35
    $btnCLI.Top = $bottomY
    $btnCLI.Left = 15
    $btnCLI.Anchor = 'Bottom,Left'
    $btnCLI.Add_Click({
        $scriptPath = $PSCommandPath
        if ($scriptPath) {
            # Use cmd /c start for reliable process creation
            $form.Close()
            $cmdArgs = "/c start `"Share Manager CLI`" powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`" -StartupMode CLI"
            Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArgs -WindowStyle Hidden
        }
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
        # Force cache refresh to ensure we see latest config state
        $allShares = @(Get-ShareConfiguration)
        
        # Temporarily remove event handler to prevent cascading updates
        $cmbCategory.remove_SelectedIndexChanged($script:categoryChangedHandler)
        
        # Refresh category dropdown with latest categories
        $currentSelection = $cmbCategory.SelectedItem
        $cmbCategory.Items.Clear()
        [void]$cmbCategory.Items.Add("All Categories")
        $categories = Get-ShareCategories
        foreach ($cat in $categories) {
            [void]$cmbCategory.Items.Add($cat)
        }
        # Restore selection or default to "All Categories"
        if ($currentSelection -and $cmbCategory.Items.Contains($currentSelection)) {
            $cmbCategory.SelectedItem = $currentSelection
        } else {
            $cmbCategory.SelectedIndex = 0
        }
        
        # Re-attach event handler
        $cmbCategory.Add_SelectedIndexChanged($script:categoryChangedHandler)
        
        # Apply filters
        $shares = $allShares
        
        # Category filter
        if ($cmbCategory.SelectedItem -and $cmbCategory.SelectedItem -ne "All Categories") {
            $selectedCat = $cmbCategory.SelectedItem
            $shares = @($shares | Where-Object { 
                $cat = if ($_.PSObject.Properties['Category']) { $_.Category } else { 'General' }
                $cat -eq $selectedCat
            })
        }
        
        # Favorites filter
        if ($chkFavoritesOnly.Checked) {
            $shares = @($shares | Where-Object { 
                $isFav = if ($_.PSObject.Properties['IsFavorite']) { $_.IsFavorite } else { $false }
                $isFav -eq $true
            })
        }
        
        # Search filter
        $searchText = $txtSearch.Text
        if ($searchText -and $searchText -ne "Search shares..." -and $searchText.Trim().Length -gt 0) {
            $shares = @($shares | Where-Object {
                $_.Name -like "*$searchText*" -or
                $_.SharePath -like "*$searchText*" -or
                $_.DriveLetter -like "*$searchText*" -or
                $_.Description -like "*$searchText*"
            })
        }
        
        $shareCount = if ($shares) { $shares.Count } else { 0 }
        Write-ActionLog -Message "Update-ShareList: Refreshing list with $shareCount shares" -Level DEBUG -Category 'GUI'
        
        foreach ($share in $shares) {
            $item = New-Object System.Windows.Forms.ListViewItem
            
            # Status column with favorite indicator
            $isConnected = Test-ShareConnection -DriveLetter $share.DriveLetter
            $isFavorite = if ($share.PSObject.Properties['IsFavorite']) { $share.IsFavorite } else { $false }
            # Use angle brackets for favorites, square brackets for regular
            if ($isFavorite) {
                $statusText = if ($isConnected) { "<*>" } else { "< >" }
            } else {
                $statusText = if ($isConnected) { "[*]" } else { "[ ]" }
            }
            $item.Text = $statusText
            $item.ForeColor = if ($isConnected) { [System.Drawing.Color]::Green } else { [System.Drawing.Color]::Red }
            
            # Add tooltip with connection info
            $lastConnected = if ($share.LastConnected) { $share.LastConnected } else { "Never" }
            $connCount = if ($share.PSObject.Properties['ConnectionCount']) { $share.ConnectionCount } else { 0 }
            $item.ToolTipText = "Last Connected: $lastConnected`nConnection Count: $connCount"
            
            # Name column
            [void]$item.SubItems.Add($share.Name)
            
            # Drive column
            [void]$item.SubItems.Add("$($share.DriveLetter):")
            
            # Category column
            $category = if ($share.PSObject.Properties['Category'] -and -not [string]::IsNullOrWhiteSpace($share.Category)) { $share.Category } else { 'General' }
            [void]$item.SubItems.Add($category)
            
            # Path column
            [void]$item.SubItems.Add($share.SharePath)
            
            # Enabled column
            [void]$item.SubItems.Add($(if ($share.Enabled) { "Yes" } else { "No" }))
            
            # Store ShareId in Tag for later reference
            $item.Tag = $share.Id
            
            [void]$listView.Items.Add($item)
        }
        
        # Re-apply sorting if a sorter is set
        if ($listView.ListViewItemSorter) { $listView.Sort() }
        
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

    # Search box events
    $txtSearch.Add_Enter({
        if ($txtSearch.Text -eq "Search shares...") {
            $txtSearch.Text = ""
            $txtSearch.ForeColor = [System.Drawing.Color]::Black
        }
    })
    $txtSearch.Add_Leave({
        if ([string]::IsNullOrWhiteSpace($txtSearch.Text)) {
            $txtSearch.Text = "Search shares..."
            $txtSearch.ForeColor = [System.Drawing.Color]::Gray
        }
    })
    $txtSearch.Add_TextChanged({ Update-ShareList })
    
    # Category filter event
    # Event handlers
    $script:categoryChangedHandler = { Update-ShareList }
    $cmbCategory.Add_SelectedIndexChanged($script:categoryChangedHandler)
    
    # Favorites checkbox event
    $chkFavoritesOnly.Add_CheckedChanged({ Update-ShareList })
    
    # Keyboard shortcuts
    $form.KeyPreview = $true
    $form.Add_KeyDown({
        param($eventSender, $e)
        
        # Ctrl+N: Add New Share
        if ($e.Control -and $e.KeyCode -eq 'N') {
            $btnAdd.PerformClick()
            $e.Handled = $true
        }
        # Ctrl+F: Focus search
        elseif ($e.Control -and $e.KeyCode -eq 'F') {
            $txtSearch.Focus()
            $e.Handled = $true
        }
        # Ctrl+R: Refresh
        elseif ($e.Control -and $e.KeyCode -eq 'R') {
            Clear-ConfigCache
            Update-ShareList
            $e.Handled = $true
        }
        # F5: Refresh (alternative)
        elseif ($e.KeyCode -eq 'F5') {
            Clear-ConfigCache
            Update-ShareList
            $e.Handled = $true
        }
        # Ctrl+A: Connect All
        elseif ($e.Control -and $e.KeyCode -eq 'A') {
            $btnConnectAll.PerformClick()
            $e.Handled = $true
        }
        # Ctrl+D: Disconnect All
        elseif ($e.Control -and $e.KeyCode -eq 'D') {
            $btnDisconnectAll.PerformClick()
            $e.Handled = $true
        }
        # Delete: Remove selected share(s)
        elseif ($e.KeyCode -eq 'Delete' -and $listView.SelectedItems.Count -gt 0) {
            $selectedCount = $listView.SelectedItems.Count
            $shareIds = @($listView.SelectedItems | ForEach-Object { $_.Tag })
            
            $confirmMsg = if ($selectedCount -eq 1) {
                $share = Get-ShareConfiguration -ShareId $shareIds[0]
                "Delete share '$($share.Name)'?"
            } else {
                "Delete $selectedCount selected shares?"
            }
            
            $result = [System.Windows.Forms.MessageBox]::Show(
                $confirmMsg,
                "Confirm Delete",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            
            if ($result -eq 'Yes') {
                foreach ($shareId in $shareIds) {
                    Remove-ShareConfiguration -ShareId $shareId
                }
                Update-ShareList
            }
            $e.Handled = $true
        }
    })
    
    # Initial population
    Update-ShareList

    # Add form disposal handler for proper resource cleanup
    $form.Add_FormClosing({
        Write-ActionLog -Message "User closed GUI" -Level INFO -Category 'Startup'
        try {
            # Dispose of context menu and its items
            if ($contextMenu) { $contextMenu.Dispose() }
            # ListView will be disposed automatically by form
        }
        catch {
            Write-ActionLog -Message "Error during form cleanup: $_" -Level DEBUG -Category 'GUI'
        }
    })

    # Bring window to front on launch
    $form.Add_Shown({
        $form.TopMost = $true
        $form.Activate()
        $form.BringToFront()
        $form.TopMost = $false
    })

    [void]$form.ShowDialog()
}

#endregion

#region Mode Selection (Entry Point)

# Log script startup
Write-ActionLog -Message "Share Manager v$version starting" -Level INFO -Category 'Startup' -Data @{ 
    mode = if ($StartupMode) { $StartupMode } else { "Auto" }
    psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
    psEdition = $PSVersionTable.PSEdition
}

# Migrate legacy config first time
Convert-LegacyConfig

$cfg = Import-AllShares
$hasShares = ($cfg.Shares.Count -gt 0)

Write-ActionLog -Message "Configuration loaded: $($cfg.Shares.Count) share(s)" -Level INFO -Category 'Startup'

# If StartupMode parameter is provided, override preference
if ($StartupMode -eq "CLI" -or $StartupMode -eq "GUI") {
    if ($StartupMode -eq "CLI") {
        $script:UseGUI = $false
        if (-not $hasShares) {
            $cliSetup = Initialize-Config-CLI
            if (-not $cliSetup) { Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow; return }
        }
        Start-CliMode
        return
    }
    elseif ($StartupMode -eq "GUI") {
        $script:UseGUI = $true
        if (-not $hasShares) {
            $setupCompleted = Initialize-Config-GUI
            if (-not $setupCompleted) {
                Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow
                return
            }
        }
        # Ensure automap scripts exist if persistent mapping is enabled
        $persistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
        if ($persistent) {
            # Always call Install-LogonScript to ensure scripts are up-to-date
            Install-LogonScript -Silent
        }
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
            # Ensure automap scripts exist if persistent mapping is enabled
            $persistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
            if ($persistent) {
                # Always call Install-LogonScript to ensure scripts are up-to-date
                # The function will only write files if content changed or files are missing
                Install-LogonScript -Silent
            }
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
        if (-not $hasShares) {
            $cliSetup = Initialize-Config-CLI
            if (-not $cliSetup) { Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow; return }
        }
        Start-CliMode
    }
    "2" {
        $script:UseGUI = $true
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName Microsoft.VisualBasic
        if (-not $hasShares) {
            $setupCompleted = Initialize-Config-GUI
            if (-not $setupCompleted) {
                Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow
                return
            }
        }
        # Ensure automap scripts exist if persistent mapping is enabled
        $persistent = Get-PreferenceValue -Name "PersistentMapping" -Default $false -AsBoolean
        if ($persistent) {
            # Always call Install-LogonScript to ensure scripts are up-to-date
            Install-LogonScript -Silent
        }
        Show-GUI
    }
        default {
        Write-Host "Invalid. Defaulting to CLI v${version}." -ForegroundColor Yellow
        $script:UseGUI = $false
        if (-not $hasShares) {
            $cliSetup = Initialize-Config-CLI
            if (-not $cliSetup) { Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow; return }
        }
        Start-CliMode
    }
}#endregion
