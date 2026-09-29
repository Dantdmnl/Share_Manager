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
    
    Reliability and usability:
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

.PARAMETER CleanupData
    Preview obsolete rotated log archives and updater backups beside this script.

.PARAMETER ApplyCleanup
    With CleanupData, delete preview-eligible archives and updater backups. Other files are preserved.

.VERSION
    2.6.0

.NOTES
    - No administrator permissions required
    - GUI mode requires '-STA' when launching PowerShell:
      powershell.exe -ExecutionPolicy Bypass -STA -File "C:\Scripts\Share_Manager.ps1"
    - Author: Dantdmnl
    - License: See LICENSE file
    - Default log level: INFO (personal data only visible at DEBUG level)
#>

param(
    [string]$StartupMode,
    [switch]$CleanupData,
    [switch]$ApplyCleanup
)

#region Global Variables (Version, Paths, Defaults)

$version        = '2.6.0'
$author         = 'Dantdmnl'
$script:ApplicationPath = $PSCommandPath

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

function New-DefaultConfigTemplate {
    return [PSCustomObject]@{
        SharePath   = $null
        DriveLetter = $null
        Username    = $null
        Preferences = [PSCustomObject]@{
            UnmapOldMapping = $true
            PreferredMode   = "Prompt"
            SyncShareNameToDriveLabel = $true
            UncProbeTimeoutSeconds = 3
            NetUseTimeoutSeconds = 15
        }
    }
}

function New-DefaultSharesConfig {
    return [PSCustomObject]@{
        Shares = @()
        SetupCompleted = $false
        Preferences = [PSCustomObject]@{
            UnmapOldMapping   = $true
            PreferredMode     = "Prompt"
            PersistentMapping = $false
            AutoReconnect     = $true
            ReconnectInterval = 300
            Theme             = "Classic"
            SyncShareNameToDriveLabel = $true
            UncProbeTimeoutSeconds = 3
            NetUseTimeoutSeconds = 15
        }
    }
}

$script:UseGUI = $false

#endregion

#region Helper Functions: InputBox, Logging, Config & Credential Key

function ConvertTo-ShareManagerReleaseInfo {
    param([Parameter(Mandatory=$true)]$Release)

    if ($Release.draft -or $Release.prerelease -or $Release.tag_name -cnotmatch '^[Vv]?\d+\.\d+\.\d+$') {
        throw 'The release is not a supported stable version.'
    }
    $releaseVersion = [version]($Release.tag_name -replace '^[Vv]', '')
    $assets = @($Release.assets | Where-Object { $_.name -ceq 'Share_Manager.ps1' -and $_.state -eq 'uploaded' })
    if ($assets.Count -ne 1) { throw 'The release must contain one Share_Manager.ps1 asset.' }
    $asset = $assets[0]
    if ($asset.digest -notmatch '^sha256:[a-fA-F0-9]{64}$') {
        throw 'The release has no SHA-256 asset digest. Use the release page to download manually.'
    }
    if ([long]$asset.size -le 0 -or [long]$asset.size -gt 5MB) { throw 'Unexpected release asset size.' }
    $downloadUrl = "https://github.com/Dantdmnl/Share_Manager/releases/download/$($Release.tag_name)/Share_Manager.ps1"
    if ($asset.browser_download_url -cne $downloadUrl) { throw 'Unexpected release download URL.' }
    return [PSCustomObject]@{
        Version = $releaseVersion.ToString()
        Tag = [string]$Release.tag_name
        DownloadUrl = $downloadUrl
        Digest = [string]$asset.digest
        Size = [long]$asset.size
        ReleaseUrl = "https://github.com/Dantdmnl/Share_Manager/releases/tag/$($Release.tag_name)"
    }
}

function Get-ShareManagerRelease {
    <# .SYNOPSIS
        Checks the public GitHub stable release without downloading or executing code.
    #>
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/Dantdmnl/Share_Manager/releases/latest' `
            -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'Share-Manager-Updater' } `
            -TimeoutSec 20 -ErrorAction Stop
        return ConvertTo-ShareManagerReleaseInfo -Release $release
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
    }
}

function Get-ShareManagerScriptVersion {
    param([Parameter(Mandatory=$true)][string]$Path)

    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw 'The script failed PowerShell parser validation.' }
    $assignments = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $_.Left.VariablePath.UserPath -eq 'version'
    })
    if ($assignments.Count -ne 1) { throw 'The script has no unique version assignment.' }
    $expression = $assignments[0].Right.Expression
    if ($expression -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        throw 'The script version must be a literal string.'
    }
    $value = $expression.Value
    if ($value -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid script version.' }
    $functions = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { $_.Name })
    foreach ($required in @('Connect-NetworkShare', 'Start-CliMode', 'Show-GUI')) {
        if ($functions -notcontains $required) { throw 'The download is not a complete Share Manager script.' }
    }
    return [version]$value
}

function Install-ShareManagerUpdate {
    <# .SYNOPSIS
        Verifies a release download and atomically replaces the script, retaining a backup.
    #>
    param(
        [Parameter(Mandatory=$true)]$Release,
        [Parameter(Mandatory=$true)][string]$CurrentScriptPath
    )

    # Revalidate the install input and construct the URL from the repository and tag.
    $checked = ConvertTo-ShareManagerReleaseInfo -Release ([PSCustomObject]@{
        tag_name = $Release.Tag; draft = $false; prerelease = $false
        assets = @([PSCustomObject]@{
            name = 'Share_Manager.ps1'; state = 'uploaded'; digest = $Release.Digest
            size = $Release.Size; browser_download_url = $Release.DownloadUrl
        })
    })
    $currentFile = Get-Item -LiteralPath $CurrentScriptPath -ErrorAction Stop
    if ($currentFile.PSIsContainer -or $currentFile.Extension -ne '.ps1') { throw 'The current script path must be a .ps1 file.' }
    $currentPath = $currentFile.FullName
    $localVersion = Get-ShareManagerScriptVersion -Path $currentPath
    if ([version]$checked.Version -le $localVersion) { throw 'This version is already installed, or the local script is newer. Restart Share Manager.' }
    $originalHash = (Get-FileHash -LiteralPath $currentPath -Algorithm SHA256 -ErrorAction Stop).Hash
    $id = [guid]::NewGuid().ToString('N')
    $stagedPath = Join-Path $currentFile.DirectoryName ('.Share_Manager.' + $id + '.update.ps1')
    $backupPath = $currentPath + '.' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.' + $id + '.bak'
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $checked.DownloadUrl -UseBasicParsing -TimeoutSec 60 -OutFile $stagedPath -ErrorAction Stop | Out-Null
        if ((Get-Item -LiteralPath $stagedPath).Length -ne $checked.Size) { throw 'The downloaded size does not match the release asset.' }
        $downloadHash = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ('sha256:' + $downloadHash -ine $checked.Digest) { throw 'The downloaded SHA-256 does not match the release asset.' }
        if ((Get-ShareManagerScriptVersion -Path $stagedPath) -ne [version]$checked.Version) { throw 'The script version does not match the release tag.' }
        if ((Get-FileHash -LiteralPath $currentPath -Algorithm SHA256 -ErrorAction Stop).Hash -ne $originalHash) {
            throw 'The local script changed during the download. Update cancelled.'
        }
        [System.IO.File]::Replace($stagedPath, $currentPath, $backupPath)
        return [PSCustomObject]@{ Version = $checked.Version; BackupPath = $backupPath }
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        if (Test-Path -LiteralPath $stagedPath) { Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-ShareManagerUpdateTask {
    param([ValidateSet('Check', 'Install')][string]$Operation, $Release, [switch]$UseGUI)

    if (-not $UseGUI) {
        if ($Operation -eq 'Check') { return Get-ShareManagerRelease }
        return Install-ShareManagerUpdate -Release $Release -CurrentScriptPath $script:ApplicationPath
    }

    # Only updater functions enter the worker; application startup and credentials stay out.
    $definitions = foreach ($name in @('ConvertTo-ShareManagerReleaseInfo', 'Get-ShareManagerRelease', 'Get-ShareManagerScriptVersion', 'Install-ShareManagerUpdate')) {
        "function $name {`n$((Get-Command $name -CommandType Function).Definition)`n}"
    }
    $worker = [PowerShell]::Create()
    $dialog = New-Object System.Windows.Forms.Form
    $timer = New-Object System.Windows.Forms.Timer
    try {
        $dialog.Text = 'Share Manager Update'
        $dialog.ClientSize = New-Object System.Drawing.Size(460, 95)
        $dialog.FormBorderStyle = 'FixedDialog'
        $dialog.StartPosition = 'CenterScreen'
        $dialog.ControlBox = $false
        $label = New-Object System.Windows.Forms.Label
        $label.Dock = 'Top'
        $label.Height = 50
        $label.TextAlign = 'MiddleCenter'
        $label.Text = if ($Operation -eq 'Check') { 'Checking GitHub for updates...' } else { 'Downloading and verifying the update...' }
        $progress = New-Object System.Windows.Forms.ProgressBar
        $progress.Dock = 'Bottom'
        $progress.Style = 'Marquee'
        $dialog.Controls.AddRange(@($label, $progress))
        $null = $worker.AddScript($definitions -join "`n")
        $null = $worker.AddScript({
            param($operation, $release, $path)
            $ErrorActionPreference = 'Stop'
            if ($operation -eq 'Check') { Get-ShareManagerRelease }
            else { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $path }
        }).AddArgument($Operation).AddArgument($Release).AddArgument($script:ApplicationPath)
        $pending = $worker.BeginInvoke()
        $timer.Interval = 100
        $timer.Add_Tick({ if ($pending.IsCompleted) { $timer.Stop(); $dialog.Close() } })
        $timer.Start()
        $null = $dialog.ShowDialog()
        $result = $worker.EndInvoke($pending)
        if ($worker.HadErrors) { throw $worker.Streams.Error[0] }
        return $result
    }
    finally {
        $timer.Stop()
        $timer.Dispose()
        $dialog.Dispose()
        $worker.Dispose()
    }
}

function Update-ShareManager {
    <# .SYNOPSIS
        Offers a user-initiated stable update in the CLI or GUI, with an install confirmation.
    #>
    param([switch]$UseGUI)

    try {
        if (-not $UseGUI) { Write-Host 'Checking GitHub for updates...' -ForegroundColor Cyan }
        $release = Invoke-ShareManagerUpdateTask -Operation Check -UseGUI:$UseGUI
        if ([version]$release.Version -le [version]$version) {
            $message = "No newer stable release. Running: $version; latest release: $($release.Version)."
        } else {
            $question = "Install Share Manager $($release.Version)?`n`nCurrent version: $version`nRelease notes: $($release.ReleaseUrl)`n`nThis replaces the script file and keeps a backup beside it. Local script edits will be replaced. Restart afterward to use the update."
            if ($UseGUI) {
                $approved = [System.Windows.Forms.MessageBox]::Show($question, 'Share Manager Update', 'YesNo', 'Question', 'Button2') -eq 'Yes'
            } else {
                Write-Host $question
                $approved = (Read-CliPrompt 'Install update? [y/N]').Trim() -ieq 'y'
            }
            if (-not $approved) { return }
            if (-not $UseGUI) { Write-Host 'Downloading and verifying the update...' -ForegroundColor Cyan }
            $installed = Invoke-ShareManagerUpdateTask -Operation Install -Release $release -UseGUI:$UseGUI
            $message = "Installed $($installed.Version). Close and reopen Share Manager to use it.`nBackup: $($installed.BackupPath)"
        }
        if ($UseGUI) { [System.Windows.Forms.MessageBox]::Show($message, 'Share Manager Update', 'OK', 'Information') | Out-Null }
        else { Write-Host $message -ForegroundColor Green }
    }
    catch {
        $message = "Update failed: $($_.Exception.Message)`nYou can retry or download manually: https://github.com/Dantdmnl/Share_Manager/releases"
        if ($UseGUI) { [System.Windows.Forms.MessageBox]::Show($message, 'Share Manager Update', 'OK', 'Error') | Out-Null }
        else { Write-Host $message -ForegroundColor Yellow }
    }
}

function Show-InputBox {
    param (
        [string]$Prompt,
        [string]$Title,
        [string]$DefaultValue = ""
    )
    Add-Type -AssemblyName Microsoft.VisualBasic
    return [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, $Title, $DefaultValue)
}

function Set-TerminalBlackBackground {
    param([switch]$Refresh)

    try {
        $rawUI = $Host.UI.RawUI
        if (-not $rawUI) { return }

        $needsRefresh = $false
        if ($rawUI.BackgroundColor -ne [System.ConsoleColor]::Black) {
            $rawUI.BackgroundColor = [System.ConsoleColor]::Black
            $needsRefresh = $true
        }

        # Keep text readable if a host starts with black-on-black defaults.
        if ($rawUI.ForegroundColor -eq [System.ConsoleColor]::Black) {
            $rawUI.ForegroundColor = [System.ConsoleColor]::Gray
            $needsRefresh = $true
        }

        if ($Refresh -or $needsRefresh) {
            Clear-Host
        }
    }
    catch {
        # Non-console hosts may not support RawUI color manipulation.
        Write-ActionLog -Message "Terminal background update skipped: $_" -Level DEBUG -Category 'Theme' -OncePerSeconds 60
    }
}

function Get-DataCleanupCandidates {
    param([string]$Folder = $baseFolder, [datetime]$Now = (Get-Date))
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { return }
    $root = Get-Item -LiteralPath $Folder -Force -ErrorAction Stop
    if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Cleanup refuses a linked application data folder.' }
    $archives = @(Get-ChildItem -LiteralPath $root.FullName -File -Force | Where-Object {
        -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        $_.Name -match '^(Share_Manager|LogonScript)(\.events)?_\d{4}-\d{2}-\d{2}_\d{6}\.(log|jsonl)$'
    })
    foreach ($stream in @('Share_Manager', 'Share_Manager.events', 'LogonScript', 'LogonScript.events')) {
        $extension = if ($stream.EndsWith('.events')) { 'jsonl' } else { 'log' }
        $pattern = '^' + [regex]::Escape($stream) + '_(\d{4}-\d{2}-\d{2}_\d{6})\.' + $extension + '$'
        $ordered = @($archives | Where-Object { $_.Name -match $pattern } | Sort-Object Name -Descending)
        foreach ($file in @($ordered | Select-Object -Skip 2)) {
            $null = $file.Name -match $pattern
            $archivedAt = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($Matches[1], 'yyyy-MM-dd_HHmmss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$archivedAt)) { continue }
            if ($archivedAt -lt $Now.AddDays(-90) -and $file.LastWriteTime -lt $Now.AddDays(-90)) { $file }
        }
    }
}

function Get-UpdateBackupCleanupCandidates {
    param([string]$CurrentScriptPath, [datetime]$Now = (Get-Date))
    if (-not $CurrentScriptPath -or -not (Test-Path -LiteralPath $CurrentScriptPath -PathType Leaf)) { return }
    $scriptFile = Get-Item -LiteralPath $CurrentScriptPath -Force -ErrorAction Stop
    $root = Get-Item -LiteralPath $scriptFile.DirectoryName -Force -ErrorAction Stop
    if ($scriptFile.Extension -ne '.ps1' -or
        ($scriptFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return }
    $pattern = '^' + [regex]::Escape($scriptFile.Name) + '\.(\d{8}-\d{6})\.[0-9a-f]{32}\.bak$'
    $backups = @(Get-ChildItem -LiteralPath $root.FullName -File -Force -ErrorAction Stop | Where-Object {
        $_.Name -match $pattern -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
    } | Sort-Object Name -Descending)
    foreach ($file in @($backups | Select-Object -Skip 2)) {
        $null = $file.Name -match $pattern
        $createdAt = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($Matches[1], 'yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$createdAt)) { continue }
        if ($createdAt -lt $Now.AddDays(-90) -and $file.LastWriteTime -lt $Now.AddDays(-90)) { $file }
    }
}

function Invoke-DataCleanup {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Folder = $baseFolder, [switch]$Apply, [string]$CurrentScriptPath)
    $rootPath = [IO.Path]::GetFullPath($Folder).TrimEnd('\')
    $allowedRoots = @($rootPath)
    if ($CurrentScriptPath) { $allowedRoots += [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($CurrentScriptPath)).TrimEnd('\') }
    $candidates = @(Get-DataCleanupCandidates -Folder $Folder)
    $candidates += @(Get-UpdateBackupCleanupCandidates -CurrentScriptPath $CurrentScriptPath)
    foreach ($candidate in $candidates) {
        $status = 'Preview'
        if ($Apply -and $PSCmdlet.ShouldProcess($candidate.FullName, 'Delete expired log archive or updater backup')) {
            try {
                $candidateRoot = $candidate.DirectoryName.TrimEnd('\')
                if ($candidateRoot -notin $allowedRoots) { throw 'File is outside the cleanup folders.' }
                $root = Get-Item -LiteralPath $candidateRoot -Force -ErrorAction Stop
                $current = Get-Item -LiteralPath $candidate.FullName -Force -ErrorAction Stop
                if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    $current.PSIsContainer -or $current.DirectoryName.TrimEnd('\') -ne $candidateRoot -or
                    $current.Length -ne $candidate.Length -or $current.LastWriteTimeUtc -ne $candidate.LastWriteTimeUtc) {
                    throw 'File changed or no longer resides directly in the application folder.'
                }
                Remove-Item -LiteralPath $current.FullName -ErrorAction Stop
                $status = 'Removed'
            } catch { $status = 'Failed'; Write-Warning "Could not clean $($candidate.Name): $($_.Exception.Message)" }
        }
        [PSCustomObject]@{ Name = $candidate.Name; Bytes = $candidate.Length; Status = $status; Folder = $candidate.DirectoryName }
    }
}

function Invoke-StartupDataCleanup {
    try {
        $results = @(Invoke-DataCleanup -CurrentScriptPath $script:ApplicationPath -Apply -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop)
        $removed = @($results | Where-Object { $_.Status -eq 'Removed' }).Count
        $failed = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
        if ($removed -gt 0 -or $failed -gt 0) {
            $level = if ($failed -gt 0) { 'WARN' } else { 'INFO' }
            Write-ActionLog -Message "Archive cleanup: $removed removed, $failed failed." -Level $level -Category 'Maintenance'
        }
    } catch {
        # Maintenance must not prevent the application from opening.
        try { Write-ActionLog -Message "Archive cleanup skipped: $($_.Exception.Message)" -Level WARN -Category 'Maintenance' } catch { }
    }
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

if (-not $CleanupData -and -not $ApplyCleanup) { Invoke-LogRotation }

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
                $config | Add-Member -MemberType NoteProperty -Name Preferences -Value (New-DefaultSharesConfig).Preferences
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
                if (-not $config.Preferences.PSObject.Properties['UncProbeTimeoutSeconds']) {
                    $config.Preferences | Add-Member -MemberType NoteProperty -Name UncProbeTimeoutSeconds -Value 3
                }
                if (-not $config.Preferences.PSObject.Properties['NetUseTimeoutSeconds']) {
                    $config.Preferences | Add-Member -MemberType NoteProperty -Name NetUseTimeoutSeconds -Value 15
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
            return (New-DefaultSharesConfig)
        }
    }
    
    return (New-DefaultSharesConfig)
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

function ConvertTo-SafeBoolean {
    <#
    .SYNOPSIS
        Converts common boolean representations to true/false with fallback
    #>
    param(
        [AllowNull()]
        [object]$Value,
        [bool]$Default = $false
    )

    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $Default }

    if ($Value -is [byte] -or
        $Value -is [sbyte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64] -or
        $Value -is [uint64] -or
        $Value -is [decimal] -or
        $Value -is [double] -or
        $Value -is [single]) {
        return ([double]$Value -ne 0)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $Default }

    switch ($text.Trim().ToLowerInvariant()) {
        'true'  { return $true }
        'false' { return $false }
        'yes'   { return $true }
        'no'    { return $false }
        '1'     { return $true }
        '0'     { return $false }
        default { return $Default }
    }
}

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
        $defaultBool = ConvertTo-SafeBoolean -Value $Default -Default $false
        return (ConvertTo-SafeBoolean -Value $value -Default $defaultBool)
    } elseif ($AsInteger) {
        $intValue = 0
        if ([int]::TryParse([string]$value, [ref]$intValue)) {
            return $intValue
        }
        $defaultInt = 0
        if ([int]::TryParse([string]$Default, [ref]$defaultInt)) {
            return $defaultInt
        }
        return 0
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
            $newJson | Set-Content -LiteralPath $tempPath -Encoding UTF8 -Force -ErrorAction Stop
            
            # Create backup of existing config if it exists
            if (Test-Path $sharesPath) {
                Copy-Item -LiteralPath $sharesPath -Destination $backupPath -Force -ErrorAction Stop
            }
            
            # Atomic rename (overwrites destination)
            Move-Item -LiteralPath $tempPath -Destination $sharesPath -Force -ErrorAction Stop
            
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
                Copy-Item -LiteralPath $backupPath -Destination $sharesPath -Force -ErrorAction Stop
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
    param([switch]$IncludeSuggestions)
    $defaults = @('General', 'Home', 'Work', 'Backups', 'Media', 'Projects')
    $config = Get-CachedConfig
    if ($config -and $config.Shares) {
        $categories = @($config.Shares | Where-Object { $_.PSObject.Properties['Category'] -and -not [string]::IsNullOrWhiteSpace($_.Category) } | Select-Object -ExpandProperty Category -Unique | Sort-Object)
        if ($IncludeSuggestions) { return @($defaults) + @($categories | Where-Object { $_ -notin $defaults }) }
        if ($categories.Count -eq 0) { return @('General') }
        return $categories
    }
    if ($IncludeSuggestions) { return $defaults }
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
    
    if (Test-DrivePath -DriveLetter $DriveLetter) {
        try {
            # Verify it's actually our network share
            $drive = Get-PSDrive -Name $DriveLetter -PSProvider FileSystem -ErrorAction Stop
            return ($drive.DisplayRoot -match '^\\\\')
        }
        catch {
            # Fall through to net use below; mapped drives can be invisible to
            # the current PowerShell provider context in some sessions.
        }
    }

    try {
        $netUseOutput = Invoke-NetUseQuery -DriveLetter $DriveLetter
        if ($netUseOutput -match '(?im)^\s*Unavailable\s+') {
            return $false
        }
        if ($netUseOutput -match '(?im)^\s*Remote name\s+\\\\') {
            return $true
        }
    }
    catch {
        Write-ActionLog -Message "Failed to query mapping state for $DriveLetter - $_" -Level DEBUG -Category 'Mapping' -OncePerSeconds 30
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
        Returns hashtable with Success, Added, Skipped, Updated properties for merge operations
    #>
    param (
        [string]$ImportPath,
        [bool]$Merge = $false
    )
    
    if (-not (Test-Path $ImportPath)) {
        Write-Host "Import file not found: $ImportPath" -ForegroundColor Red
        return @{ Success = $false; Added = 0; Skipped = 0; Updated = 0 }
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
                $existingMatches = @($config.Shares | Where-Object {
                    $_.SharePath -eq $share.SharePath -or $_.DriveLetter -eq $share.DriveLetter
                })
                
                if ($existingMatches.Count -eq 0) {
                    # Generate new ID to avoid conflicts
                    $share.Id = [guid]::NewGuid().ToString()
                    $config.Shares += $share
                    $added++
                } else {
                    $existing = $existingMatches | Select-Object -First 1
                    if ($existingMatches.Count -gt 1) {
                        Write-ActionLog -Message "Multiple merge targets found for import share '$($share.Name)'; updating first match only" -Level WARN -Category 'BackupRestore' -Data @{ shareName = $share.Name; matchCount = $existingMatches.Count }
                    }

                    # Update existing share with imported properties (IsFavorite, Category, Description, etc.)
                    if ($share.PSObject.Properties['IsFavorite']) {
                        if (-not $existing.PSObject.Properties['IsFavorite']) {
                            $existing | Add-Member -MemberType NoteProperty -Name IsFavorite -Value $share.IsFavorite
                        } else {
                            $existing.IsFavorite = $share.IsFavorite
                        }
                    }
                    if ($share.PSObject.Properties['Category']) {
                        if (-not $existing.PSObject.Properties['Category']) {
                            $existing | Add-Member -MemberType NoteProperty -Name Category -Value $share.Category
                        } else {
                            $existing.Category = $share.Category
                        }
                    }
                    if ($share.PSObject.Properties['Description']) {
                        if (-not $existing.PSObject.Properties['Description']) {
                            $existing | Add-Member -MemberType NoteProperty -Name Description -Value $share.Description
                        } else {
                            $existing.Description = $share.Description
                        }
                    }
                    if ($share.PSObject.Properties['Enabled']) {
                        if (-not $existing.PSObject.Properties['Enabled']) {
                            $existing | Add-Member -MemberType NoteProperty -Name Enabled -Value ([bool]$share.Enabled)
                        } else {
                            $existing.Enabled = [bool]$share.Enabled
                        }
                    }
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
            return @{ Success = $true; Added = $added; Skipped = $skipped; Updated = $skipped }
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
        return @{ Success = $false; Added = 0; Skipped = 0; Updated = 0 }
    }
    
    return @{ Success = $false; Added = 0; Skipped = 0; Updated = 0 }
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

function Get-ShareCredentialDiagnostics {
    <#
    .SYNOPSIS
        Finds likely Windows SMB credential conflict risks in configured shares.
    #>
    $config = Get-CachedConfig -Force
    $shares = @()
    if ($config -and $config.Shares) {
        $shares = @($config.Shares | Where-Object { $_.Enabled })
    }

    $serverMap = @{}
    foreach ($share in @($shares | Where-Object { $_.Enabled })) {
        if (-not $share.SharePath -or $share.SharePath -notmatch '^\\\\([^\\]+)') { continue }
        $server = "\\$($Matches[1])"
        $key = $server.ToLowerInvariant()
        if (-not $serverMap.ContainsKey($key)) {
            $serverMap[$key] = @{
                Server = $server
                Usernames = @{}
                Shares = @()
            }
        }
        $username = if ($share.Username) { [string]$share.Username } else { "" }
        if (-not $serverMap[$key].Usernames.ContainsKey($username)) {
            $serverMap[$key].Usernames[$username] = 0
        }
        $serverMap[$key].Usernames[$username]++
        $serverMap[$key].Shares += $share.Name
    }

    $diagnostics = @()
    foreach ($entry in $serverMap.Values) {
        $usernames = @($entry.Usernames.Keys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($usernames.Count -gt 1) {
            $diagnostics += [PSCustomObject]@{
                Server = $entry.Server
                Issue = "MultipleConfiguredUsernames"
                Detail = "Windows may reject multiple credentials for the same SMB server."
                Usernames = ($usernames -join ', ')
                Shares = ($entry.Shares -join ', ')
            }
        }
    }

    return @($diagnostics)
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
                $cfg | Add-Member -MemberType NoteProperty -Name Preferences -Value (New-DefaultConfigTemplate).Preferences
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
    param ([System.Management.Automation.PSCredential]$Credential, [switch]$PassThru)

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
        $store | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $credentialsStorePath -Encoding UTF8 -Force -ErrorAction Stop

        # Silent in GUI (caller handles messaging), verbose in CLI
        if (-not $UseGUI) {
            Write-Host "  [OK] Credentials saved for $user" -ForegroundColor Green
        }
        Write-ActionLog -Message "Saved credential for $user" -Level DEBUG -Category 'Credentials'
        if ($PassThru) { return $true }
    }
    catch {
        if ($UseGUI) {
            [void][System.Windows.Forms.MessageBox]::Show(
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
        if ($PassThru) { return $false }
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
        [System.Windows.Forms.Control]$TextBox,
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
                            $sel = Read-CliPrompt "Remove which username (number), or 'ALL'"
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
        $key = Read-CliKey
        if ($key.VirtualKeyCode -eq 13) {
            break
        }
        elseif ($key.VirtualKeyCode -eq 27) {
            Write-Host ''
            $secureString.Dispose()
            throw [System.OperationCanceledException]::new('Password entry cancelled with Escape')
        }
        elseif ($key.VirtualKeyCode -eq 8) {
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
        elseif (-not [char]::IsControl($key.Character)) {
            $secureString.AppendChar($key.Character)
            Write-Host -NoNewline '*'
        }
    }
    Write-Host ""
    $secureString.MakeReadOnly()
    return $secureString
}

#endregion

#region Network Check & Mapping Functions

function ConvertTo-UncPathInput {
    param([string]$Path)
    $value = $Path.Trim()
    if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[$value.Length - 1] -eq '"') -or
        ($value[0] -eq "'" -and $value[$value.Length - 1] -eq "'"))) {
        $value = $value.Substring(1, $value.Length - 2).Trim()
    }
    $suggestion = $null
    # Only repair the accidental backtick/separator before the server, never path components.
    if ($value.StartsWith('\\`\')) { $suggestion = '\\' + $value.Substring(4) }
    if ($value -and -not $value.StartsWith('\')) { $value = '\\' + $value }
    [PSCustomObject]@{ Path = $value; Suggestion = $suggestion }
}

function Resolve-GuiUncPathInput {
    param([string]$Path)
    $inputPath = ConvertTo-UncPathInput -Path $Path
    if ($inputPath.Suggestion) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "There is a stray backtick and separator before the server name. Use this path instead?`n`n$($inputPath.Suggestion)",
            'Confirm Network Path', [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return $null }
        $inputPath.Path = $inputPath.Suggestion
    }
    $validation = Get-UncPathValidation -Path $inputPath.Path
    if (-not $validation.Valid -and $validation.Suggestion) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "$($validation.Message) Use this path instead?`n`n$($validation.Suggestion)",
            'Confirm Network Path', [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -eq [System.Windows.Forms.DialogResult]::Yes) { return $validation.Suggestion }
        return $null
    }
    if (-not $validation.Valid) {
        [void][System.Windows.Forms.MessageBox]::Show($validation.Message,
            'Invalid Network Path', [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $null
    }
    return $inputPath.Path
}

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
    
    # Valid UNC: \\servername\sharename with optional subfolders
    # Server: 2+ chars, Share: 1+ chars
    if ($Path -notmatch '^\\\\([^\\]{2,})\\[^\\]+(\\[^\\]+)*\\?$') { return $false }
    $server = $Matches[1]
    if ($server -match '[\s/:*?"<>|]') { return $false }
    if ($server.Contains('..')) { return $false }
    if ($server -match '^[0-9.]+$' -and $server.Contains('.')) {
        if ($server -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
        foreach ($octet in $server.Split('.')) {
            if ([int]$octet -gt 255) { return $false }
        }
    }
    return $true
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
        $reachable = Test-Connection -ComputerName $shareHost -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($reachable) { return $true }
    }
    catch {
        $reachable = $false
    }

    # Fallback for environments where ICMP is blocked: quick UNC probe with timeout.
    $uncTimeout = Get-PreferenceValue -Name "UncProbeTimeoutSeconds" -Default 3 -AsInteger
    if ($uncTimeout -lt 1) { $uncTimeout = 1 }
    if ($uncTimeout -gt 30) { $uncTimeout = 30 }

    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($path)
            Test-Path $path
        } -ArgumentList $SharePath

        $completed = Wait-Job -Job $job -Timeout $uncTimeout
        if ($completed) {
            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            return [bool]$result
        }
    }
    catch {
        return $false
    }
    finally {
        if ($job) {
            try { Stop-Job -Job $job -ErrorAction Stop | Out-Null } catch { }
            try { Remove-Job -Job $job -Force | Out-Null } catch { }
        }
    }

    return $false
}

function Test-DrivePath {
    param([string]$DriveLetter)

    return (Test-Path "$DriveLetter`:")
}

function Invoke-NetUseDelete {
    param([string]$DriveLetter)

    $output = cmd /c "net use `"${DriveLetter}:`" /delete /y" 2>&1
    return [PSCustomObject]@{
        Output = ($output | Out-String)
        ExitCode = $LASTEXITCODE
    }
}

function Invoke-NetUseQuery {
    param([string]$DriveLetter)

    return (net use "$DriveLetter`:" 2>&1 | Out-String)
}

function Invoke-NetUseWithCredential {
    param(
        [string]$DriveLetter,
        [string]$SharePath,
        [string]$Username,
        [string]$Password,
        [string]$PersistentFlag,
        [int]$TimeoutSeconds
    )

    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($drive, $share, $username, $password, $flag)
            $output = net use "$drive`:" $share /USER:$username $password $flag 2>&1
            $exitCode = $LASTEXITCODE
            [PSCustomObject]@{
                Output = ($output | Out-String)
                ExitCode = $exitCode
            }
        } -ArgumentList $DriveLetter, $SharePath, $Username, $Password, $PersistentFlag

        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if ($completed) {
            $jobResult = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if ($jobResult) {
                return [PSCustomObject]@{
                    Output = $jobResult.Output
                    ExitCode = [int]$jobResult.ExitCode
                }
            }
        }

        return [PSCustomObject]@{
            Output = "net use timed out after ${TimeoutSeconds}s"
            ExitCode = 1460
        }
    }
    catch {
        return [PSCustomObject]@{
            Output = "net use failed: $_"
            ExitCode = 1
        }
    }
    finally {
        if ($job) {
            try { Stop-Job -Job $job -ErrorAction Stop | Out-Null } catch { }
            try { Remove-Job -Job $job -Force | Out-Null } catch { }
        }
    }
}

function Invoke-CmdKeyList {
    param([string]$Target)

    return (cmdkey /list:$Target 2>&1 | Out-String)
}

function Invoke-CmdKeyDelete {
    param([string]$Target)

    cmdkey /delete:$Target 2>&1 | Out-Null
    return $LASTEXITCODE
}

function Invoke-CmdKeyAdd {
    param(
        [string]$Target,
        [string]$Username,
        [string]$Password
    )

    $cmdkeyArgs = @(('/add:' + $Target), ('/user:' + $Username), ('/pass:' + $Password))
    $output = & cmdkey $cmdkeyArgs 2>&1
    return [PSCustomObject]@{
        Output = ($output | Out-String)
        ExitCode = $LASTEXITCODE
    }
}

function Get-CredentialTargetsForSharePath {
    param([string]$SharePath)

    if ($SharePath -match '^\\\\([^\\]+)') {
        $server = $Matches[1]
        return @($server, "\\$server") | Sort-Object -Unique
    }
    return @($SharePath)
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

    if (Test-DrivePath -DriveLetter $DriveLetter) {
        # Auto-unmap if preference is set
        if ($autoUnmap) {
            try {
                Invoke-NetUseDelete -DriveLetter $DriveLetter | Out-Null
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
        Write-ActionLog -Message "Skipped mapping $DriveLetter -> $SharePath (offline)" -Level DEBUG
        if ($ReturnStatus) {
            return @{ Success = $false; ErrorType = "Offline"; ErrorMessage = "Share host not reachable" }
        }
        return
    }

    $target = $null
    $plainPassword = $null
    try {
        $user = $Credential.UserName
        $bstrPtr = [IntPtr]::Zero

        try {
            # Securely extract password for mapping command.
            $bstrPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
        }
        finally {
            # CRITICAL: Always zero and free the BSTR to prevent password leaks.
            if ($bstrPtr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
            }
        }

        if ($persistent) {
            $credentialTargets = @(Get-CredentialTargetsForSharePath -SharePath $SharePath)

            foreach ($target in $credentialTargets) {
                # Matching usernames do not establish that the stored password is current.
                $cmdkeyResult = Invoke-CmdKeyAdd -Target $target -Username $user -Password $plainPassword
                if ($cmdkeyResult.ExitCode -ne 0) {
                    Write-ActionLog -Message "Credential Manager update failed (exit code: $($cmdkeyResult.ExitCode)); continuing with supplied mapping credentials" -Level WARN -Category 'Credentials'
                }
            }
        }
        
        $netUseTimeout = Get-PreferenceValue -Name "NetUseTimeoutSeconds" -Default 15 -AsInteger
        if ($netUseTimeout -lt 5) { $netUseTimeout = 5 }
        if ($netUseTimeout -gt 120) { $netUseTimeout = 120 }

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
            
            $netResult = $null
            $netExitCode = 1

            $netUseResult = Invoke-NetUseWithCredential `
                -DriveLetter $DriveLetter `
                -SharePath $SharePath `
                -Username $user `
                -Password $plainPassword `
                -PersistentFlag $persistentFlag `
                -TimeoutSeconds $netUseTimeout
            $netResult = $netUseResult.Output
            $netExitCode = [int]$netUseResult.ExitCode

            if ($netExitCode -eq 0) {
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
                    exitCode = $netExitCode
                }
            }
        }

        if ($mapped) {
            # Verify connection by checking net use output matches expected share path
            $verified = $false
            try {
                $netUseOutput = Invoke-NetUseQuery -DriveLetter $DriveLetter
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
                netUseOutput = $lastError
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
    finally {
        $plainPassword = $null
    }
}

function Disconnect-NetworkShare {
    param (
        [string]$DriveLetter,
        [switch]$Silent,
        [switch]$ReturnStatus
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
        $netUseResult = Invoke-NetUseDelete -DriveLetter $DriveLetter
        $netUseExitCode = if ($netUseResult.PSObject.Properties['ExitCode']) { [int]$netUseResult.ExitCode } else { [int]$netUseResult }
        $netUseOutput = if ($netUseResult.PSObject.Properties['Output']) { [string]$netUseResult.Output } else { "" }

        if ($netUseExitCode -eq 0) {
            # If persistent, remove credentials from Credential Manager
                if ($persistent -and $sharePath) {
                foreach ($target in @(Get-CredentialTargetsForSharePath -SharePath $sharePath)) {
                    Invoke-CmdKeyDelete -Target $target | Out-Null
                }
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
            if ($ReturnStatus) {
                return @{ Success = $true; ErrorType = $null; ErrorMessage = $null }
            }
        }
        elseif (-not (Test-ShareConnection -DriveLetter $DriveLetter)) {
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
            if ($ReturnStatus) {
                return @{ Success = $false; ErrorType = "NotMapped"; ErrorMessage = "Drive not mapped" }
            }
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
            Write-ActionLog -Message "Failed unmapping $DriveLetter" -Level ERROR -Category 'Mapping' -Data @{ exitCode = $netUseExitCode; output = $netUseOutput }
            if ($ReturnStatus) {
                return @{ Success = $false; ErrorType = "NetUseFailed"; ErrorMessage = "net use delete failed with exit code $netUseExitCode"; Output = $netUseOutput }
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
        if ($ReturnStatus) {
            return @{ Success = $false; ErrorType = "Exception"; ErrorMessage = "$_" }
        }
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
        $sel = Read-CliPrompt "Choose (1-3) [1]"
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

function Test-FirstRunNeeded {
    param($Config)
    if (-not $Config) { return $true }
    if ($Config.PSObject.Properties['SetupCompleted']) {
        return -not (ConvertTo-SafeBoolean -Value $Config.SetupCompleted -Default $false)
    }
    if ($null -eq $Config.Shares) { return $true }
    return @($Config.Shares).Count -eq 0
}

function Start-FirstRunSetup {
    $config = Get-CachedConfig -Force
    if (-not $config.PSObject.Properties['SetupCompleted']) {
        $config | Add-Member -MemberType NoteProperty -Name SetupCompleted -Value $false
    } else {
        $config.SetupCompleted = $false
    }
    return (Save-AllShares -Config $config)
}

function Complete-FirstRunSetup {
    param([PSCustomObject]$Preferences)
    $config = Get-CachedConfig -Force
    foreach ($property in $Preferences.PSObject.Properties) {
        if ($config.Preferences.PSObject.Properties[$property.Name]) {
            $config.Preferences.($property.Name) = $property.Value
        } else {
            $config.Preferences | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
        }
    }
    if (-not $config.PSObject.Properties['SetupCompleted']) {
        $config | Add-Member -MemberType NoteProperty -Name SetupCompleted -Value $true
    } else {
        $config.SetupCompleted = $true
    }
    return (Save-AllShares -Config $config)
}

function Initialize-Config-CLI {
    try {
        Set-TerminalBlackBackground -Refresh
        Write-Host ''
        Write-Host "  SHARE MANAGER v$version - FIRST SETUP" -ForegroundColor Cyan
        Write-Host '  Add a share, restore a backup, or start with an empty list.' -ForegroundColor Gray
        Write-Host ''
        if (-not (Start-FirstRunSetup)) {
            Clear-ConfigCache
            Write-Host '  Setup could not be started. Check folder permissions and disk space.' -ForegroundColor Red
            return $false
        }

        $preferences = (New-DefaultSharesConfig).Preferences
        $preferences.PreferredMode = 'CLI'
        do {
            $advanced = Read-CliPrompt '  Customize preferences now? (Y/N) [N]'
            if ($advanced -match '^(|[YyNn])$') { break }
            Write-Host '  Enter Y or N.' -ForegroundColor Yellow
        } while ($true)
        if ($advanced -match '^[Yy]$') {
            Write-Host ''
            Write-Host '  PREFERENCES' -ForegroundColor Cyan
            Write-CliMenuOption -Key '1' -Label 'CLI at startup'
            Write-CliMenuOption -Key '2' -Label 'GUI at startup'
            Write-CliMenuOption -Key '3' -Label 'Ask each time'
            do {
                $mode = Read-CliPrompt '  Startup mode (1-3) [1]'
                if ($mode -in @('', '1', '2', '3')) { break }
                Write-Host '  Enter 1, 2, or 3.' -ForegroundColor Yellow
            } while ($true)
            $preferences.PreferredMode = switch ($mode) {
                '2' { 'GUI' }
                '3' { 'Prompt' }
                default { 'CLI' }
            }
            foreach ($setting in @(
                @{ Name = 'PersistentMapping'; Prompt = 'Reconnect at logon' },
                @{ Name = 'UnmapOldMapping'; Prompt = 'Auto-unmap after a drive-letter change' },
                @{ Name = 'SyncShareNameToDriveLabel'; Prompt = 'Sync share name to Explorer drive label' }
            )) {
                $current = [bool]$preferences.($setting.Name)
                $defaultText = if ($current) { 'Y' } else { 'N' }
                do {
                    $answer = Read-CliPrompt "  $($setting.Prompt)? (Y/N) [$defaultText]"
                    if ($answer -match '^(|[YyNn])$') { break }
                    Write-Host '  Enter Y or N.' -ForegroundColor Yellow
                } while ($true)
                if ($answer) { $preferences.($setting.Name) = $answer -match '^[Yy]$' }
            }
            Write-CliMenuOption -Key '1' -Label 'Classic GUI theme'
            Write-CliMenuOption -Key '2' -Label 'Modern GUI theme'
            do {
                $theme = Read-CliPrompt '  GUI theme (1-2) [1]'
                if ($theme -in @('', '1', '2')) { break }
                Write-Host '  Enter 1 or 2.' -ForegroundColor Yellow
            } while ($true)
            if ($theme -eq '2') { $preferences.Theme = 'Modern' }
            foreach ($timeout in @(
                @{ Name = 'UncProbeTimeoutSeconds'; Prompt = 'UNC probe timeout (seconds)'; Min = 1; Max = 30 },
                @{ Name = 'NetUseTimeoutSeconds'; Prompt = 'Net use timeout (seconds)'; Min = 5; Max = 120 }
            )) {
                $current = [int]$preferences.($timeout.Name)
                do {
                    $value = Read-CliPrompt "  $($timeout.Prompt) ($($timeout.Min)-$($timeout.Max)) [$current]"
                    if ($value -eq '') { break }
                    $parsed = 0
                    if ([int]::TryParse($value, [ref]$parsed) -and $parsed -ge $timeout.Min -and $parsed -le $timeout.Max) {
                        $preferences.($timeout.Name) = $parsed
                        break
                    }
                    Write-Host "  Enter a number from $($timeout.Min) to $($timeout.Max)." -ForegroundColor Yellow
                } while ($true)
            }
        }

        while ($true) {
            $actionComplete = $false
            $existingCount = @(Get-ShareConfiguration).Count
            Write-Host ''
            Write-Host '  FIRST SHARE' -ForegroundColor Cyan
            Write-CliMenuOption -Key '1' -Label 'Add a network share'
            Write-CliMenuOption -Key '2' -Label 'Restore a backup'
            if ($existingCount -gt 0) { Write-CliMenuOption -Key '3' -Label "Use $existingCount saved share(s)" }
            else { Write-CliMenuOption -Key '3' -Label 'Start with no shares' }
            Write-CliMenuOption -Key '0' -Label 'Cancel setup'
            $choice = Read-CliPrompt '  Choose (0-3)'
            switch ($choice) {
                '0' { Write-Host '  Setup remains unfinished and will resume next time.' -ForegroundColor Yellow; return $false }
                '1' {
                    $before = @(Get-ShareConfiguration).Count
                    Add-NewShareCli
                    if (@(Get-ShareConfiguration).Count -le $before) {
                        Write-Host '  No share was saved. Choose another option or try again.' -ForegroundColor Yellow
                        continue
                    }
                    $actionComplete = $true
                    break
                }
                '2' {
                    $path = Read-CliPrompt '  Backup JSON path'
                    if ([string]::IsNullOrWhiteSpace($path)) {
                        Write-Host '  No backup selected.' -ForegroundColor Yellow
                        continue
                    }
                    $result = Import-ShareConfiguration -ImportPath $path -Merge:$true
                    if (-not $result -or -not $result.Success -or @(Get-ShareConfiguration).Count -eq 0) {
                        Write-Host '  No usable shares were restored. Check the file and try again.' -ForegroundColor Yellow
                        continue
                    }
                    Write-Host '  Shares restored. Their passwords are not included in the backup.' -ForegroundColor Yellow
                    $actionComplete = $true
                    break
                }
                '3' { $actionComplete = $true; break }
                default { Write-Host '  Enter 0, 1, 2, or 3.' -ForegroundColor Yellow; continue }
            }
            if ($actionComplete) { break }
        }

        if (-not (Complete-FirstRunSetup -Preferences $preferences)) {
            Clear-ConfigCache
            Write-Host '  Setup could not be completed. Your shares remain saved; setup will resume next time.' -ForegroundColor Red
            return $false
        }
        $shares = @(Get-ShareConfiguration)
        Write-Host ''
        Write-Host "  Setup complete: $($shares.Count) share(s) configured." -ForegroundColor Green
        if ($shares.Count -eq 0) { Write-Host '  Add a share anytime from the main menu.' -ForegroundColor Gray }
        elseif ($choice -eq '2') { Write-Host '  Add saved credentials before connecting restored shares.' -ForegroundColor Yellow }
        return $true
    }
    catch [System.OperationCanceledException] {
        Write-Host '  Setup cancelled. It will resume next time.' -ForegroundColor Yellow
        return $false
    }
}

function Set-GuiVisualStyle {
    param([string]$Theme)
    Add-Type -AssemblyName System.Windows.Forms
    try {
        if ($Theme -eq 'Modern') {
            [System.Windows.Forms.Application]::EnableVisualStyles()
            [System.Windows.Forms.Application]::VisualStyleState = [System.Windows.Forms.VisualStyles.VisualStyleState]::ClientAndNonClientAreasEnabled
        } else {
            [System.Windows.Forms.Application]::VisualStyleState = [System.Windows.Forms.VisualStyles.VisualStyleState]::NoneEnabled
        }
    } catch {
        Write-Verbose "Could not apply GUI theme '$Theme': $_"
    }
}

function Show-FirstRunChoiceGUI {
    param([PSCustomObject]$Preferences, [string]$PreferredShareId)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Share Manager v$version - First Setup"
    $form.ClientSize = New-Object System.Drawing.Size(440, 292)
    $form.FormBorderStyle = 'FixedDialog'
    $form.StartPosition = 'CenterScreen'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $form.AutoScroll = $true
    $shares = @(Get-ShareConfiguration)
    $existingCount = $shares.Count
    $heading = New-Object System.Windows.Forms.Label
    $heading.Text = 'Set up Share Manager'
    $heading.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $heading.SetBounds(20, 16, 400, 30)
    $form.Controls.Add($heading)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Choose what to set up now.'
    $label.ForeColor = [System.Drawing.Color]::DimGray
    $label.SetBounds(20, 52, 400, 24)
    $form.Controls.Add($label)
    foreach ($option in @(
        @{ Text = 'Add Share'; Action = 'Add'; Top = 84; Left = 20 },
        @{ Text = 'Restore Backup'; Action = 'Restore'; Top = 84; Left = 226 }
    )) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $option.Text
        $button.Tag = $option.Action
        $button.SetBounds($option.Left, $option.Top, 194, 34)
        $button.Add_Click({
            $form.Tag = [PSCustomObject]@{ Action = [string]$this.Tag }
            $form.Close()
        })
        $form.Controls.Add($button)
        if ($option.Action -eq 'Add') { $addButton = $button }
    }
    $shareLabel = New-Object System.Windows.Forms.Label
    $shareLabel.Text = 'Your shares'
    $shareLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $shareLabel.SetBounds(20, 140, 260, 22)
    $form.Controls.Add($shareLabel)
    $countLabel = New-Object System.Windows.Forms.Label
    $countLabel.Text = "$existingCount configured"
    $countLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $countLabel.ForeColor = [System.Drawing.Color]::DimGray
    $countLabel.SetBounds(285, 140, 135, 22)
    $form.Controls.Add($countLabel)
    $sectionEnd = 204
    if ($existingCount -gt 0) {
        $form.ClientSize = New-Object System.Drawing.Size(440, 400)
        $sectionEnd = 310
        $shareList = New-Object System.Windows.Forms.ListView
        $shareList.SetBounds(20, 166, 400, 96)
        $shareList.View = [System.Windows.Forms.View]::Details
        $shareList.FullRowSelect = $true
        $shareList.MultiSelect = $false
        $shareList.HideSelection = $false
        $shareList.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
        [void]$shareList.Columns.Add('Name', 125)
        [void]$shareList.Columns.Add('Drive', 55)
        [void]$shareList.Columns.Add('Network path', 200)
        foreach ($share in $shares) {
            $item = New-Object System.Windows.Forms.ListViewItem([string]$share.Name)
            [void]$item.SubItems.Add("$($share.DriveLetter):")
            [void]$item.SubItems.Add([string]$share.SharePath)
            $item.Tag = [string]$share.Id
            [void]$shareList.Items.Add($item)
        }
        $form.Controls.Add($shareList)
        $selectedIndex = $existingCount - 1
        if ($PreferredShareId) {
            for ($i = 0; $i -lt $existingCount; $i++) {
                if ($shares[$i].Id -eq $PreferredShareId) { $selectedIndex = $i; break }
            }
        }
        $editButton = New-Object System.Windows.Forms.Button
        $editButton.Text = 'Edit selected'
        $editButton.SetBounds(196, 270, 108, 28)
        $editButton.Add_Click({
            if ($shareList.SelectedItems.Count -eq 0) { return }
            $form.Tag = [PSCustomObject]@{ Action = 'Edit'; ShareId = [string]$shareList.SelectedItems[0].Tag }
            $form.Close()
        })
        $form.Controls.Add($editButton)
        $removeButton = New-Object System.Windows.Forms.Button
        $removeButton.Text = 'Remove selected'
        $removeButton.SetBounds(310, 270, 110, 28)
        $removeButton.Add_Click({
            if ($shareList.SelectedItems.Count -eq 0) { return }
            $form.Tag = [PSCustomObject]@{ Action = 'Remove'; ShareId = [string]$shareList.SelectedItems[0].Tag }
            $form.Close()
        })
        $form.Controls.Add($removeButton)
        $shareList.Add_SelectedIndexChanged({
            $editButton.Enabled = $shareList.SelectedItems.Count -gt 0
            $removeButton.Enabled = $shareList.SelectedItems.Count -gt 0
        })
        $shareList.Add_DoubleClick({ $editButton.PerformClick() })
        $shareList.Items[$selectedIndex].Selected = $true
        $shareList.Items[$selectedIndex].Focused = $true
    } else {
        $emptyLabel = New-Object System.Windows.Forms.Label
        $emptyLabel.Text = 'No shares yet. You can finish setup now and add them later.'
        $emptyLabel.ForeColor = [System.Drawing.Color]::DimGray
        $emptyLabel.SetBounds(20, 174, 400, 32)
        $form.Controls.Add($emptyLabel)
    }
    $separator = New-Object System.Windows.Forms.Label
    $separator.BorderStyle = 'Fixed3D'
    $separator.SetBounds(20, $sectionEnd, 400, 2)
    $form.Controls.Add($separator)
    $prefSummary = New-Object System.Windows.Forms.Label
    $prefSummary.Text = if ($Preferences) { "$($Preferences.PreferredMode) at startup  |  $($Preferences.Theme) theme" } else { 'GUI at startup  |  Modern theme' }
    $prefSummary.ForeColor = [System.Drawing.Color]::DimGray
    $prefSummary.SetBounds(20, ($sectionEnd + 12), 280, 28)
    $form.Controls.Add($prefSummary)
    $prefButton = New-Object System.Windows.Forms.Button
    $prefButton.Text = 'Preferences...'
    $prefButton.SetBounds(298, ($sectionEnd + 8), 122, 30)
    $prefButton.Add_Click({ $form.Tag = [PSCustomObject]@{ Action = 'Preferences' }; $form.Close() })
    $form.Controls.Add($prefButton)
    $finish = New-Object System.Windows.Forms.Button
    $finish.Text = 'Finish Setup'
    $finish.SetBounds(196, ($sectionEnd + 52), 122, 28)
    $finish.Add_Click({ $form.Tag = [PSCustomObject]@{ Action = 'Finish' }; $form.Close() })
    $form.Controls.Add($finish)
    $form.AcceptButton = if ($existingCount -eq 0) { $addButton } else { $finish }
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.SetBounds(320, ($sectionEnd + 52), 100, 28)
    $cancel.Add_Click({ $form.Tag = [PSCustomObject]@{ Action = 'Cancel' }; $form.Close() })
    $form.Controls.Add($cancel)
    $form.CancelButton = $cancel
    $form.Add_FormClosing({
        if ((-not $form.Tag -or $form.Tag.Action -eq 'Cancel') -and $existingCount -gt 0) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                'Shares you added are saved. Setup will resume the next time you open Share Manager. Close setup now?',
                'Close setup', [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { $_.Cancel = $true; return }
        }
        if (-not $form.Tag) { $form.Tag = [PSCustomObject]@{ Action = 'Cancel' } }
    })
    [void]$form.ShowDialog()
    $choice = $form.Tag
    $form.Dispose()
    return $choice
}

function Show-FirstRunMessageGUI {
    param([string]$Message, [string]$Title, [string]$Icon = 'Information')
    [void][System.Windows.Forms.MessageBox]::Show($Message, $Title, 'OK', $Icon)
}

function Select-FirstRunBackupGUI {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = 'Select Share Manager Backup'
    $dialog.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $dialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    try {
        if ($dialog.ShowDialog() -eq 'OK') { return $dialog.FileName }
        return $null
    } finally {
        $dialog.Dispose()
    }
}

function Remove-FirstRunShareGUI {
    param([string]$ShareId)
    if (-not $ShareId) { return $false }
    $share = Get-ShareConfiguration -ShareId $ShareId
    if (-not $share) { return $false }
    $message = "Remove '$($share.Name)' from Share Manager?"
    if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
        $message += "`n`nThe existing drive mapping will remain connected."
    }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $message, 'Remove share', [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return $false }
    if (Remove-ShareConfiguration -ShareId $ShareId) { return $true }
    Show-FirstRunMessageGUI -Message 'The share could not be removed. Check folder permissions and disk space.' -Title 'Share Manager - Setup Error' -Icon Error
    return $false
}

function Initialize-Config-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    if (-not (Start-FirstRunSetup)) {
        Clear-ConfigCache
        Show-FirstRunMessageGUI -Message 'Setup could not be started. Check folder permissions and disk space.' -Title 'Share Manager - Setup Error' -Icon Error
        return $false
    }

    $preferences = (New-DefaultSharesConfig).Preferences
    $preferences.PreferredMode = 'GUI'
    $preferences.Theme = 'Modern'
    Set-GuiVisualStyle -Theme $preferences.Theme
    $restoredBackup = $false
    $selectedShareId = $null
    while ($true) {
        $selection = Show-FirstRunChoiceGUI -Preferences $preferences -PreferredShareId $selectedShareId
        if (-not $selection -or $selection.Action -eq 'Cancel') { return $false }
        $choice = $selection.Action
        if ($choice -eq 'Preferences') {
            $custom = Show-PreferencesForm -CurrentPrefs $preferences -IsInitial $false
            if ($custom) {
                $preferences = $custom
                Set-GuiVisualStyle -Theme $preferences.Theme
            }
            continue
        }
        if ($choice -eq 'Finish') { break }
        if ($choice -eq 'Edit') {
            if ($selection.ShareId -and (Get-ShareConfiguration -ShareId $selection.ShareId)) {
                $selectedShareId = $selection.ShareId
                Show-ManageShareDialog -ShareId $selection.ShareId -FromSetup
            }
            continue
        }
        if ($choice -eq 'Remove') {
            if (Remove-FirstRunShareGUI -ShareId $selection.ShareId) { $selectedShareId = $null }
            continue
        }
        if ($choice -eq 'Add') {
            Show-AddShareDialog
            continue
        }
        if ($choice -eq 'Restore') {
            $backupPath = Select-FirstRunBackupGUI
            if (-not $backupPath) { continue }
            $result = Import-ShareConfiguration -ImportPath $backupPath -Merge:$true
            if ($result -and $result.Success -and @(Get-ShareConfiguration).Count -gt 0) {
                $restoredBackup = $true
                continue
            }
            Show-FirstRunMessageGUI -Message 'No usable shares were restored. Check the backup file and try again.' -Title 'Share Manager - Import' -Icon Warning
        }
    }

    if (-not (Complete-FirstRunSetup -Preferences $preferences)) {
        Clear-ConfigCache
        Show-FirstRunMessageGUI -Message 'Setup could not be completed. Your shares remain saved; setup will resume next time.' -Title 'Share Manager - Setup Error' -Icon Error
        return $false
    }
    $shares = @(Get-ShareConfiguration)
    $message = "Setup complete: $($shares.Count) share(s) configured."
    if ($shares.Count -eq 0) {
        $message += " You can add one later from the main window."
    } elseif ($restoredBackup) {
        $message += " Passwords are not included in share backups. Add saved credentials before connecting."
    }
    Show-FirstRunMessageGUI -Message $message -Title 'Share Manager - Ready'
    return $true
}

function Get-UncPathValidation {
    param([string]$Path)
    if (Test-ValidUncPath -Path $Path) {
        return [PSCustomObject]@{ Valid = $true; Message = ''; Suggestion = $null }
    }

    $message = 'Enter a path such as \\server\share.'
    $suggestion = $null
    if ($Path -match '^\\\\([^\\]+)\\') {
        $server = $Matches[1]
        if ($server -match '[\s/:*?"<>|]') {
            $message = 'The server name contains a space or an invalid character.'
        } elseif ($server.Contains('..')) {
            $message = 'The server name contains consecutive dots.'
            if ($server -match '^[0-9.]+$') {
                $candidate = '\\' + ($server -replace '\.{2,}', '.') + $Path.Substring(2 + $server.Length)
                if (Test-ValidUncPath -Path $candidate) { $suggestion = $candidate }
            }
        } elseif ($server -match '^[0-9.]+$' -and $server.Contains('.')) {
            $message = 'IPv4 addresses need four numbers from 0 to 255, separated by single dots.'
        }
    }
    return [PSCustomObject]@{ Valid = $false; Message = $message; Suggestion = $suggestion }
}

#endregion

#region Credential GUI Form

function Confirm-ShareCredential {
    param([string]$Username, [switch]$Gui, [switch]$KeepExisting, [switch]$ReplaceExisting, [string]$ShareId, [switch]$ReturnToReview)
    $Username = $Username.Trim()
    if (-not $Username) { return $false }
    $existing = Get-CredentialForShare -Username $Username
    if ($existing -and $KeepExisting -and -not $ReplaceExisting) { return $true }
    $linked = @((Get-ShareConfiguration) | Where-Object { $_.Username -eq $Username -and (-not $ShareId -or $_.Id -ne $ShareId) } | ForEach-Object { $_.Name })
    $usage = if ($linked.Count) { "Used by: " + ($linked -join ', ') } else { 'No existing shares use this username.' }
    if ($existing -and $ReplaceExisting) {
        $question = "Replace the saved password for $Username ?`n`n$usage"
        if ($linked.Count -eq 0) {
            # The explicit change-password action is sufficient for an unshared credential.
        } elseif ($Gui) {
            if ([System.Windows.Forms.MessageBox]::Show($question, 'Replace Shared Password', 'YesNo', 'Warning') -ne 'Yes') { return $false }
        } else {
            Write-Host "  $usage" -ForegroundColor Yellow
            if ((Read-CliPrompt "  Replace the saved password for $Username for all linked shares? (Y/N) [N]") -ne 'Y') { return $false }
        }
    } elseif ($existing) {
        if ($Gui) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "Reuse the saved credential for $Username ?`n`n$usage`n`nYes: reuse. No: replace the password for all linked shares. Cancel: return without saving the share.",
                'Share Credential', [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($answer -eq 'Yes') { return $true }
            if ($answer -ne 'No') { return $false }
        } else {
            Write-Host "  $usage" -ForegroundColor Gray
            do { $answer = Read-CliPrompt "  Credential for $Username - reuse [R], replace for all linked shares [U], cancel [C] (default R)" } while ($answer -notmatch '^(|R|U|C)$')
            if ($answer -eq '' -or $answer -eq 'R') { return $true }
            if ($answer -eq 'C') { return $false }
        }
    } elseif ($linked.Count) {
        if ($Gui) {
            if ([System.Windows.Forms.MessageBox]::Show("Saving a password for $Username also affects these shares:`n$usage`n`nContinue?", 'Shared Credential', 'YesNo', 'Warning') -ne 'Yes') { return $false }
        } else {
            Write-Host "  $usage" -ForegroundColor Yellow
            if ((Read-CliPrompt '  Save a password for all these shares? (Y/N) [N]') -ne 'Y') { return $false }
        }
    }
    if ($Gui) {
        $credential = Show-CredentialForm -Username $Username -Message "Credential for $Username"
        if (-not $credential) { return $false }
        if ($credential.UserName -ne $Username) {
            [void][System.Windows.Forms.MessageBox]::Show('Change the username in the share dialog first, then save again.', 'Username Changed')
            return $false
        }
    } else {
        $passwordPrompt = if ($existing) { '  New password (Enter keeps existing): ' } elseif ($ReturnToReview) { '  Password (Enter returns to review): ' } else { '  Password (empty cancels): ' }
        $password = Read-Password $passwordPrompt
        if (-not $password -or $password.Length -eq 0) {
            if ($existing) {
                Write-Host '  Password unchanged.' -ForegroundColor Gray
                return $true
            }
            return $false
        }
        $credential = New-Object System.Management.Automation.PSCredential($Username, $password)
    }
    return (Save-Credential -Credential $credential -PassThru)
}

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
function Resolve-CliPrefix {
    param([string]$InputText, [hashtable]$Commands)
    if ([string]::IsNullOrWhiteSpace($InputText)) { return $null }
    $value = $InputText.Trim().ToLowerInvariant() -replace '\s+', '-'
    $matchingNames = @($Commands.Keys | Where-Object {
        if ($value -match '^[a-z]+-[a-z]+$' -and $_ -match '^[a-z]+-[a-z]+$') {
            $requestedParts = $value.Split('-')
            $parts = $_.Split('-')
            $requestedParts[0].Length -ge 3 -and $requestedParts[1].Length -ge 1 -and
                $parts[0].StartsWith($requestedParts[0]) -and $parts[1].StartsWith($requestedParts[1])
        } else {
            $value.Length -ge 2 -and $_ -notmatch '-all$' -and $_.StartsWith($value)
        }
    })
    if ($matchingNames.Count -eq 1) { return $Commands[$matchingNames[0]] }
    return $null
}

function Resolve-CliCommand {
    param([string]$InputText)
    if ($null -eq $InputText) { return $null }
    $value = $InputText.Trim().ToLowerInvariant()
    $commands = @{
        '1' = '1'; 'add' = '1'; 'add-share' = '1'
        '2' = '2'; 'manage' = '2'; 'shares' = '2'
        '3' = '3'; 'status' = '3'
        'c' = 'C'; 'connect-all' = 'C'
        'd' = 'D'; 'disconnect-all' = 'D'
        'n' = 'N'; 'reconnect-all' = 'N'
        'p' = 'P'; 'preferences' = 'P'
        'k' = 'K'; 'credentials' = 'K'
        'b' = 'B'; 'backup' = 'B'
        'l' = 'L'; 'logs' = 'L'
        'u' = 'U'; 'updates' = 'U'
        'g' = 'G'; 'gui' = 'G'
        'h' = 'H'; 'help' = 'H'; '?' = 'H'
        'q' = 'Q'; 'quit' = 'Q'; 'exit' = 'Q'
    }
    if ($commands.ContainsKey($value)) { return $commands[$value] }
    return Resolve-CliPrefix -InputText $value -Commands @{
        'add' = '1'; 'manage' = '2'; 'status' = '3'
        'connect-all' = 'C'; 'disconnect-all' = 'D'; 'reconnect-all' = 'N'
        'preferences' = 'P'; 'credentials' = 'K'; 'backup' = 'B'
        'logs' = 'L'; 'updates' = 'U'; 'gui' = 'G'; 'help' = 'H'; 'quit' = 'Q'
    }
}

function Write-CliMenuOption {
    param(
        [string]$Key,
        [string]$Label,
        [string]$Value = '',
        [string]$Indent = '  '
    )
    Write-Host "$Indent$Key" -NoNewline -ForegroundColor Yellow
    Write-Host " $Label" -NoNewline -ForegroundColor Gray
    if ($Value) { Write-Host $Value -ForegroundColor White }
    else { Write-Host '' }
}

function Show-CliHelp {
    param([switch]$NoPause)
    Clear-Host
    Write-Host ''
    Write-Host '  SHARE MANAGER COMMANDS' -ForegroundColor Cyan
    Write-Host '  ----------------------' -ForegroundColor DarkGray
    Write-CliMenuOption -Key 'Shares' -Label '      add, manage, status'
    Write-CliMenuOption -Key 'Connections' -Label ' connect-all, disconnect-all, reconnect-all'
    Write-CliMenuOption -Key 'Settings' -Label '    preferences, credentials'
    Write-CliMenuOption -Key 'Data' -Label '        backup, logs, updates'
    Write-CliMenuOption -Key 'App' -Label '         gui, help, quit'
    Write-Host ''
    Write-Host '  Shortcuts shown on the main screen continue to work.' -ForegroundColor DarkGray
    Write-Host '  Unique prefixes work (stat, pref); bulk commands need all (con a).' -ForegroundColor DarkGray
    Write-Host ''
    if (-not $NoPause) {
        Write-Host '  Press any key to return...' -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

function Resolve-CliManageCommand {
    param([string]$InputText)
    if ($null -eq $InputText) { return $null }
    $value = $InputText.Trim().ToLowerInvariant()
    $commands = @{
        's' = 'S'; 'status' = 'S'
        'e' = 'E'; 'edit' = 'E'
        'r' = 'R'; 'remove' = 'R'; 'delete' = 'R'
        'f' = 'F'; 'filter' = 'F'; 'search' = 'F'
        'x' = 'X'; 'batch' = 'X'
        'b' = 'B'; 'back' = 'B'; 'q' = 'B'; 'quit' = 'B'
    }
    if ($commands.ContainsKey($value)) { return $commands[$value] }
    if ($value -match '^\d+$') { return $value }
    return Resolve-CliPrefix -InputText $value -Commands @{
        'status' = 'S'; 'edit' = 'E'; 'remove' = 'R'
        'filter' = 'F'; 'batch' = 'X'; 'back' = 'B'
    }
}

function Select-CliSharesByFilter {
    param([array]$Shares, [string]$FilterText)
    if ([string]::IsNullOrWhiteSpace($FilterText)) { return $Shares }
    $escapedFilter = [WildcardPattern]::Escape($FilterText.Trim())
    return @($Shares | Where-Object {
        $_.Name -like "*$escapedFilter*" -or $_.SharePath -like "*$escapedFilter*" -or $_.DriveLetter -like "*$escapedFilter*"
    })
}

function Test-CliInteractiveInput {
    try {
        return ($Host.Name -eq 'ConsoleHost' -and -not [Console]::IsInputRedirected)
    } catch {
        return $false
    }
}

function Read-CliKey {
    return $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Write-CliPromptLine {
    param([string]$Text, [int]$CursorIndex, [int]$PreviousLength, [int]$StartLeft, [int]$StartTop, [int]$Width)
    try {
        [Console]::SetCursorPosition($StartLeft, $StartTop)
        Write-Host ($Text + (' ' * [Math]::Max(0, $PreviousLength - $Text.Length))) -NoNewline
        $position = $StartLeft + $CursorIndex
        [Console]::SetCursorPosition(($position % $Width), ($StartTop + [int][Math]::Floor($position / $Width)))
        return $true
    } catch {
        return $false
    }
}

function Read-CliPrompt {
    param([string]$Prompt)
    if (-not (Test-CliInteractiveInput)) {
        if ($PSBoundParameters.ContainsKey('Prompt')) { return Read-Host $Prompt }
        return Read-Host
    }
    if ($Prompt) { Write-Host "${Prompt}: " -NoNewline -ForegroundColor Cyan }
    $value = New-Object System.Text.StringBuilder
    $cursorIndex = 0
    $canPosition = $false
    try {
        $startLeft = [Console]::CursorLeft
        $startTop = [Console]::CursorTop
        $bufferWidth = [Console]::BufferWidth
        $canPosition = ($bufferWidth -gt 0)
    } catch { $canPosition = $false }
    while ($true) {
        $key = Read-CliKey
        switch ($key.VirtualKeyCode) {
            27 {
                Write-Host ''
                throw [System.OperationCanceledException]::new('Input cancelled with Escape')
            }
            13 {
                Write-Host ''
                return $value.ToString()
            }
            8 {
                if ($cursorIndex -gt 0) {
                    $previousLength = $value.Length
                    $null = $value.Remove($cursorIndex - 1, 1)
                    $cursorIndex--
                    if (-not $canPosition -or -not (Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $previousLength -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth)) {
                        Write-Host "`b `b" -NoNewline
                    }
                }
                continue
            }
            37 { if ($canPosition -and $cursorIndex -gt 0) { $cursorIndex--; $null = Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $value.Length -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth }; continue }
            39 { if ($canPosition -and $cursorIndex -lt $value.Length) { $cursorIndex++; $null = Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $value.Length -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth }; continue }
            36 { if ($canPosition) { $cursorIndex = 0; $null = Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $value.Length -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth }; continue }
            35 { if ($canPosition) { $cursorIndex = $value.Length; $null = Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $value.Length -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth }; continue }
            46 {
                if ($canPosition -and $cursorIndex -lt $value.Length) {
                    $previousLength = $value.Length
                    $null = $value.Remove($cursorIndex, 1)
                    $null = Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $previousLength -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth
                }
                continue
            }
        }
        if (-not [char]::IsControl($key.Character)) {
            $previousLength = $value.Length
            if ($canPosition) { $null = $value.Insert($cursorIndex, $key.Character) }
            else { $null = $value.Append($key.Character) }
            $cursorIndex++
            if (-not $canPosition -or -not (Write-CliPromptLine -Text $value.ToString() -CursorIndex $cursorIndex -PreviousLength $previousLength -StartLeft $startLeft -StartTop $startTop -Width $bufferWidth)) {
                Write-Host $key.Character -NoNewline
            }
        }
    }
}

function Get-CliManageTargets {
    param([array]$VisibleShares, [int]$FocusedIndex, [hashtable]$SelectedIds)
    $selected = @($VisibleShares | Where-Object { $SelectedIds.ContainsKey([string]$_.Id) })
    if ($selected.Count -gt 0) { return $selected }
    if ($FocusedIndex -ge 0 -and $FocusedIndex -lt $VisibleShares.Count) {
        return @($VisibleShares[$FocusedIndex])
    }
    return @()
}

function Invoke-CliManageAction {
    param([ValidateSet('C', 'D', 'E', 'R', 'Enable', 'Disable')][string]$Action, [array]$Targets)
    $ids = @($Targets | ForEach-Object { [string]$_.Id })
    $shares = @(Get-ShareConfiguration | Where-Object { $ids -contains [string]$_.Id })
    if ($shares.Count -eq 0) {
        Write-Host '  The selected shares no longer exist. Refresh Manage Shares.' -ForegroundColor Yellow
        return $true
    }
    if ($Action -in @('E', 'R')) {
        if ($shares.Count -ne 1) {
            Write-Host '  Select one share to edit or remove it.' -ForegroundColor Yellow
            return $true
        }
        if ($Action -eq 'E') { Edit-ShareCli -Shares $shares -Direct }
        else { Remove-ShareCli -Shares $shares -Direct }
        return $true
    }

    Write-Host ''
    Write-Host "  $Action $($shares.Count) share(s):" -ForegroundColor Cyan
    foreach ($share in $shares) { Write-Host "    $($share.Name) [$($share.DriveLetter):]" -ForegroundColor Gray }
    if ($shares.Count -gt 1 -or $Action -in @('Enable', 'Disable')) {
        $confirm = Read-CliPrompt '  Continue? (Y/N) [N]'
        if ($confirm -notmatch '^[Yy]$') {
            return $false
        }
    }

    if ($Action -in @('Enable', 'Disable')) {
        $config = Get-CachedConfig -Force
        $enabled = ($Action -eq 'Enable')
        $changed = 0
        foreach ($share in $config.Shares) {
            if ($ids -contains [string]$share.Id -and $share.Enabled -ne $enabled) {
                $share.Enabled = $enabled
                $changed++
            }
        }
        if ($changed -eq 0) { Write-Host '  No changes needed.' -ForegroundColor DarkGray }
        elseif (Save-AllShares -Config $config) {
            Write-Host "  [OK] Updated $changed share(s)." -ForegroundColor Green
        } else { Write-Host '  [X] Could not save changes.' -ForegroundColor Red }
        return $true
    }

    foreach ($share in $shares) {
        if ($Action -eq 'C') {
            if (-not $share.Enabled) {
                Write-Host "  [ ] $($share.Name): disabled" -ForegroundColor Yellow
                continue
            }
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                Write-Host "  [ ] $($share.Name): already connected" -ForegroundColor DarkGray
                continue
            }
            $cred = Get-CredentialForShare -Username $share.Username
            if (-not $cred) {
                Write-Host "  Password needed for $($share.Name) ($($share.Username))." -ForegroundColor Yellow
                $password = Read-Password '  Password: '
                if (-not $password -or $password.Length -eq 0) {
                    Write-Host "  [ ] $($share.Name): skipped" -ForegroundColor Yellow
                    continue
                }
                $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
            }
            Write-Host "  Connecting $($share.Name) [$($share.DriveLetter):]..." -ForegroundColor Cyan
            $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
            if ($result.Success) { Write-Host '  [OK] Mapping succeeded.' -ForegroundColor Green }
            else { Write-Host "  [X] $($result.ErrorMessage)" -ForegroundColor Red }
        } else {
            Write-Host "  Disconnecting $($share.Name) [$($share.DriveLetter):]..." -ForegroundColor Cyan
            $result = Disconnect-NetworkShare -DriveLetter $share.DriveLetter -ReturnStatus -Silent
            if ($result.Success) { Write-Host '  [OK] Disconnected.' -ForegroundColor Green }
            elseif ($result.ErrorType -eq 'NotMapped') { Write-Host '  [ ] Not mapped.' -ForegroundColor DarkGray }
            else { Write-Host "  [X] $($result.ErrorMessage)" -ForegroundColor Red }
        }
    }
    return $true
}

function Show-CliShareDetails {
    param($Share, [bool]$Connected)
    Clear-Host
    Write-Host ''
    Write-Host "  ======[ $($Share.Name) ]======" -ForegroundColor Cyan
    Write-Host "  Drive       $($Share.DriveLetter):" -ForegroundColor White
    Write-Host "  Path        $($Share.SharePath)" -ForegroundColor Gray
    Write-Host "  Connection  $(if ($Connected) { 'Connected' } else { 'Disconnected' })" -ForegroundColor $(if ($Connected) { 'Green' } else { 'Yellow' })
    Write-Host "  Enabled     $($Share.Enabled)" -ForegroundColor Gray
    if ($Share.Description) { Write-Host "  Description $($Share.Description)" -ForegroundColor Gray }
    Write-Host ''
    if ($Share.Enabled -and -not $Connected) { Write-CliMenuOption -Key 'C' -Label 'Connect' }
    Write-CliMenuOption -Key 'D' -Label 'Disconnect'
    Write-CliMenuOption -Key 'E' -Label 'Edit'
    Write-CliMenuOption -Key 'R' -Label 'Remove'
    Write-CliMenuOption -Key 'Esc' -Label 'Back'
    $key = Read-CliKey
    if ($key.VirtualKeyCode -eq 27) { return $null }
    $action = [string]$key.Character
    if ($action -match '^[cder]$') {
        if ($action -eq 'c' -and ($Connected -or -not $Share.Enabled)) { return $null }
        return $action.ToUpperInvariant()
    }
    return $null
}

function Show-CliManageHelp {
    Clear-Host
    Write-Host ''
    Write-Host '  MANAGE SHARES - KEYS' -ForegroundColor Cyan
    Write-CliMenuOption -Key 'Up/Down' -Label '   Move focus'
    Write-CliMenuOption -Key 'Enter' -Label '     Open focused share'
    Write-CliMenuOption -Key 'Space' -Label '     Select or unselect focused share'
    Write-CliMenuOption -Key 'A / U' -Label '     Select all shown / clear selection'
    Write-CliMenuOption -Key 'C / D' -Label '     Connect / disconnect selected shares'
    Write-CliMenuOption -Key 'X' -Label '         Enable or disable selected shares'
    Write-CliMenuOption -Key 'E / R' -Label '     Edit or remove one selected share'
    Write-CliMenuOption -Key '/' -Label '         Search by name, path, or drive'
    Write-CliMenuOption -Key 'S / T' -Label '     Status / refresh connection states'
    Write-CliMenuOption -Key ':' -Label '         Switch to the numbered menu'
    Write-CliMenuOption -Key 'Esc' -Label '       Return to the main menu'
    Write-Host ''
    Write-Host '  Press any key to return...' -ForegroundColor DarkGray
    $null = Read-CliKey
}

function Show-CliInteractiveManageShares {
    $filterText = ''
    $selectedIds = @{}
    $focusedIndex = 0
    $statusCache = @{}
    while ($true) {
        $allShares = @(Get-ShareConfiguration)
        $shares = @(Select-CliSharesByFilter -Shares $allShares -FilterText $filterText)
        if ($shares.Count -eq 0 -and $allShares.Count -eq 0) {
            Write-Host '  No shares configured. Add one from the main menu.' -ForegroundColor Yellow
            Write-Host '  Press any key to return...' -ForegroundColor DarkGray
            $null = Read-CliKey
            return $true
        }
        if ($focusedIndex -ge $shares.Count) { $focusedIndex = [Math]::Max(0, $shares.Count - 1) }
        $windowHeight = 25
        try { $windowHeight = [Math]::Max(12, [Console]::WindowHeight) } catch { $windowHeight = 25 }
        $pageSize = [Math]::Max(1, [int][Math]::Floor(($windowHeight - 11) / 2))
        $pageStart = [int][Math]::Floor($focusedIndex / $pageSize) * $pageSize
        $pageEnd = [Math]::Min($shares.Count, $pageStart + $pageSize)
        for ($i = $pageStart; $i -lt $pageEnd; $i++) {
            $share = $shares[$i]
            $id = [string]$share.Id
            if (-not $statusCache.ContainsKey($id)) {
                $statusCache[$id] = [bool](Test-ShareConnection -DriveLetter $share.DriveLetter)
            }
        }
        $visibleIds = @($shares | ForEach-Object { [string]$_.Id })
        foreach ($id in @($selectedIds.Keys)) {
            if ($visibleIds -notcontains $id) { $selectedIds.Remove($id) }
        }
        $selectedShares = @($shares | Where-Object { $selectedIds.ContainsKey([string]$_.Id) })
        foreach ($share in $selectedShares) {
            $id = [string]$share.Id
            if (-not $statusCache.ContainsKey($id)) {
                $statusCache[$id] = [bool](Test-ShareConnection -DriveLetter $share.DriveLetter)
            }
        }
        $canConnect = @($selectedShares | Where-Object { $_.Enabled -and -not $statusCache[[string]$_.Id] }).Count -gt 0
        Clear-Host
        Write-Host ''
        Write-Host "  MANAGE SHARES  ($($shares.Count) shown)" -ForegroundColor Cyan
        if ($filterText) { Write-Host "  Search: $filterText" -ForegroundColor Yellow }
        if ($shares.Count -gt $pageSize) { Write-Host "  Rows $($pageStart + 1)-$pageEnd of $($shares.Count)" -ForegroundColor DarkGray }
        Write-Host ''
        if ($shares.Count -eq 0) { Write-Host '  No matching shares. Press / to search again.' -ForegroundColor Yellow }
        for ($i = $pageStart; $i -lt $pageEnd; $i++) {
            $share = $shares[$i]
            $id = [string]$share.Id
            $cursor = if ($i -eq $focusedIndex) { '>' } else { ' ' }
            $mark = if ($selectedIds.ContainsKey($id)) { '[x]' } else { '[ ]' }
            $state = if (-not $share.Enabled) { 'Disabled' } elseif ($statusCache[$id]) { 'Connected' } else { 'Disconnected' }
            $nameColor = if (-not $share.Enabled) { 'DarkGray' } elseif ($i -eq $focusedIndex) { 'White' } else { 'Gray' }
            $stateColor = if (-not $share.Enabled) { 'DarkGray' } elseif ($statusCache[$id]) { 'Green' } else { 'Yellow' }
            Write-Host "  $cursor " -NoNewline -ForegroundColor $(if ($i -eq $focusedIndex) { 'Cyan' } else { 'DarkGray' })
            Write-Host "$mark " -NoNewline -ForegroundColor $(if ($selectedIds.ContainsKey($id)) { 'Yellow' } else { 'DarkGray' })
            Write-Host "$($share.Name) [$($share.DriveLetter):]  " -NoNewline -ForegroundColor $nameColor
            Write-Host $state -ForegroundColor $stateColor
            Write-Host "          $($share.SharePath)" -ForegroundColor DarkGray
        }
        Write-Host ''
        if ($selectedIds.Count -gt 0) {
            Write-Host "  $($selectedIds.Count) selected" -ForegroundColor Cyan
            if ($canConnect) {
                Write-Host '  C' -NoNewline -ForegroundColor Yellow
                Write-Host ' Connect   ' -NoNewline -ForegroundColor Gray
            } else { Write-Host '  ' -NoNewline }
            Write-Host 'D' -NoNewline -ForegroundColor Yellow
            Write-Host ' Disconnect   ' -NoNewline -ForegroundColor Gray
            Write-Host 'X' -NoNewline -ForegroundColor Yellow
            Write-Host ' Enable/disable' -ForegroundColor Gray
            if ($selectedIds.Count -eq 1) {
                Write-Host '  E' -NoNewline -ForegroundColor Yellow
                Write-Host ' Edit   ' -NoNewline -ForegroundColor Gray
                Write-Host 'R' -NoNewline -ForegroundColor Yellow
                Write-Host ' Remove' -ForegroundColor Gray
            }
        }
        Write-Host '  Up/Down' -NoNewline -ForegroundColor Yellow
        Write-Host ' Move   ' -NoNewline -ForegroundColor Gray
        Write-Host 'Enter' -NoNewline -ForegroundColor Yellow
        Write-Host ' Open   ' -NoNewline -ForegroundColor Gray
        Write-Host 'Space' -NoNewline -ForegroundColor Yellow
        Write-Host ' Select   ' -NoNewline -ForegroundColor Gray
        Write-Host '/' -NoNewline -ForegroundColor Yellow
        Write-Host ' Search' -ForegroundColor Gray
        Write-Host '  Esc' -NoNewline -ForegroundColor Yellow
        Write-Host ' Back       ' -NoNewline -ForegroundColor Gray
        Write-Host '?' -NoNewline -ForegroundColor Yellow
        Write-Host ' More' -ForegroundColor Gray
        try { $key = Read-CliKey }
        catch { return $false }
        switch ($key.VirtualKeyCode) {
            38 { if ($focusedIndex -gt 0) { $focusedIndex-- }; continue }
            40 { if ($focusedIndex -lt $shares.Count - 1) { $focusedIndex++ }; continue }
            27 { return $true }
            13 {
                if ($shares.Count -eq 0) { continue }
                $share = $shares[$focusedIndex]
                $action = Show-CliShareDetails -Share $share -Connected $statusCache[[string]$share.Id]
                if ($action) {
                    try { $shouldPause = Invoke-CliManageAction -Action $action -Targets @($share) }
                    catch [System.OperationCanceledException] { continue }
                    if ($shouldPause) {
                        Write-Host '  Press any key to return...' -ForegroundColor DarkGray
                        $null = Read-CliKey
                    }
                    $statusCache = @{}
                }
                continue
            }
            32 {
                if ($shares.Count -gt 0) {
                    $id = [string]$shares[$focusedIndex].Id
                    if ($selectedIds.ContainsKey($id)) { $selectedIds.Remove($id) }
                    else { $selectedIds[$id] = $true }
                }
                continue
            }
        }
        $letter = ([string]$key.Character).ToUpperInvariant()
        if ($letter -eq 'B') { return $true }
        if ($letter -eq '?') { Show-CliManageHelp; continue }
        if ($letter -eq ':') { return $false }
        if ($letter -eq '/') {
            try { $filterText = (Read-CliPrompt '  Search by name, path, or drive (blank clears)').Trim() }
            catch [System.OperationCanceledException] { continue }
            $focusedIndex = 0
            $selectedIds = @{}
            continue
        }
        if ($letter -eq 'A') {
            foreach ($share in $shares) { $selectedIds[[string]$share.Id] = $true }
            continue
        }
        if ($letter -eq 'U') { $selectedIds = @{}; continue }
        if ($letter -eq 'T') { $statusCache = @{}; continue }
        if ($letter -eq 'S') {
            Show-ShareStatusCli
            Write-Host '  Press any key to return...' -ForegroundColor DarkGray
            $null = Read-CliKey
            continue
        }
        if ($letter -notin @('C', 'D', 'E', 'R', 'X')) { continue }
        if ($selectedIds.Count -eq 0) { continue }
        if ($letter -eq 'C' -and -not $canConnect) { continue }
        $targets = @(Get-CliManageTargets -VisibleShares $shares -FocusedIndex $focusedIndex -SelectedIds $selectedIds)
        if ($targets.Count -eq 0) { continue }
        if ($letter -eq 'X') {
            $hasDisabled = @($targets | Where-Object { -not $_.Enabled }).Count -gt 0
            $hasEnabled = @($targets | Where-Object { $_.Enabled }).Count -gt 0
            if ($hasDisabled) { Write-CliMenuOption -Key '1' -Label 'Enable selected' }
            if ($hasEnabled) { Write-CliMenuOption -Key '2' -Label 'Disable selected' }
            Write-CliMenuOption -Key 'Esc' -Label 'Cancel'
            $operation = Read-CliKey
            try {
                if ($operation.Character -eq '1' -and $hasDisabled) { $shouldPause = Invoke-CliManageAction -Action Enable -Targets $targets }
                elseif ($operation.Character -eq '2' -and $hasEnabled) { $shouldPause = Invoke-CliManageAction -Action Disable -Targets $targets }
                else { continue }
            } catch [System.OperationCanceledException] { continue }
        } else {
            try { $shouldPause = Invoke-CliManageAction -Action $letter -Targets $targets }
            catch [System.OperationCanceledException] { continue }
        }
        if ($shouldPause) {
            Write-Host '  Press any key to return...' -ForegroundColor DarkGray
            $null = Read-CliKey
        }
        $statusCache = @{}
        $selectedIds = @{}
    }
}

function Start-CliMode {
    Write-ActionLog -Message "Entering CLI mode" -Level INFO -Category 'Startup'
    Set-TerminalBlackBackground
    
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
        Write-Host ''
        Write-Host '  Choice (Esc quits): ' -NoNewline -ForegroundColor Cyan
        try { $rawChoice = Read-CliPrompt }
        catch [System.OperationCanceledException] {
            Write-ActionLog -Message 'User exited CLI mode with Escape' -Level INFO -Category 'Startup'
            return
        }
        $choice = Resolve-CliCommand -InputText $rawChoice
        
        Write-Host ""
        
    # Auto-continue actions that don't need user confirmation
    $autoContinue = @("L","1","2","C","D","N")
        
        try {
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
                Disconnect-AllSharesCli
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
            "U" { Update-ShareManager }
            "L" { 
                Write-Host "`n=== Log Menu ===" -ForegroundColor Cyan
                Write-CliMenuOption -Key '1.' -Label 'Open Log File'
                Write-CliMenuOption -Key '2.' -Label 'Query Events'
                Write-CliMenuOption -Key '3.' -Label 'Back'
                $logChoice = Read-CliPrompt "Select (1-3)"
                switch ($logChoice) {
                    "1" { Invoke-LogFileOpen -Prompt; Start-Sleep -Seconds 1 }
                    "2" {
                        Write-Host "`n=== Query Log Events ===" -ForegroundColor Cyan
                        Write-Host "Category filter (leave blank for all):"
                        Write-Host "  Config, Credentials, BackupRestore, Migration, Mapping, Log, Startup, AutoMap" -ForegroundColor Gray
                        $cat = Read-CliPrompt "Category"
                        
                        Write-Host "`nLevel filter (leave blank for all):"
                        Write-Host "  DEBUG, INFO, WARN, ERROR" -ForegroundColor Gray
                        $lvl = Read-CliPrompt "Level"
                        
                        $lastN = Read-CliPrompt "Show last N events (leave blank for all)"
                        
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
            
            "H" { Show-CliHelp }

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
                if ([string]::IsNullOrWhiteSpace($rawChoice)) {
                    Write-Host "  Enter a command, or type 'help' to see available commands." -ForegroundColor Yellow
                } else {
                    Write-Host "  Unknown choice '$($rawChoice.Trim())'. Enter a shown key or type help." -ForegroundColor Red
                }
                Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
        
        # Only pause for actions that need it (skip for actions with their own pause)
        if ($choice -and $choice -notin @("Q", "G", "H", "3", "B", "P", "D", "C", "N") + $autoContinue) {
            Write-Host ""
            Write-Host "  Press any key..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        } catch [System.OperationCanceledException] {
            continue
        }
    } while ($true)
}

function Show-ManageSharesMenu {
    <#
    .SYNOPSIS
        Shows submenu for managing existing shares with filtering and batch operations
    #>
    if (Test-CliInteractiveInput) {
        if (Show-CliInteractiveManageShares) { return }
    }
    $filterText = ""
    
    do {
        Clear-Host
        Write-Host ""
        Write-Host "  ======[ MANAGE SHARES ]======" -ForegroundColor Cyan
        
    $allShares = @(Get-ShareConfiguration)
        
        if ($allShares.Count -eq 0) {
            Write-Host "  No shares configured." -ForegroundColor Yellow
            Write-Host "  Add a share from the main menu to get started." -ForegroundColor DarkGray
            Write-Host "  Press any key to return..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        
        # Apply filter if set
        if ($filterText) {
            $shares = @(Select-CliSharesByFilter -Shares $allShares -FilterText $filterText)
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
            Write-Host "  F" -NoNewline -ForegroundColor Yellow
            Write-Host " - Clear Filter  " -NoNewline -ForegroundColor Gray
            Write-Host "B" -NoNewline -ForegroundColor Yellow
            Write-Host " - Back" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Manage choice: " -NoNewline -ForegroundColor Cyan
            $rawChoice = Read-CliPrompt
            $choice = Resolve-CliManageCommand -InputText $rawChoice
            
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
            Write-Host "$idxStr " -NoNewline -ForegroundColor Yellow
            
            Write-Host "$($share.Name)" -NoNewline -ForegroundColor $nameColor
            if ($enabledIndicator) {
                Write-Host $enabledIndicator -NoNewline -ForegroundColor DarkGray
            }
            Write-Host " " -NoNewline
            Write-Host "[$($share.DriveLetter):]" -NoNewline -ForegroundColor DarkGray
            Write-Host " " -NoNewline
            Write-Host "$($share.SharePath)" -ForegroundColor DarkGray
            
            $index++
        }
        
        Write-Host ""
        Write-Host "  Actions:" -ForegroundColor DarkGray
        Write-Host "    1-$($shares.Count)" -NoNewline -ForegroundColor Yellow
        Write-Host " - Toggle connect/disconnect  " -NoNewline -ForegroundColor Gray
        Write-Host "S" -NoNewline -ForegroundColor Yellow
        Write-Host " - Show status" -ForegroundColor Gray
        Write-Host "    E" -NoNewline -ForegroundColor Yellow
        Write-Host " - Edit share  " -NoNewline -ForegroundColor Gray
        Write-Host "R" -NoNewline -ForegroundColor Yellow
        Write-Host " - Remove share  " -NoNewline -ForegroundColor Gray
        Write-Host "F" -NoNewline -ForegroundColor Yellow
        Write-Host " - Filter shares" -ForegroundColor Gray
        Write-Host "    X" -NoNewline -ForegroundColor Yellow
        Write-Host " - Batch enable/disable  " -NoNewline -ForegroundColor Gray
        Write-Host "B" -NoNewline -ForegroundColor Yellow
        Write-Host " - Back to main menu" -ForegroundColor Gray
        Write-Host "    Type a share number or one of the action keys above." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Manage choice: " -NoNewline -ForegroundColor Cyan
        $rawChoice = Read-CliPrompt
        $choice = Resolve-CliManageCommand -InputText $rawChoice
        
        try {
        # Status command
        if ($choice -eq "S") {
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ CONNECTION STATUS ]======" -ForegroundColor Cyan
            Write-Host ""
            
            $connected = @($shares | Where-Object { $_.Enabled -and (Test-ShareConnection -DriveLetter $_.DriveLetter) })
            $disconnected = @($shares | Where-Object { $_.Enabled -and -not (Test-ShareConnection -DriveLetter $_.DriveLetter) })
            $disabled = @($shares | Where-Object { -not $_.Enabled })
            
            Write-Host "  Connected: " -NoNewline -ForegroundColor Green
            Write-Host "$($connected.Count)" -ForegroundColor White
            if ($connected.Count -gt 0) {
                foreach ($s in $connected) {
                    Write-Host "    [$($s.DriveLetter):] " -NoNewline -ForegroundColor DarkGray
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
                Write-Host "  Disabled: " -NoNewline -ForegroundColor DarkGray
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
            
            if (-not $share.Enabled -and -not $connected) {
                Write-Host "  $($share.Name) is disabled. Use X - Batch enable/disable first." -ForegroundColor Yellow
                Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                continue
            }
            if ($connected) {
                Write-Host "  Disconnecting..." -ForegroundColor Yellow
                Disconnect-NetworkShare -DriveLetter $share.DriveLetter
            } else {
                Write-Host "  Connecting..." -ForegroundColor Green
                $cred = Get-CredentialForShare -Username $share.Username
                
                if (-not $cred) {
                    Write-Host "  No saved credentials" -ForegroundColor Yellow
                    $password = Read-Password "  Password: "
                    if ($password.Length -gt 0) {
                        $cred = New-Object System.Management.Automation.PSCredential($share.Username, $password)
                        Write-Host "  Save credentials? (Y/N) [Y]: " -NoNewline
                        $saveIt = Read-CliPrompt
                        if ($saveIt -eq "" -or $saveIt -match '^[Yy]$') {
                            Save-Credential -Credential $cred
                        }
                    }
                }
                
                if ($cred) {
                    $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus

                    if ($result.Success) {
                        Write-Host "  [OK] $($share.Name) mapped to $($share.DriveLetter):" -ForegroundColor Green
                        $config = Get-CachedConfig
                        $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                        if ($shareObj) {
                            $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            Save-AllShares -Config $config | Out-Null
                        }
                    }
                }
            }
            Write-Host "  Press any key to return to Manage..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        elseif ($choice -eq "E") {
            Edit-ShareCli -Shares $shares
            $filterText = ""  # Clear filter after edit
        }
        elseif ($choice -eq "R") {
            Remove-ShareCli -Shares $shares
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
            $newFilter = Read-CliPrompt
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
            Write-Host "  Unknown command. Enter a share number or use status, edit, remove, filter, batch, or back." -ForegroundColor Red
            Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        } catch [System.OperationCanceledException] {
            continue
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
            $shares = @(Select-CliSharesByFilter -Shares $allShares -FilterText $CurrentFilter)
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
        Write-Host "  1" -NoNewline -ForegroundColor Yellow
        Write-Host " - Pick shares to enable" -NoNewline -ForegroundColor Gray
        Write-Host "   (interactive selection)" -ForegroundColor DarkGray
        Write-Host "  2" -NoNewline -ForegroundColor Yellow
        Write-Host " - Pick shares to disable" -NoNewline -ForegroundColor Gray
        Write-Host "  (interactive selection)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  3" -NoNewline -ForegroundColor Yellow
        Write-Host " - Enable all $($shares.Count) $(if ($CurrentFilter) { '(filtered)' } else { '' })" -ForegroundColor Gray
        Write-Host "  4" -NoNewline -ForegroundColor Yellow
        Write-Host " - Disable all $($shares.Count) $(if ($CurrentFilter) { '(filtered)' } else { '' })" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  B" -NoNewline -ForegroundColor Yellow
        Write-Host " - Back to manage menu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  > " -NoNewline -ForegroundColor Cyan
        $choice = Read-CliPrompt
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
                        $configShare = $config.Shares | Where-Object { $_.Id -eq $selectedShare.Id } | Select-Object -First 1
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
                        $configShare = $config.Shares | Where-Object { $_.Id -eq $selectedShare.Id } | Select-Object -First 1
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
                Write-Host "  Enable all $($shares.Count) share(s)? (Y/N) [N]: " -NoNewline
                $confirm = Read-CliPrompt
                if ($confirm -match '^[Yy]$') {
                    $config = Get-CachedConfig -Force
                    $enabled = 0
                    foreach ($share in $shares) {
                        $configShare = $config.Shares | Where-Object { $_.Id -eq $share.Id } | Select-Object -First 1
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
                $confirm = Read-CliPrompt
                if ($confirm -match '^[Yy]$') {
                    $config = Get-CachedConfig -Force
                    $disabled = 0
                    foreach ($share in $shares) {
                        $configShare = $config.Shares | Where-Object { $_.Id -eq $share.Id } | Select-Object -First 1
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
        Write-Host "A" -NoNewline -ForegroundColor Yellow
        Write-Host " when done to apply changes" -ForegroundColor DarkGray
        Write-Host "    - Press " -NoNewline -ForegroundColor DarkGray
        Write-Host "C" -NoNewline -ForegroundColor Yellow
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
                    Write-Host "[DISABLED]" -ForegroundColor DarkGray
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
        $choice = Read-CliPrompt
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
    param([array]$Shares, [switch]$Direct)
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ EDIT SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = if ($PSBoundParameters.ContainsKey('Shares')) { @($Shares) } else { @(Get-ShareConfiguration) }
    if ($shares.Count -eq 0) {
        Write-Host "  No shares to edit" -ForegroundColor Yellow
        return
    }
    
    for ($i = 0; $i -lt $shares.Count; $i++) {
        Write-Host "  $($i + 1). $($shares[$i].Name)"
    }
    
    Write-Host ""
    if ($Direct -and $shares.Count -eq 1) { $choice = '1' }
    else {
        Write-Host "  Select share (or 0 to cancel): " -NoNewline -ForegroundColor White
        $choice = Read-CliPrompt
    }
    $num = 0
    
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $shares.Count) {
        $share = $shares[$num - 1] | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        
        Write-Host ""
        Write-Host "  Editing: $($share.Name)" -ForegroundColor Cyan
        Write-Host "  (Leave blank to keep current value)" -ForegroundColor DarkGray
        Write-Host ""
        
        # Name
        Write-Host "  Name [$($share.Name)]: " -NoNewline
        $newName = Read-CliPrompt
        if (-not [string]::IsNullOrWhiteSpace($newName)) {
            $share.Name = $newName
        }
        
        # SharePath
        Write-Host "  Share Path [$($share.SharePath)]: " -NoNewline
        $newPath = Read-CliPrompt
        if (-not [string]::IsNullOrWhiteSpace($newPath)) {
            $share.SharePath = $newPath
        }
        
        # DriveLetter
        Write-Host "  Drive Letter [$($share.DriveLetter)]: " -NoNewline
        $newDrive = Read-CliPrompt
        if (-not [string]::IsNullOrWhiteSpace($newDrive)) {
            $newDrive = $newDrive.ToUpper() -replace '[^A-Z]', ''
            if ($newDrive.Length -eq 1) {
                $share.DriveLetter = $newDrive
            } else {
                Write-Host "  Invalid drive letter, keeping current." -ForegroundColor Yellow
            }
        }
        
        # Username
        Write-Host "  Saved credentials: $((@(Get-RecentUsernames)) -join ', ')" -ForegroundColor Gray
        Write-Host "  Enter keeps credentials; /password updates this share's saved password." -ForegroundColor DarkGray
        Write-Host "  Username [$($share.Username)]: " -NoNewline
        $newUser = Read-CliPrompt
        $changePassword = ($newUser.Trim() -eq '/password')
        $keepCredential = [string]::IsNullOrWhiteSpace($newUser) -or $newUser.Trim() -eq $share.Username
        if (-not $changePassword -and -not [string]::IsNullOrWhiteSpace($newUser)) {
            $share.Username = $newUser.Trim()
        }
        if (-not (Confirm-ShareCredential -Username $share.Username -KeepExisting:$keepCredential -ReplaceExisting:$changePassword -ShareId $share.Id)) { return }
        
        # Description
        Write-Host "  Description [$($share.Description)]: " -NoNewline
        $newDesc = Read-CliPrompt
        if (-not [string]::IsNullOrWhiteSpace($newDesc)) {
            $share.Description = $newDesc
        }
        
        # Category
        $currentCategory = if ($share.PSObject.Properties['Category']) { $share.Category } else { "General" }
        Write-Host "  Categories: $((Get-ShareCategories -IncludeSuggestions) -join ', ')" -ForegroundColor Gray
        Write-Host "  Category [$currentCategory]: " -NoNewline
        $newCategory = Read-CliPrompt
        
        # Enabled
        Write-Host "  Enabled [$($share.Enabled)] (Y/N/blank): " -NoNewline
        $toggle = Read-CliPrompt
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
            if (-not [string]::IsNullOrWhiteSpace($newCategory)) {
                Set-ShareCategory -ShareId $share.Id -Category $newCategory
            }
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
        $statusColor = if (-not $share.Enabled) { 'DarkGray' } elseif ($connected) { 'Green' } else { 'Yellow' }
        
        Write-Host "  $icon " -ForegroundColor $statusColor -NoNewline
        Write-Host "$($share.Name) " -ForegroundColor $(if ($connected) { "White" } else { "Gray" }) -NoNewline
        Write-Host "[$($share.DriveLetter):]" -ForegroundColor DarkGray
        Write-Host "      $($share.SharePath)" -ForegroundColor DarkGray
        if (-not [string]::IsNullOrWhiteSpace($share.Description)) {
            Write-Host "      $($share.Description)" -ForegroundColor DarkGray
        }
        if (-not $share.Enabled) {
            Write-Host "      [DISABLED]" -ForegroundColor DarkGray
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
            if ([string]::IsNullOrWhiteSpace($Prompt)) {
                Write-Host "  > " -ForegroundColor Cyan -NoNewline
            }
            $firstAttempt = $false
        }
        
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            $userInput = Read-CliPrompt
        } else {
            $userInput = Read-CliPrompt $Prompt
        }
        
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

function Read-CliUncPath {
    while ($true) {
        Write-Host '  > ' -NoNewline -ForegroundColor Cyan
        $entered = Read-CliPrompt
        $inputPath = ConvertTo-UncPathInput -Path $entered
        if ($inputPath.Suggestion) {
            Write-Host "  Suggested path: $($inputPath.Suggestion)" -ForegroundColor Yellow
            $accept = Read-CliPrompt '  Use suggested path? (Y/N) [Y]'
            if ($accept -eq '' -or $accept -match '^[Yy]$') { $inputPath.Path = $inputPath.Suggestion }
            else { continue }
        }
        $validation = Get-UncPathValidation -Path $inputPath.Path
        if ($validation.Valid) { return $inputPath.Path }
        Write-Host "  $($validation.Message)" -ForegroundColor Yellow
        if ($validation.Suggestion) {
            Write-Host "  Suggested path: $($validation.Suggestion)" -ForegroundColor Yellow
            $accept = Read-CliPrompt '  Use suggested path? (Y/N) [Y]'
            if ($accept -eq '' -or $accept -match '^[Yy]$') { return $validation.Suggestion }
        }
        Write-Host '  Try again, or press Esc to cancel.' -ForegroundColor DarkGray
    }
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
            Write-Host '  Share name' -ForegroundColor White
            Write-Host '  e.g., Office Files' -ForegroundColor DarkGray
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
            Write-Host '  Network path' -ForegroundColor White
            Write-Host '  e.g., \\server\share or \\192.168.1.100\share' -ForegroundColor DarkGray
            $sharePath = Read-CliUncPath
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
            
            Write-Host "  Drive letter [$($availableLetters[0])]" -ForegroundColor White
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
            $savedUsers = @(Get-RecentUsernames)
            if ($savedUsers.Count -gt 0) {
                Write-Host "  Saved usernames: $($savedUsers -join ', ')" -ForegroundColor Gray
            }
            Write-Host '  Username' -ForegroundColor White
            Write-Host '  e.g., DOMAIN\user or user' -ForegroundColor DarkGray
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
            Write-Host '  Description (optional)' -ForegroundColor White
            Write-Host "  > " -ForegroundColor Cyan -NoNewline
            $description = Read-CliPrompt
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
        $savedCredential = Get-CredentialForShare -Username $username.Trim()
        Write-Host "  Credentials : " -NoNewline -ForegroundColor DarkGray
        if ($savedCredential) { Write-Host 'Saved password available' -ForegroundColor Green }
        else { Write-Host 'Password needed before saving' -ForegroundColor Yellow }
        if ($description.Trim().Length -gt 0) {
            Write-Host "  Description : " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($description.Trim())" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor Cyan
        if ($savedCredential) {
            Write-CliMenuOption -Indent '    ' -Key '1)' -Label 'Save and connect'
            Write-CliMenuOption -Indent '    ' -Key '2)' -Label 'Save only'
        } else {
            Write-CliMenuOption -Indent '    ' -Key '1)' -Label 'Enter password, save and connect'
            Write-CliMenuOption -Indent '    ' -Key '2)' -Label 'Enter password and save only'
        }
        Write-CliMenuOption -Indent '    ' -Key '3)' -Label 'Edit Name'
        Write-CliMenuOption -Indent '    ' -Key '4)' -Label 'Edit Path'
        Write-CliMenuOption -Indent '    ' -Key '5)' -Label 'Edit Drive Letter'
        Write-CliMenuOption -Indent '    ' -Key '6)' -Label 'Edit Username'
        Write-CliMenuOption -Indent '    ' -Key '7)' -Label 'Edit Description'
        Write-CliMenuOption -Indent '    ' -Key 'C)' -Label 'Cancel'
        Write-Host ""
        Write-Host "  Choose (1-7, C) [1]: " -ForegroundColor Cyan -NoNewline
        $choice = Read-CliPrompt

        if ($choice -eq "" -or $choice -eq "1" -or $choice -eq "2") {
            $connectAfterSave = $choice -ne '2'
            $preCheckConfig = Get-CachedConfig -Force
            $conflict = $preCheckConfig.Shares | Where-Object { $_.DriveLetter -eq $driveLetter } | Select-Object -First 1
            if ($conflict) {
                Write-Host "  [!] Drive ${driveLetter}: is now assigned to '$($conflict.Name)'. Edit the drive letter." -ForegroundColor Yellow
                continue
            }
            $pathConflict = $preCheckConfig.Shares | Where-Object { $_.SharePath -eq $sharePath } | Select-Object -First 1
            if ($pathConflict) {
                Write-Host "  [!] This path is already configured as '$($pathConflict.Name)'. Edit the path." -ForegroundColor Yellow
                continue
            }
            $username = $username.Trim()
            $credentialsReady = $false
            try { $credentialsReady = Confirm-ShareCredential -Username $username -ReturnToReview }
            catch [System.OperationCanceledException] { $credentialsReady = $false }
            if (-not $credentialsReady) {
                Write-Host '  No share was saved. Your entries are still here for review.' -ForegroundColor Yellow
                continue
            }
            $credential = Get-CredentialForShare -Username $username
            if (-not $credential) {
                Write-Host '  Saved credentials could not be loaded. Your share entries are unchanged.' -ForegroundColor Yellow
                continue
            }
            break
        } elseif ($choice -eq "3") {
            $name = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT NAME ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "4") {
            $sharePath = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT PATH ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "5") {
            $driveLetter = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT DRIVE LETTER ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "6") {
            $username = ""
            Clear-Host
            Write-Host ""
            Write-Host "  ======[ EDIT USERNAME ]======" -ForegroundColor Cyan
            Write-Host ""
        } elseif ($choice -eq "7") {
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
    
    # Add the share
    $result = Add-ShareConfiguration -Name $name -SharePath $sharePath -DriveLetter $driveLetter -Username $username -Description $description
    
    if (-not $result) {
        Write-Host '  [X] Failed to save share.' -ForegroundColor Red
        return
    }

    Write-Host "  [OK] Share '$name' saved as ${driveLetter}:." -ForegroundColor Green
    if (-not $connectAfterSave) { return }

    Write-Host "  Connecting ${driveLetter}: to $sharePath..." -ForegroundColor Cyan
    $connection = Connect-NetworkShare -SharePath $sharePath -DriveLetter $driveLetter -Credential $credential -ReturnStatus -Silent
    if (-not $connection -or -not $connection.Success) {
        $reason = if ($connection -and $connection.ErrorMessage) { $connection.ErrorMessage } else { 'Check the network path and credentials.' }
        Write-Host "  [!] Share saved, but connection failed: $reason" -ForegroundColor Yellow
        return
    }
    if (-not $connection.Verified) {
        Write-Host '  [!] Mapping command succeeded, but the drive target could not be verified. Check Status before using it.' -ForegroundColor Yellow
        return
    }
    Write-Host "  [OK] Drive ${driveLetter}: connected and verified." -ForegroundColor Green
    $config = Get-CachedConfig -Force
    $savedShare = $config.Shares | Where-Object { $_.Id -eq $result.Id } | Select-Object -First 1
    if ($savedShare) {
        $savedShare.LastConnected = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Save-AllShares -Config $config | Out-Null
    }
}

function Remove-ShareCli {
    param([array]$Shares, [switch]$Direct)
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ REMOVE SHARE ]======" -ForegroundColor Cyan
    Write-Host ""
    
    $shares = if ($PSBoundParameters.ContainsKey('Shares')) { @($Shares) } else { @(Get-ShareConfiguration) }
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
    if ($Direct -and $shares.Count -eq 1) { $choice = '1' }
    else {
        Write-Host "  Select share to remove (or 0 to cancel): " -NoNewline -ForegroundColor White
        $choice = Read-CliPrompt
    }
    $num = 0
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $shares.Count) {
        $share = $shares[$num - 1]
        
        Write-Host ""
        Write-Host "  Remove '$($share.Name)'? This cannot be undone." -ForegroundColor Yellow
        Write-Host "  Confirm (Y/N): " -NoNewline
        $confirm = Read-CliPrompt
        
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
    $choice = Read-CliPrompt
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
                    $save = Read-CliPrompt
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
                        $retry = Read-CliPrompt
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
    
    $shares = @(Get-ShareConfiguration | Where-Object { $_.DriveLetter })
    
    if ($shares.Count -eq 0) {
        Write-Host "  No shares with drive letters are configured." -ForegroundColor Yellow
        return
    }
    
    Write-Host "  Configured Shares:" -ForegroundColor Gray
    Write-Host ""
    for ($i = 0; $i -lt $shares.Count; $i++) {
        $isConnected = Test-ShareConnection -DriveLetter $shares[$i].DriveLetter
        $statusText = if ($isConnected) { "connected" } else { "not detected" }
        $statusColor = if ($isConnected) { "Green" } else { "DarkGray" }
        Write-Host "  $($i + 1). " -NoNewline -ForegroundColor White
        Write-Host "$($shares[$i].Name)" -NoNewline
        Write-Host " [$($shares[$i].DriveLetter):] " -NoNewline -ForegroundColor DarkGray
        Write-Host "($statusText)" -ForegroundColor $statusColor
    }
    
    Write-Host ""
    Write-Host "  Enter number to disconnect (or 0 to cancel): " -NoNewline -ForegroundColor White
    $choice = Read-CliPrompt
    $num = 0
    if ([int]::TryParse($choice, [ref]$num) -and $num -gt 0 -and $num -le $shares.Count) {
        $share = $shares[$num - 1]
        Write-Host ""
        Write-Host "  Disconnecting '$($share.Name)'..." -ForegroundColor Yellow
        $result = Disconnect-NetworkShare -DriveLetter $share.DriveLetter -ReturnStatus
        if ($result.Success) {
            Write-Host "  [OK] Disconnected" -ForegroundColor Green
        } elseif ($result.ErrorType -eq "NotMapped") {
            Write-Host "  [ ] Not mapped" -ForegroundColor DarkGray
        } else {
            Write-Host "  [X] Failed: $($result.ErrorMessage)" -ForegroundColor Red
        }
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
    $netUseTimeout = Get-PreferenceValue -Name "NetUseTimeoutSeconds" -Default 15 -AsInteger
    if ($netUseTimeout -lt 5) { $netUseTimeout = 5 }
    if ($netUseTimeout -gt 120) { $netUseTimeout = 120 }
    $index = 0
    
    foreach ($share in $shares) {
        $index++
        $shareName = if ($share.Name) { $share.Name } else { "Unknown" }
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            Write-Host "  [ ] " -NoNewline -ForegroundColor DarkGray
            Write-Host "($index/$($shares.Count)) $shareName" -NoNewline -ForegroundColor Gray
            Write-Host " (already connected)" -ForegroundColor DarkGray
            $skipped++
            continue
        }
        
        Write-Host "  [*] " -NoNewline -ForegroundColor Cyan
        Write-Host "($index/$($shares.Count)) $shareName" -NoNewline
        Write-Host " -> $($share.DriveLetter): " -NoNewline -ForegroundColor DarkGray
        Write-Host "(timeout ${netUseTimeout}s)... " -NoNewline -ForegroundColor DarkGray
        
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
            Write-Host "  [*] Connecting $shareName... " -NoNewline -ForegroundColor Cyan
        }
        
        try {
            $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
            if ($result.Success -or (Test-ShareConnection -DriveLetter $share.DriveLetter)) {
                Write-Host "[OK]" -ForegroundColor Green
                $success++
                
                # Offer to save credentials if they weren't saved
                if (-not (Get-CredentialForShare -Username $share.Username)) {
                    Write-Host "  Save credentials for $($share.Username)? (Y/N) [Y]: " -NoNewline
                    $save = Read-CliPrompt
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
                $errorText = if ($result.ErrorMessage) { $result.ErrorMessage } else { "connection did not verify" }
                Write-Host "      $errorText" -ForegroundColor DarkGray
                $failed++
            }
        }
        catch {
            Write-Host "[X]" -ForegroundColor Red
            Write-Host "      $_" -ForegroundColor DarkGray
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
    $confirm = Read-CliPrompt
    
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
                    $save = Read-CliPrompt
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
    
    $targets = @($shares | Where-Object { $_.DriveLetter })
    
    if ($targets.Count -eq 0) {
        Write-Host "  No shares with drive letters are configured." -ForegroundColor Yellow
        return
    }
    
    Write-Host "  This will attempt to disconnect " -NoNewline -ForegroundColor Yellow
    Write-Host "$($targets.Count)" -NoNewline -ForegroundColor White
    Write-Host " configured share(s)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Are you sure? (Y/N) [N]: " -NoNewline
    $confirm = Read-CliPrompt
    
    if ($confirm -notmatch '^[Yy]$') {
        Write-Host "  Cancelled" -ForegroundColor Gray
        return
    }
    
    Write-Host ""
    $disconnected = 0
    $notMapped = 0
    $failed = 0
    foreach ($share in $targets) {
        Write-Host "  [*] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($share.Name)" -NoNewline
        Write-Host "... " -NoNewline -ForegroundColor DarkGray
        $result = Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent -ReturnStatus
        if ($result.Success) {
            Write-Host "[OK]" -ForegroundColor Green
            $disconnected++
        } elseif ($result.ErrorType -eq "NotMapped") {
            Write-Host "[ ]" -ForegroundColor DarkGray
            Write-Host "      Not mapped" -ForegroundColor DarkGray
            $notMapped++
        } else {
            Write-Host "[X]" -ForegroundColor Red
            if ($result.ErrorMessage) {
                Write-Host "      $($result.ErrorMessage)" -ForegroundColor DarkGray
            }
            $failed++
        }
    }
    
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Disconnected " -NoNewline
    Write-Host "$disconnected" -NoNewline -ForegroundColor Yellow
    Write-Host " share(s)" -ForegroundColor Gray
    if ($notMapped -gt 0) {
        Write-Host "  Not mapped " -NoNewline
        Write-Host "$notMapped" -NoNewline -ForegroundColor DarkGray
        Write-Host " share(s)" -ForegroundColor Gray
    }
    if ($failed -gt 0) {
        Write-Host "  Failed " -NoNewline
        Write-Host "$failed" -NoNewline -ForegroundColor Red
        Write-Host " share(s)" -ForegroundColor Gray
    }
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-ActionLog -Message "Disconnect All completed: $disconnected disconnected, $notMapped not mapped, $failed failed" -Level INFO -Category 'Mapping'
    
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
    $enabledCount = @($shares | Where-Object { $_.Enabled }).Count
    foreach ($share in $shares) {
        $status = Get-DetailedShareStatus -ShareId $share.Id
        
        $icon = if ($status.IsConnected) { "[*]" } else { "[ ]" }
        $iconColor = if (-not $share.Enabled) { 'DarkGray' } elseif ($status.IsConnected) { 'Green' } else { 'Yellow' }
        
        if ($status.IsConnected -and $share.Enabled) { $connectedCount++ }
        
        Write-Host "  $icon " -NoNewline -ForegroundColor $iconColor
        Write-Host "$($share.Name) " -ForegroundColor $(if ($share.Enabled) { 'White' } else { 'DarkGray' }) -NoNewline
        Write-Host "[$($share.DriveLetter):]" -ForegroundColor DarkGray
        
        $statusLine = @()
        if (-not $share.Enabled) { $statusLine += '[ ] Disabled' }
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
    Write-Host "$connectedCount/$enabledCount" -NoNewline -ForegroundColor $(if ($enabledCount -gt 0 -and $connectedCount -eq $enabledCount) { "Green" } elseif ($connectedCount -eq 0) { "Red" } else { "Yellow" })
    Write-Host " enabled shares connected" -ForegroundColor Gray
}

function Import-ExportConfigCli {
    Clear-Host
    Write-Host ""
    Write-Host "  ======[ BACKUP & RESTORE ]======" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. " -NoNewline -ForegroundColor Yellow
    Write-Host "Export Configuration" -ForegroundColor Gray -NoNewline
    Write-Host " (Create backup)" -ForegroundColor DarkGray
    Write-Host "  2. " -NoNewline -ForegroundColor Yellow
    Write-Host "Import & Replace" -ForegroundColor Gray -NoNewline
    Write-Host " (Overwrite current)" -ForegroundColor DarkGray
    Write-Host "  3. " -NoNewline -ForegroundColor Yellow
    Write-Host "Import & Merge" -ForegroundColor Gray -NoNewline
    Write-Host " (Add to current)" -ForegroundColor DarkGray
    Write-Host "  4. " -NoNewline -ForegroundColor Yellow
    Write-Host "Back to Main Menu" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Enter choice: " -NoNewline -ForegroundColor Cyan
    $choice = Read-CliPrompt
    
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
            $exportPath = Read-CliPrompt
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
            $importPath = Read-CliPrompt
            
            if (-not [string]::IsNullOrWhiteSpace($importPath)) {
                if (-not (Test-Path $importPath)) {
                    Write-Host ""
                    Write-Host "  [X] File not found: $importPath" -ForegroundColor Red
                    return
                }
                
                Write-Host ""
                Write-Host "  Type 'REPLACE' to confirm: " -NoNewline
                $confirm = Read-CliPrompt
                
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
            $importPath = Read-CliPrompt
            
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
                    if ($result.Skipped -gt 0) {
                        Write-Host "  Updated: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($result.Skipped)" -NoNewline -ForegroundColor Cyan
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
    $disconnected = 0
    $enabledCount = @($shares | Where-Object { $_.Enabled }).Count
    foreach ($share in @($shares | Where-Object { $_.Enabled })) {
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            $connected++
        } else {
            $disconnected++
        }
    }
    
    Write-Host ''
    Write-Host "  SHARE MANAGER v$version" -NoNewline -ForegroundColor Cyan
    Write-Host "   by $author" -ForegroundColor DarkGray
    Write-Host "  Status: " -NoNewline -ForegroundColor Gray
    
    if ($total -eq 0) {
        Write-Host "No shares configured" -ForegroundColor Yellow
    } elseif ($enabledCount -eq 0) {
        Write-Host "No enabled shares ($total disabled)" -ForegroundColor Yellow
    } else {
        Write-Host "$connected/$enabledCount" -NoNewline -ForegroundColor $(if ($enabledCount -gt 0 -and $connected -eq $enabledCount) { "Green" } elseif ($connected -eq 0) { "Red" } else { "Yellow" })
        Write-Host " connected (enabled shares)" -NoNewline -ForegroundColor Gray
        $disabledCount = $total - $enabledCount
        if ($disabledCount -gt 0) { Write-Host " ($disabledCount disabled)" -ForegroundColor DarkGray }
        else { Write-Host '' }
    }
    Write-Host ''
    Write-Host '  SHARES' -ForegroundColor Cyan
    Write-Host '  1' -NoNewline -ForegroundColor Yellow
    Write-Host ' Add share      ' -NoNewline -ForegroundColor Gray
    Write-Host '2' -NoNewline -ForegroundColor Yellow
    Write-Host ' Manage shares      ' -NoNewline -ForegroundColor Gray
    Write-Host '3' -NoNewline -ForegroundColor Yellow
    Write-Host ' Status' -ForegroundColor Gray

    if ($total -eq 0) {
        Write-Host '  Try adding a network share to get started!' -ForegroundColor Yellow
    } else {
        Write-Host ''
        Write-Host '  CONNECTIONS' -ForegroundColor Cyan
        if ($disconnected -gt 0) {
            Write-Host '  C' -NoNewline -ForegroundColor Yellow
            Write-Host " Connect all ($disconnected remaining)" -ForegroundColor Gray
        }
        if ($enabledCount -gt 0) {
            Write-Host '  D' -NoNewline -ForegroundColor Yellow
            Write-Host ' Disconnect all     ' -NoNewline -ForegroundColor Gray
            Write-Host 'N' -NoNewline -ForegroundColor Yellow
            Write-Host ' Reconnect all' -ForegroundColor Gray
        } else {
            Write-Host '  D' -NoNewline -ForegroundColor Yellow
            Write-Host ' Disconnect all' -ForegroundColor Gray
        }
    }

    Write-Host ''
    Write-Host '  TOOLS & SETTINGS' -ForegroundColor Cyan
    Write-Host '  P' -NoNewline -ForegroundColor Yellow
    Write-Host ' Preferences     ' -NoNewline -ForegroundColor Gray
    Write-Host 'K' -NoNewline -ForegroundColor Yellow
    Write-Host ' Credentials       ' -NoNewline -ForegroundColor Gray
    Write-Host 'B' -NoNewline -ForegroundColor Yellow
    Write-Host ' Backup/restore' -ForegroundColor Gray
    Write-Host '  L' -NoNewline -ForegroundColor Yellow
    Write-Host ' Logs            ' -NoNewline -ForegroundColor Gray
    Write-Host 'U' -NoNewline -ForegroundColor Yellow
    Write-Host ' Updates           ' -NoNewline -ForegroundColor Gray
    Write-Host 'H' -NoNewline -ForegroundColor Yellow
    Write-Host ' Help' -ForegroundColor Gray
    Write-Host '  G' -NoNewline -ForegroundColor Yellow
    Write-Host ' GUI mode        ' -NoNewline -ForegroundColor Gray
    Write-Host 'Q' -NoNewline -ForegroundColor Yellow
    Write-Host ' Quit' -ForegroundColor Gray
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
        $newSharePath = Read-CliPrompt "New share (UNC), or Enter to keep"
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
        $newDriveLetter = Read-CliPrompt "New drive letter (A-Z), or Enter"
        if ($newDriveLetter -eq "") { break }
        if ($newDriveLetter -match '^[A-Za-z]$') {
            $cfg.DriveLetter = $newDriveLetter.ToUpper()
            break
        }
        else {
            Write-Host "Enter single letter A-Z, or blank." -ForegroundColor Yellow
        }
    } while ($true)

    $newUsername = Read-CliPrompt "New username, or Enter"
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
            UncProbeTimeoutSeconds = 3
            NetUseTimeoutSeconds = 15
        }
    }
    # Backfill SyncShareNameToDriveLabel if missing (for configs created before 2.1.1)
    if (-not $config.Preferences.PSObject.Properties['SyncShareNameToDriveLabel']) {
        $config.Preferences | Add-Member -MemberType NoteProperty -Name SyncShareNameToDriveLabel -Value $true -Force
    }
    if (-not $config.Preferences.PSObject.Properties['UncProbeTimeoutSeconds']) {
        $config.Preferences | Add-Member -MemberType NoteProperty -Name UncProbeTimeoutSeconds -Value 3 -Force
    }
    if (-not $config.Preferences.PSObject.Properties['NetUseTimeoutSeconds']) {
        $config.Preferences | Add-Member -MemberType NoteProperty -Name NetUseTimeoutSeconds -Value 15 -Force
    }
    
    $prefs = $config.Preferences

    while ($true) {
        Clear-Host
        Write-Host "=== Preferences v$version ===" -ForegroundColor Cyan
        Write-Host ""
        Write-CliMenuOption -Key '1.' -Label 'Auto-unmap on drive change: ' -Value $prefs.UnmapOldMapping
        Write-CliMenuOption -Key '2.' -Label 'Preferred startup mode    : ' -Value $prefs.PreferredMode
        Write-CliMenuOption -Key '3.' -Label 'Persistent mapping        : ' -Value $prefs.PersistentMapping
        $syncLabelValue = if ($prefs.PSObject.Properties['SyncShareNameToDriveLabel']) { $prefs.SyncShareNameToDriveLabel } else { $true }
        Write-CliMenuOption -Key '4.' -Label 'Sync share name to label  : ' -Value $syncLabelValue
        $uncTimeoutValue = if ($prefs.PSObject.Properties['UncProbeTimeoutSeconds']) { $prefs.UncProbeTimeoutSeconds } else { 3 }
        $netUseTimeoutValue = if ($prefs.PSObject.Properties['NetUseTimeoutSeconds']) { $prefs.NetUseTimeoutSeconds } else { 15 }
        Write-CliMenuOption -Key '5.' -Label 'UNC probe timeout (sec)   : ' -Value $uncTimeoutValue
        Write-CliMenuOption -Key '6.' -Label 'Net use timeout (sec)     : ' -Value $netUseTimeoutValue
        Write-CliMenuOption -Key '7.' -Label 'Back'
        Write-Host ""
        $choice = Read-CliPrompt "Select (1-7)"
        switch ($choice) {
            "1" {
                do {
                    $yn = Read-CliPrompt "Auto-unmap on letter change? (Y/N) [Y]"
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
                    $m = Read-CliPrompt "Enter 1, 2, or 3"
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
                    $yn = Read-CliPrompt "Enable persistent mapping (reconnect at logon)? (Y/N) [N]"
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
                    $yn = Read-CliPrompt "Sync share name to Explorer drive label? (Y/N) [Y]"
                    if ($yn -eq "" -or $yn -match '^[YyNn]$') { break }
                    Write-Host "Enter Y or N." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.SyncShareNameToDriveLabel = ($yn -eq "" -or $yn -match '^[Yy]$')
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "5" {
                do {
                    $value = Read-CliPrompt "UNC probe timeout seconds (1-30) [3]"
                    if ($value -eq "") { $value = 3; break }
                    $parsed = 0
                    if ([int]::TryParse($value, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le 30) { $value = $parsed; break }
                    Write-Host "Enter a number between 1 and 30." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.UncProbeTimeoutSeconds = [int]$value
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "6" {
                do {
                    $value = Read-CliPrompt "Net use timeout seconds (5-120) [15]"
                    if ($value -eq "") { $value = 15; break }
                    $parsed = 0
                    if ([int]::TryParse($value, [ref]$parsed) -and $parsed -ge 5 -and $parsed -le 120) { $value = $parsed; break }
                    Write-Host "Enter a number between 5 and 120." -ForegroundColor Yellow
                } while ($true)
                $config.Preferences.NetUseTimeoutSeconds = [int]$value
                Save-AllShares -Config $config | Out-Null
                Write-Host "Updated." -ForegroundColor Green
                $prefs = $config.Preferences
            }
            "7" { return }
            default { return }
        }
    }
}

function Update-CliCredentialsMenu {
    Write-Host "=== Credentials Menu v$version ===" -ForegroundColor Cyan
    Write-CliMenuOption -Key '1.' -Label 'Add/Update Credentials'
    Write-CliMenuOption -Key '2.' -Label 'List Credentials'
    Write-CliMenuOption -Key '3.' -Label 'Remove Credential'
    Write-CliMenuOption -Key '4.' -Label 'Export Credentials (Backup)'
    Write-CliMenuOption -Key '5.' -Label 'Import Credentials (Restore)'
    Write-CliMenuOption -Key '6.' -Label 'Back'
    Write-Host ""
    $sub = Read-CliPrompt "Select (1-6)"
    switch ($sub) {
        "1" {
            # Prompt for username
            $username = Read-CliPrompt "Username"
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
            $choice = Read-CliPrompt "Select credential to remove (1-$($creds.Count))"
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
            Write-CliMenuOption -Key '1)' -Label 'Replace all credentials'
            Write-CliMenuOption -Key '2)' -Label 'Merge with existing credentials'
            $mode = Read-CliPrompt "Choose (1-2) [2]"
            $merge = ($mode -ne '1')
            
            $path = Read-CliPrompt "Enter path to backup file"
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
# Auto-generated by Share Manager v2.6.0 (multi-share, DPAPI-protected)
# Per-share retries and access verification
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
    if ($Level -ne 'DEBUG') {
        "$ts`t$prefix $Message" | Out-File -FilePath $logPath -Encoding UTF8 -Append
    }
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
        ver           = '2.6.0'
        data          = $Data
    }
    ($evt | ConvertTo-Json -Compress) | Out-File -FilePath $eventsPath -Encoding UTF8 -Append
}

function Convert-SecureStringToPlainText {
    param([System.Security.SecureString]$SecureString)

    $bstrPtr = [IntPtr]::Zero
    try {
        $bstrPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
    }
    finally {
        if ($bstrPtr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
        }
    }
}

function Invoke-AutoMapNetUseDelete {
    param([string]$Drive, [int]$TimeoutSeconds = 15)

    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($drive)
            Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public static class ShareManagerDisconnect {
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    public static extern int WNetCancelConnection2W(string name, int flags, bool force);
}
"@
            # Keep the remembered profile and refuse to close open files.
            $code = [ShareManagerDisconnect]::WNetCancelConnection2W($drive, 0, $false)
            [PSCustomObject]@{ ExitCode = $code; Output = "Disconnect returned $code." }
        } -ArgumentList $Drive
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
            return Receive-Job -Job $job -ErrorAction Stop
        }
        return [PSCustomObject]@{ ExitCode = 1460; Output = 'Disconnect timed out.' }
    } catch {
        return [PSCustomObject]@{ ExitCode = 1; Output = 'Disconnect failed.' }
    } finally {
        if ($job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-AutoMapNetUseQuery {
    param([string]$Drive, [int]$TimeoutSeconds = 15)

    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($drive)
            if ($drive) { net use $drive 2>&1 | Out-String } else { net use 2>&1 | Out-String }
        } -ArgumentList $Drive
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) { return Receive-Job -Job $job -ErrorAction Stop }
        throw 'Mapping query timed out.'
    } finally {
        if ($job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-AutoMapServerTarget {
    param([string]$SharePath)

    if ($SharePath -match '^\\\\([^\\]+)') {
        return "\\$($Matches[1])"
    }
    return $SharePath
}

function Get-AutoMapCredentialTargets {
    param([string]$SharePath)

    if ($SharePath -match '^\\\\([^\\]+)') {
        $server = $Matches[1]
        return @($server, "\\$server") | Sort-Object -Unique
    }
    return @($SharePath)
}

function Get-AutoMapServerConnections {
    param([string]$ServerTarget)

    try { $allConnections = Invoke-AutoMapNetUseQuery -Drive '' } catch { return @() }
    $escaped = [regex]::Escape($ServerTarget)
    $matches = @()
    foreach ($line in ($allConnections -split "`r?`n")) {
        if ($line -match $escaped) {
            $matches += $line.Trim()
        }
    }
    return @($matches)
}

function Set-AutoMapCredentialTarget {
    param(
        [string]$ServerTarget,
        [string]$Username,
        [string]$Password
    )

    if ([string]::IsNullOrWhiteSpace($ServerTarget) -or
        [string]::IsNullOrWhiteSpace($Username) -or
        [string]::IsNullOrEmpty($Password)) {
        return [PSCustomObject]@{
            Updated = $false
            ExitCode = 0
            Output = "Skipped credential target update"
        }
    }

    $output = & cmdkey @(('/add:' + $ServerTarget), ('/user:' + $Username), ('/pass:' + $Password)) 2>&1
    return [PSCustomObject]@{
        Updated = ($LASTEXITCODE -eq 0)
        ExitCode = $LASTEXITCODE
        Output = ($output | Out-String)
    }
}

function Get-AutoMapSmbMapping {
    param([string]$Drive, [int]$TimeoutSeconds = 15)
    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($drive)
            if (Get-Command Get-SmbMapping -ErrorAction SilentlyContinue) {
                Get-SmbMapping -LocalPath $drive -ErrorAction SilentlyContinue | Select-Object -First 1
            }
        } -ArgumentList $Drive
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) { return Receive-Job -Job $job -ErrorAction Stop }
        throw 'SMB mapping lookup timed out.'
    } finally {
        if ($job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-AutoMapNetUseMap {
    param(
        [string]$Drive,
        [string]$Share,
        [string]$Username,
        [string]$Password,
        [int]$TimeoutSeconds,
        [bool]$CredentialPrepared = $false
    )

    $job = $null
    try {
        if ($Username -and [string]::IsNullOrEmpty($Password)) {
            return [PSCustomObject]@{ Output = 'Configured credentials are unavailable; refusing to use a different Windows identity.'; ExitCode = 1326 }
        }
        $job = Start-Job -ScriptBlock {
            param($drive, $share, $username, $password, $credentialPrepared)
            $smbSaveErrorCode = $null
            $smbSaveErrorType = $null
            $smbSaveErrorMessage = $null
            $smbCommand = Get-Command New-SmbMapping -ErrorAction SilentlyContinue
            if (-not $credentialPrepared -and $password -and $smbCommand -and $smbCommand.Parameters.ContainsKey('SaveCredentials')) {
                try {
                    New-SmbMapping -LocalPath $drive -RemotePath $share -UserName $username -Password $password -Persistent $true -SaveCredentials -ErrorAction Stop | Out-Null
                    return [PSCustomObject]@{ Output = 'SMB mapping created with saved credentials.'; ExitCode = 0; Backend = 'New-SmbMapping'; CredentialsSaved = $true; SaveErrorCode = $null }
                } catch {
                    # Preserve the explicit-credential fallback when saving credentials is unsupported by policy.
                    $smbSaveErrorCode = $_.Exception.HResult
                    $smbSaveErrorType = $_.Exception.GetType().FullName
                    $smbSaveErrorMessage = ([string]$_.Exception.Message).Replace($password, '[REDACTED]') -replace '[\r\n]+', ' '
                    $win32Code = $smbSaveErrorCode -band 0xFFFF
                    if ($win32Code -in @(5, 86, 1326, 1219, 1330, 1331, 1909)) {
                        return [PSCustomObject]@{ Output = "SMB authentication or session conflict ($win32Code)."; ExitCode = $win32Code; Backend = 'New-SmbMapping'; CredentialsSaved = $false; SaveErrorCode = $smbSaveErrorCode; SaveErrorType = $smbSaveErrorType; SaveErrorMessage = $smbSaveErrorMessage }
                    }
                }
            }
            if ($password) {
                $output = net use $drive $share /USER:$username $password /PERSISTENT:YES 2>&1
            } else {
                $output = net use $drive $share /PERSISTENT:YES 2>&1
            }
            [PSCustomObject]@{
                Output = ($output | Out-String)
                ExitCode = $LASTEXITCODE
                Backend = 'net use'
                CredentialsSaved = $false
                SaveErrorCode = $smbSaveErrorCode
                SaveErrorType = $smbSaveErrorType
                SaveErrorMessage = $smbSaveErrorMessage
            }
        } -ArgumentList $Drive, $Share, $Username, $Password, $CredentialPrepared

        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if ($completed) {
            $jobResult = Receive-Job -Job $job -ErrorAction SilentlyContinue
            if ($jobResult) {
                return [PSCustomObject]@{
                    Output = $jobResult.Output
                    ExitCode = [int]$jobResult.ExitCode
                    Backend = $jobResult.Backend
                    CredentialsSaved = $jobResult.CredentialsSaved
                    SaveErrorCode = $jobResult.SaveErrorCode
                    SaveErrorType = $jobResult.SaveErrorType
                    SaveErrorMessage = $jobResult.SaveErrorMessage
                }
            }
        }

        return [PSCustomObject]@{
            Output = "net use timed out after ${TimeoutSeconds}s"
            ExitCode = 1460
        }
    }
    catch {
        return [PSCustomObject]@{
            Output = "net use failed: $_"
            ExitCode = 1
        }
    }
    finally {
        if ($job) {
            try { Stop-Job -Job $job -ErrorAction Stop | Out-Null } catch { }
            try { Remove-Job -Job $job -Force | Out-Null } catch { }
        }
    }
}

function Test-AutoMapDriveAccess {
    param([string]$Drive, [int]$TimeoutSeconds = 15)

    $job = $null
    try {
        $job = Start-Job -ScriptBlock {
            param($root)
            Test-Path -LiteralPath $root -PathType Container -ErrorAction Stop
        } -ArgumentList ($Drive.TrimEnd('\') + '\')
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
            $result = @(Receive-Job -Job $job -ErrorAction Stop)
            return ($result.Count -eq 1 -and $result[0] -eq $true)
        }
        return $false
    } catch {
        return $false
    } finally {
        if ($job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-AutoMapLocalDrive {
    param([string]$Drive)
    Get-PSDrive -Name $Drive.TrimEnd(':') -PSProvider FileSystem -ErrorAction SilentlyContinue
}

function Get-AutoMapExecutionContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return @{ elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); sessionId = (Get-Process -Id $PID).SessionId }
    } finally { $identity.Dispose() }
}

function Get-AutoMapFailureKind {
    param([int]$ExitCode, [string]$Output)
    if ($ExitCode -in @(5, 86, 1326, 1330, 1331, 1909) -or $Output -match '\b(1326|1330|1331|1909|86)\b') { return 'Authentication' }
    if ($ExitCode -eq 1219 -or $Output -match '\b1219\b') { return 'MultipleConnections' }
    if ($ExitCode -in @(85, 1202) -or $Output -match '\b(85|1202)\b') { return 'DriveInUse' }
    if ($ExitCode -eq 67 -or $Output -match '\b67\b') { return 'InvalidPath' }
    return 'NetworkOrAccess'
}

# Rotate and write a start marker
Invoke-LogFileRotation -Path $logPath -Prefix 'LogonScript'
Invoke-LogFileRotation -Path $eventsPath -Prefix 'LogonScript.events'

# Track script execution time
$scriptStartTime = Get-Date
$psVersion = $PSVersionTable.PSVersion.ToString()
$psEditionInfo = $PSVersionTable.PSEdition

Write-Log -Message "========================================" -Category 'AutoMap'
Write-Log -Message "AutoMap start (v2.6.0)" -Category 'AutoMap' -Data @{ psVersion = $psVersion; psEdition = $psEditionInfo }
Write-Log -Message "Environment: PowerShell $psVersion ($psEditionInfo)" -Level DEBUG -Category 'AutoMap'
try {
    $executionContextInfo = Get-AutoMapExecutionContext
    Write-Log -Message "AutoMap execution context: elevated=$($executionContextInfo.elevated), session=$($executionContextInfo.sessionId)" -Category 'AutoMap' -Data $executionContextInfo
    if ($executionContextInfo.elevated) {
        Write-Log -Message "AutoMap is elevated. Run it as the signed-in user without elevation so Explorer can use the mappings. No mapping changes made." -Level ERROR -Category 'AutoMap'
        exit 2
    }
} catch {
    Write-Log -Message "Could not establish the AutoMap execution context; no mapping changes made." -Level ERROR -Category 'AutoMap'
    exit 2
}

$autoMapMutex = New-Object System.Threading.Mutex($false, 'Local\ShareManager.AutoMap')
$lockHeld = $false
try {
    try { $lockHeld = $autoMapMutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $lockHeld = $true }
    if (-not $lockHeld) {
        Write-Log -Message 'Another AutoMap run is active in this session; skipping duplicate run.' -Category 'AutoMap'
        exit 0
    }

# Adapter state and Internet access do not establish reachability of a configured SMB server.
Write-Log -Message "Checking configured shares directly; mapping attempts use per-share timeouts and retries." -Category 'AutoMap'

if (!(Test-Path $sharesPath)) { 
    Write-Log "Missing shares.json at $sharesPath" -Level WARN -Category 'AutoMap'
    Write-Log -Message "AutoMap aborted (no config)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    exit 1
}

$cfg = $null
try { 
    $cfg = (Get-Content -Path $sharesPath -Raw) | ConvertFrom-Json 
} catch { 
    Write-Log "shares.json parse error: $_" -Level ERROR -Category 'AutoMap'
    Write-Log -Message "AutoMap aborted (parse error)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    exit 1
}

if (-not $cfg -or -not $cfg.PSObject.Properties['Shares']) {
    Write-Log -Message 'Configuration has no Shares collection.' -Level ERROR -Category 'AutoMap'
    exit 1
}
if (-not $cfg.Shares) {
    Write-Log "No shares in config" -Level INFO -Category 'AutoMap'
    Write-Log -Message "AutoMap complete (no shares)" -Category 'AutoMap'
    Write-Log -Message "========================================" -Category 'AutoMap'
    return 
}

$totalShares = @($cfg.Shares).Count
$enabledShares = @($cfg.Shares | Where-Object { $_.Enabled }).Count
Write-Log -Message "Found $totalShares total shares ($enabledShares enabled, $($totalShares - $enabledShares) disabled)" -Level INFO -Category 'AutoMap'

$netUseTimeoutSeconds = 15
try {
    if ($cfg.Preferences -and $cfg.Preferences.PSObject.Properties['NetUseTimeoutSeconds']) {
        $netUseTimeoutSeconds = [int]$cfg.Preferences.NetUseTimeoutSeconds
    }
} catch {
    $netUseTimeoutSeconds = 15
}
if ($netUseTimeoutSeconds -lt 5) { $netUseTimeoutSeconds = 5 }
if ($netUseTimeoutSeconds -gt 120) { $netUseTimeoutSeconds = 120 }
Write-Log -Message "Using net use timeout: ${netUseTimeoutSeconds}s" -Level INFO -Category 'AutoMap'

$serverUserMap = @{}
foreach ($s in @($cfg.Shares | Where-Object { $_.Enabled })) {
    $serverTarget = Get-AutoMapServerTarget -SharePath $s.SharePath
    if ([string]::IsNullOrWhiteSpace($serverTarget)) { continue }
    $serverKey = $serverTarget.ToLowerInvariant()
    $username = if ($s.Username) { [string]$s.Username } else { "" }
    if (-not $serverUserMap.ContainsKey($serverKey)) {
        $serverUserMap[$serverKey] = @{}
    }
    if (-not $serverUserMap[$serverKey].ContainsKey($username)) {
        $serverUserMap[$serverKey][$username] = @()
    }
    $serverUserMap[$serverKey][$username] += $s.Name
}
foreach ($serverKey in $serverUserMap.Keys) {
    $usernames = @($serverUserMap[$serverKey].Keys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($usernames.Count -gt 1) {
        Write-Log -Message "Potential Windows credential conflict: multiple usernames configured for $serverKey" -Level WARN -Category 'AutoMap' -Data @{ server = $serverKey; usernames = ($usernames -join ', ') }
    }
}

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
                        $credMap[$e.Username] = ($e.Encrypted | ConvertTo-SecureString -ErrorAction Stop)
                    } elseif ($aesKey) {
                        # Legacy AES encryption
                        $credMap[$e.Username] = ($e.Encrypted | ConvertTo-SecureString -Key $aesKey -ErrorAction Stop)
                    } else {
                        # Try DPAPI anyway
                        $credMap[$e.Username] = ($e.Encrypted | ConvertTo-SecureString -ErrorAction Stop)
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
    if ([string]$s.DriveLetter -notmatch '^[A-Za-z]$' -or [string]$s.SharePath -notmatch '^\\\\[^\\\s]+\\[^\\]+') {
        Write-Log -Message 'Invalid drive letter or UNC path in an enabled share; skipping it.' -Level ERROR -Category 'AutoMap'
        $failCount++
        continue
    }
    if (@($cfg.Shares | Where-Object { $_.Enabled -and $_.DriveLetter -eq $s.DriveLetter }).Count -ne 1) {
        Write-Log -Message 'Multiple enabled shares use the same drive letter; skipping the ambiguous mapping.' -Level ERROR -Category 'AutoMap'
        $failCount++
        continue
    }
    
    $drive = "$($s.DriveLetter):"
    $share = $s.SharePath
    $user  = $s.Username
    $name  = $s.Name
    $serverTarget = Get-AutoMapServerTarget -SharePath $share

    $plainPW = $null
    try {
    try {
        $existingMapping = Get-AutoMapSmbMapping -Drive $drive
        if ($existingMapping -and ([string]$existingMapping.RemotePath).TrimEnd('\') -ne $share.TrimEnd('\')) {
            throw 'The drive belongs to another SMB mapping.'
        }
        $existing = if ($existingMapping) { [string]$existingMapping.RemotePath } else { Invoke-AutoMapNetUseQuery -Drive $drive -TimeoutSeconds $netUseTimeoutSeconds }
        $sameTarget = $existing -match ('(?im)' + [regex]::Escape($share.TrimEnd('\')) + '\\?\s*$')
        if (-not $sameTarget -and (Get-AutoMapLocalDrive -Drive $drive)) { throw 'The drive letter is already occupied.' }
    } catch {
        Write-Log -Message "Cannot safely use drive $drive; existing resources left untouched. $($_.Exception.Message)" -Level ERROR -Category 'AutoMap'
        $failCount++
        continue
    }

    $plainPW = $null
    if ($user -and $credMap.ContainsKey($user)) {
        try {
            $plainPW = Convert-SecureStringToPlainText -SecureString $credMap[$user]
        } catch {
            Write-Log "Failed to decrypt password for $user" -Level ERROR -Category 'AutoMap'
        }
    }

    if ($user -and [string]::IsNullOrEmpty($plainPW)) {
        Write-Log -Message "Configured credential missing or unreadable for drive $drive. Re-save it in Share Manager under the Windows account that signs in. Existing mapping left untouched." -Level ERROR -Category 'AutoMap'
        $failCount++
        continue
    }

    $credentialPrepared = $false
    if ($plainPW) {
        foreach ($credentialTarget in @(Get-AutoMapCredentialTargets -SharePath $share)) {
            $cmdKeyResult = Set-AutoMapCredentialTarget -ServerTarget $credentialTarget -Username $user -Password $plainPW
            if ($cmdKeyResult.Updated) {
                if ($credentialTarget -eq $serverTarget.TrimStart('\')) { $credentialPrepared = $true }
                Write-Log -Message "Prepared Windows credential target for $credentialTarget" -Level DEBUG -Category 'AutoMap'
            } elseif ($cmdKeyResult.ExitCode -ne 0) {
                Write-Log -Message "Could not prepare Windows credential target for $credentialTarget (exit code $($cmdKeyResult.ExitCode)); continuing with explicit credentials" -Level DEBUG -Category 'AutoMap' -Data @{ server = $credentialTarget; output = $cmdKeyResult.Output }
            }
        }
        if (-not $credentialPrepared) {
            Write-Log -Message "Server credential preparation failed for $name; attempting native credential saving and explicit mapping." -Level WARN -Category 'AutoMap'
        }
    } else {
        Write-Log -Message "No stored password available for $name; attempting mapping without explicit password" -Level WARN -Category 'AutoMap'
    }

    if ($sameTarget -and (Test-AutoMapDriveAccess -Drive $drive -TimeoutSeconds $netUseTimeoutSeconds)) {
        Write-Log -Message "Drive $drive is already accessible; skipping remap." -Category 'AutoMap'
        $plainPW = $null
        $skipCount++
        continue
    }
    # Reconnect in place first. Give startup networking time between bounded attempts.
    $mapped = $false
    $resetAttempted = $false
    $maxAttempts = 3
    for ($i=1; $i -le $maxAttempts; $i++) {
        if ($i -gt 1) {
            $backoff = 30
            Write-Log -Message "Retry attempt $i/$maxAttempts after ${backoff}s delay for $name" -Level INFO -Category 'AutoMap' -Data @{ attempt = $i; backoff = $backoff }
            Start-Sleep -Seconds $backoff
        }
        
        Write-Log -Message "Mapping attempt ${i}: $drive -> $share ($name, timeout ${netUseTimeoutSeconds}s)" -Level INFO -Category 'AutoMap'
        $mapResult = Invoke-AutoMapNetUseMap -Drive $drive -Share $share -Username $user -Password $plainPW -TimeoutSeconds $netUseTimeoutSeconds -CredentialPrepared $credentialPrepared
        if ($mapResult.SaveErrorType) {
            $diagnosticLevel = if ($mapResult.ExitCode -eq 0) { 'DEBUG' } else { 'WARN' }
            Write-Log -Message "SMB mapping diagnostic for $drive - $($mapResult.SaveErrorType): $($mapResult.SaveErrorMessage)" -Level $diagnosticLevel -Category 'AutoMap'
        }
        Write-Log -Message "Mapping result for $drive - backend=$($mapResult.Backend), exit=$($mapResult.ExitCode), SMB credentials saved=$($mapResult.CredentialsSaved), save error=$($mapResult.SaveErrorCode)" -Category 'AutoMap' -Data @{ backend = $mapResult.Backend; credentialsSavedBySmb = $mapResult.CredentialsSaved; saveErrorCode = $mapResult.SaveErrorCode; exitCode = $mapResult.ExitCode }
        
        if ($mapResult.ExitCode -eq 0) {
            if (Test-AutoMapDriveAccess -Drive $drive -TimeoutSeconds $netUseTimeoutSeconds) {
                Write-Log -Message "Mapped and verified access to drive $drive" -Category 'AutoMap'
                $successCount++
                $mapped = $true
                break
            }
            Write-Log -Message "Mapping command succeeded but drive $drive is inaccessible; not counting this as success." -Level WARN -Category 'AutoMap'
            $errorType = 'Inaccessible'
        } else {
            $resultStr = $mapResult.Output | Out-String
            $errorType = Get-AutoMapFailureKind -ExitCode $mapResult.ExitCode -Output $resultStr

            if ($errorType -eq "MultipleConnections") {
                $activeServerConnections = @(Get-AutoMapServerConnections -ServerTarget $serverTarget)
                Write-Log -Message "Windows reported credential conflict for $serverTarget. Existing SMB sessions may need to be disconnected." -Level WARN -Category 'AutoMap' -Data @{ server = $serverTarget; activeConnections = ($activeServerConnections -join ' | ') }
            }
            
            Write-Log -Message "Attempt $i failed for $name`: $errorType" -Level WARN -Category 'AutoMap' -Data @{ attempt = $i; errorType = $errorType; exitCode = $mapResult.ExitCode; share = $name; netUseOutput = $resultStr }
        }
        if ($errorType -in @('Authentication', 'MultipleConnections', 'InvalidPath')) {
            Write-Log -Message "Stopping retries for drive $drive ($errorType). Check the saved credential, share permissions, or existing server sessions." -Level ERROR -Category 'AutoMap'
            break
        }
        if ($errorType -in @('DriveInUse', 'Inaccessible') -and $sameTarget -and -not $resetAttempted -and $i -lt $maxAttempts) {
            $resetAttempted = $true
            $currentMapping = Get-AutoMapSmbMapping -Drive $drive
            if (-not $currentMapping -or ([string]$currentMapping.RemotePath).TrimEnd('\') -ne $share.TrimEnd('\')) { break }
            $removed = Invoke-AutoMapNetUseDelete -Drive $drive -TimeoutSeconds $netUseTimeoutSeconds
            if ($removed.ExitCode -notin @(0, 2250)) {
                Write-Log -Message "Drive $drive could not be disconnected without forcing open files; leaving it untouched." -Level ERROR -Category 'AutoMap'
                break
            }
        }
    }
    $plainPW = $null
    if (-not $mapped) { 
        $attemptsUsed = [Math]::Min($i, $maxAttempts)
        Write-Log -Message "Failed mapping drive $drive after $attemptsUsed attempts" -Level ERROR -Category 'AutoMap' -Data @{ drive = $drive; attempts = $attemptsUsed }
        $failCount++
    }
    } catch {
        $failCount++
        Write-Log -Message "Unexpected mapping failure for drive $drive; continuing with other shares." -Level ERROR -Category 'AutoMap' -Data @{ errorType = $_.Exception.GetType().FullName; errorCode = $_.Exception.HResult }
    } finally {
        $plainPW = $null
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
if ($failCount -gt 0) { exit 1 }
} finally {
    if ($lockHeld) { $autoMapMutex.ReleaseMutex() }
    $autoMapMutex.Dispose()
}
'@
    $cmdScript = @"
@echo off
setlocal DisableDelayedExpansion
REM Auto-generated by Share Manager v$version - current-user logon launcher.
title Share Manager v$version - AutoMap
echo Share Manager v$version is reconnecting your network drives.
echo AutoMap runs in the background and may retry while the network becomes available.
echo Check Share Manager for drive status.
echo Log: "%APPDATA%\Share_Manager\LogonScript.log"
echo.
if /I not "%~1"=="HIDDEN" (
    start "" /min "%~f0" HIDDEN
    exit /b
)
set "SCRIPT=%APPDATA%\Share_Manager\Share_Manager_AutoMap.ps1"
set "LOG=%APPDATA%\Share_Manager\LogonScript.log"
set "TEMP_LOG=%TEMP%\ShareManager_AutoMap_%RANDOM%_%RANDOM%.log"
set "SHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%SCRIPT%" (
    echo AutoMap script missing. Open Share Manager to regenerate it.
    echo [ERROR][CMD] AutoMap script missing. Open Share Manager to regenerate it. >>"%LOG%"
    exit /b 1
)
echo %DATE% %TIME% [INFO][CMD] AutoMap launcher started >>"%LOG%"
"%SHELL%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT%" >"%TEMP_LOG%" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"
if exist "%TEMP_LOG%" (
    if not "%EXIT_CODE%"=="0" type "%TEMP_LOG%" >>"%LOG%"
    del /q "%TEMP_LOG%" >nul 2>&1
)
if "%EXIT_CODE%"=="0" (
    echo AutoMap finished. See the log for individual drive results.
    echo %DATE% %TIME% [INFO][CMD] AutoMap launcher completed successfully >>"%LOG%"
) else (
    echo AutoMap needs attention. Open Share Manager or check the log for details.
    echo %DATE% %TIME% [ERROR][CMD] AutoMap launcher failed with exit code %EXIT_CODE% >>"%LOG%"
)
exit /b %EXIT_CODE%
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
        UncProbeTimeoutSeconds = if ($CurrentPrefs.PSObject.Properties["UncProbeTimeoutSeconds"]) { [int]$CurrentPrefs.UncProbeTimeoutSeconds } else { 3 }
        NetUseTimeoutSeconds = if ($CurrentPrefs.PSObject.Properties["NetUseTimeoutSeconds"]) { [int]$CurrentPrefs.NetUseTimeoutSeconds } else { 15 }
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = "Preferences v$version"
    $form.Width           = 420
    $form.Height          = 520
    $form.StartPosition   = if ($IsInitial) { 'CenterScreen' } else { 'CenterParent' }
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

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

    $grpTimeouts = New-Object System.Windows.Forms.GroupBox
    $grpTimeouts.Text = "Network timeouts"
    $grpTimeouts.Top = 110
    $grpTimeouts.Left = 15
    $grpTimeouts.Width = 380
    $grpTimeouts.Height = 80
    $form.Controls.Add($grpTimeouts)

    $lblUncTimeout = New-Object System.Windows.Forms.Label
    $lblUncTimeout.Text = "UNC probe timeout (sec)"
    $lblUncTimeout.AutoSize = $true
    $lblUncTimeout.Top = 25
    $lblUncTimeout.Left = 15
    $grpTimeouts.Controls.Add($lblUncTimeout)

    $nudUncTimeout = New-Object System.Windows.Forms.NumericUpDown
    $nudUncTimeout.Minimum = 1
    $nudUncTimeout.Maximum = 30
    $nudUncTimeout.Value = $prefs.UncProbeTimeoutSeconds
    $nudUncTimeout.Top = 22
    $nudUncTimeout.Left = 240
    $nudUncTimeout.Width = 60
    $grpTimeouts.Controls.Add($nudUncTimeout)

    $lblNetUseTimeout = New-Object System.Windows.Forms.Label
    $lblNetUseTimeout.Text = "Net use timeout (sec)"
    $lblNetUseTimeout.AutoSize = $true
    $lblNetUseTimeout.Top = 50
    $lblNetUseTimeout.Left = 15
    $grpTimeouts.Controls.Add($lblNetUseTimeout)

    $nudNetUseTimeout = New-Object System.Windows.Forms.NumericUpDown
    $nudNetUseTimeout.Minimum = 5
    $nudNetUseTimeout.Maximum = 120
    $nudNetUseTimeout.Value = $prefs.NetUseTimeoutSeconds
    $nudNetUseTimeout.Top = 47
    $nudNetUseTimeout.Left = 240
    $nudNetUseTimeout.Width = 60
    $grpTimeouts.Controls.Add($nudNetUseTimeout)

    # Startup mode group
    $grpStartup = New-Object System.Windows.Forms.GroupBox
    $grpStartup.Text = "Startup mode"
    $grpStartup.Top = 200
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
    $grpTheme.Top = 300
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
    $btnSave.Top    = 420
    $btnSave.Left   = 70
    $btnSave.Add_Click({
        $prefs.UnmapOldMapping   = $chk.Checked
    $prefs.PersistentMapping = $chkPersist.Checked
    $prefs.SyncShareNameToDriveLabel = $chkSync.Checked
    $prefs.UncProbeTimeoutSeconds = [int]$nudUncTimeout.Value
    $prefs.NetUseTimeoutSeconds = [int]$nudNetUseTimeout.Value
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
    $btnCancel.Top    = 420
        $btnCancel.Left   = 200
        $btnCancel.Add_Click({ $form.Close() })
        $form.Controls.Add($btnCancel)
    }

    [void]$form.ShowDialog()
    $result = $form.Tag
    $form.Dispose()
    return $result
}

function Hide-ConsoleWindow {
    Write-Host "Share Manager v$version is opening in GUI mode." -ForegroundColor Cyan
    Write-Host "Continue in the Share Manager window." -ForegroundColor Gray

    if (-not ('ShareManagerConsoleWindow' -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ShareManagerConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll")]
    public static extern uint GetConsoleProcessList(uint[] processList, uint processCount);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
    }
    $hWnd = [ShareManagerConsoleWindow]::GetConsoleWindow()
    if ($hWnd -ne [IntPtr]::Zero) {
        $consoleProcesses = New-Object 'uint32[]' 16
        if ([ShareManagerConsoleWindow]::GetConsoleProcessList($consoleProcesses, $consoleProcesses.Length) -ne 1) {
            Write-Host 'This terminal will remain visible while the GUI is open.' -ForegroundColor Gray
            return
        }
        [void][ShareManagerConsoleWindow]::ShowWindow($hWnd, 0)
    }
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
    
    $txtUser = New-Object System.Windows.Forms.ComboBox
    $txtUser.DropDownStyle = 'DropDown'
    foreach ($savedUser in @(Get-RecentUsernames)) { [void]$txtUser.Items.Add($savedUser) }
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
    $categories = Get-ShareCategories -IncludeSuggestions
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
        
        $path = Resolve-GuiUncPathInput -Path $txtPath.Text
        if ($null -eq $path) { return }
        $txtPath.Text = $path
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
        if (-not (Confirm-ShareCredential -Username $username -Gui)) { return }
        
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
    param([string]$ShareId, [switch]$FromSetup)
    
    $share = Get-ShareConfiguration -ShareId $ShareId
    if (-not $share) {
        [System.Windows.Forms.MessageBox]::Show("Share not found", "Error")
        return
    }
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Manage Share - $($share.Name)"
    $form.Width = 500
    $form.Height = 525
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
    
    $txtUser = New-Object System.Windows.Forms.ComboBox
    $txtUser.DropDownStyle = 'DropDown'
    foreach ($savedUser in @(Get-RecentUsernames)) { [void]$txtUser.Items.Add($savedUser) }
    $txtUser.Text = $share.Username
    $txtUser.Top = $y
    $txtUser.Left = 150
    $txtUser.Width = 300
    $form.Controls.Add($txtUser)
    $y += 30
    $btnChangePassword = New-Object System.Windows.Forms.Button
    $btnChangePassword.Text = 'Change password...'
    $btnChangePassword.Left = 150
    $btnChangePassword.Top = $y
    $btnChangePassword.Size = New-Object System.Drawing.Size(170, 27)
    $btnChangePassword.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtUser.Text)) {
            [void][System.Windows.Forms.MessageBox]::Show('Enter or select a username first.', 'Credentials')
            $txtUser.Focus()
            return
        }
        if (Confirm-ShareCredential -Username $txtUser.Text.Trim() -Gui -ReplaceExisting -ShareId $ShareId) {
            [void][System.Windows.Forms.MessageBox]::Show('Credential saved. Share settings are saved separately with Save Changes.', 'Credentials')
        }
    })
    $form.Controls.Add($btnChangePassword)
    
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
    $categories = Get-ShareCategories -IncludeSuggestions
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
        $path = Resolve-GuiUncPathInput -Path $txtPath.Text
        if ($null -eq $path) { return }
        $txtPath.Text = $path
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

        $txtUser.Text = $txtUser.Text.Trim()
        if (-not (Confirm-ShareCredential -Username $txtUser.Text -Gui -KeepExisting -ShareId $ShareId)) { return }
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
    $btnDelete.Visible = -not $FromSetup
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
    $btnClose.Left = if ($FromSetup) { 150 } else { 280 }
    $btnClose.Width = 120
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)
    
    [void]$form.ShowDialog()
}

function Show-CredentialsDialog {
    param(
        [ValidateSet("Credentials", "Backup")]
        [string]$StartPage = "Credentials"
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Credential Center"
    $form.Width = 720
    $form.Height = 560
    $form.MinimumSize = New-Object System.Drawing.Size(720, 560)
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "Sizable"
    $form.MaximizeBox = $true

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.AutoPopDelay = 12000
    $toolTip.InitialDelay = 400
    $toolTip.ReshowDelay = 200
    $toolTip.ShowAlways = $true

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Credential Center"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize = $true
    $lblTitle.Left = 15
    $lblTitle.Top = 12
    $lblTitle.Anchor = 'Top,Left'
    $form.Controls.Add($lblTitle)

    $lblSubtitle = New-Object System.Windows.Forms.Label
    $lblSubtitle.Text = "Manage saved credentials and DPAPI backups from one place."
    $lblSubtitle.AutoSize = $true
    $lblSubtitle.Left = 15
    $lblSubtitle.Top = 34
    $lblSubtitle.ForeColor = [System.Drawing.Color]::DimGray
    $lblSubtitle.Anchor = 'Top,Left'
    $form.Controls.Add($lblSubtitle)

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Left = 15
    $tabs.Top = 58
    $tabs.Width = 675
    $tabs.Height = 425
    $tabs.Anchor = 'Top,Left,Right,Bottom'
    $form.Controls.Add($tabs)

    # Tab 1: Stored credentials
    $tabCredentials = New-Object System.Windows.Forms.TabPage
    $tabCredentials.Text = "Stored Credentials"
    $tabs.TabPages.Add($tabCredentials) | Out-Null

    $lblSearch = New-Object System.Windows.Forms.Label
    $lblSearch.Text = "Search:"
    $lblSearch.Top = 16
    $lblSearch.Left = 15
    $lblSearch.AutoSize = $true
    $tabCredentials.Controls.Add($lblSearch)

    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Top = 12
    $txtSearch.Left = 80
    $txtSearch.Width = 570
    $txtSearch.Anchor = 'Top,Left,Right'
    $tabCredentials.Controls.Add($txtSearch)

    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = 'Details'
    $listView.FullRowSelect = $true
    $listView.MultiSelect = $false
    $listView.HideSelection = $false
    $listView.Top = 45
    $listView.Left = 15
    $listView.Width = 635
    $listView.Height = 255
    $listView.Anchor = 'Top,Left,Right,Bottom'
    [void]$listView.Columns.Add("Username", 280)
    [void]$listView.Columns.Add("Encryption", 140)
    [void]$listView.Columns.Add("Shares Using", 110)
    $tabCredentials.Controls.Add($listView)

    $lblCredHint = New-Object System.Windows.Forms.Label
    $lblCredHint.Text = "Tip: Select a credential to inspect exactly which shares use it."
    $lblCredHint.Top = 308
    $lblCredHint.Left = 15
    $lblCredHint.Width = 635
    $lblCredHint.Height = 18
    $lblCredHint.ForeColor = [System.Drawing.Color]::DimGray
    $lblCredHint.Anchor = 'Left,Right,Bottom'
    $tabCredentials.Controls.Add($lblCredHint)

    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Text = "Add"
    $btnAdd.Top = 332
    $btnAdd.Left = 15
    $btnAdd.Width = 95
    $btnAdd.Height = 32
    $btnAdd.Anchor = 'Left,Bottom'
    $tabCredentials.Controls.Add($btnAdd)

    $btnUpdate = New-Object System.Windows.Forms.Button
    $btnUpdate.Text = "Update"
    $btnUpdate.Top = 332
    $btnUpdate.Left = 115
    $btnUpdate.Width = 95
    $btnUpdate.Height = 32
    $btnUpdate.Anchor = 'Left,Bottom'
    $btnUpdate.Enabled = $false
    $tabCredentials.Controls.Add($btnUpdate)

    $btnUsage = New-Object System.Windows.Forms.Button
    $btnUsage.Text = "Usage"
    $btnUsage.Top = 332
    $btnUsage.Left = 215
    $btnUsage.Width = 95
    $btnUsage.Height = 32
    $btnUsage.Anchor = 'Left,Bottom'
    $btnUsage.Enabled = $false
    $tabCredentials.Controls.Add($btnUsage)

    $btnRemove = New-Object System.Windows.Forms.Button
    $btnRemove.Text = "Remove"
    $btnRemove.Top = 332
    $btnRemove.Left = 315
    $btnRemove.Width = 95
    $btnRemove.Height = 32
    $btnRemove.Anchor = 'Left,Bottom'
    $btnRemove.Enabled = $false
    $tabCredentials.Controls.Add($btnRemove)

    $btnRemoveUnused = New-Object System.Windows.Forms.Button
    $btnRemoveUnused.Text = "Unused"
    $btnRemoveUnused.Top = 332
    $btnRemoveUnused.Left = 415
    $btnRemoveUnused.Width = 110
    $btnRemoveUnused.Height = 32
    $btnRemoveUnused.Anchor = 'Left,Bottom'
    $tabCredentials.Controls.Add($btnRemoveUnused)

    $btnRefreshCreds = New-Object System.Windows.Forms.Button
    $btnRefreshCreds.Text = "Refresh"
    $btnRefreshCreds.Top = 332
    $btnRefreshCreds.Left = 530
    $btnRefreshCreds.Width = 120
    $btnRefreshCreds.Height = 32
    $btnRefreshCreds.Anchor = 'Right,Bottom'
    $tabCredentials.Controls.Add($btnRefreshCreds)

    # Tab 2: Backup and restore for credentials only
    $tabBackup = New-Object System.Windows.Forms.TabPage
    $tabBackup.Text = "Backup && Restore"
    $tabs.TabPages.Add($tabBackup) | Out-Null

    $lblBackupInfo = New-Object System.Windows.Forms.Label
    $lblBackupInfo.Text = "Credential backups are encrypted with DPAPI and can only be restored by this Windows user on this machine."
    $lblBackupInfo.Top = 15
    $lblBackupInfo.Left = 15
    $lblBackupInfo.Width = 635
    $lblBackupInfo.Height = 35
    $lblBackupInfo.Anchor = 'Top,Left,Right'
    $tabBackup.Controls.Add($lblBackupInfo)

    $grpExport = New-Object System.Windows.Forms.GroupBox
    $grpExport.Text = "Export"
    $grpExport.Top = 58
    $grpExport.Left = 15
    $grpExport.Width = 635
    $grpExport.Height = 95
    $grpExport.Anchor = 'Top,Left,Right'
    $tabBackup.Controls.Add($grpExport)

    $btnExportCreds = New-Object System.Windows.Forms.Button
    $btnExportCreds.Text = "Export Credentials Backup..."
    $btnExportCreds.Top = 36
    $btnExportCreds.Left = 15
    $btnExportCreds.Width = 230
    $btnExportCreds.Height = 35
    $grpExport.Controls.Add($btnExportCreds)

    $lblExportInfo = New-Object System.Windows.Forms.Label
    $lblExportInfo.Text = "Create a backup file of your encrypted credential store."
    $lblExportInfo.Top = 43
    $lblExportInfo.Left = 260
    $lblExportInfo.Width = 360
    $lblExportInfo.Height = 18
    $lblExportInfo.ForeColor = [System.Drawing.Color]::DimGray
    $grpExport.Controls.Add($lblExportInfo)

    $grpImport = New-Object System.Windows.Forms.GroupBox
    $grpImport.Text = "Import"
    $grpImport.Top = 163
    $grpImport.Left = 15
    $grpImport.Width = 635
    $grpImport.Height = 145
    $grpImport.Anchor = 'Top,Left,Right'
    $tabBackup.Controls.Add($grpImport)

    $btnImportMerge = New-Object System.Windows.Forms.Button
    $btnImportMerge.Text = "Import and Merge..."
    $btnImportMerge.Top = 30
    $btnImportMerge.Left = 15
    $btnImportMerge.Width = 230
    $btnImportMerge.Height = 32
    $grpImport.Controls.Add($btnImportMerge)

    $btnImportReplace = New-Object System.Windows.Forms.Button
    $btnImportReplace.Text = "Import and Replace..."
    $btnImportReplace.Top = 70
    $btnImportReplace.Left = 15
    $btnImportReplace.Width = 230
    $btnImportReplace.Height = 32
    $grpImport.Controls.Add($btnImportReplace)

    $lblImportInfo = New-Object System.Windows.Forms.Label
    $lblImportInfo.Text = "Merge keeps existing entries and adds new usernames. Replace overwrites the current credential store."
    $lblImportInfo.Top = 35
    $lblImportInfo.Left = 260
    $lblImportInfo.Width = 360
    $lblImportInfo.Height = 60
    $lblImportInfo.ForeColor = [System.Drawing.Color]::DimGray
    $grpImport.Controls.Add($lblImportInfo)

    $btnOpenStore = New-Object System.Windows.Forms.Button
    $btnOpenStore.Text = "Open Data Folder"
    $btnOpenStore.Top = 320
    $btnOpenStore.Left = 15
    $btnOpenStore.Width = 160
    $btnOpenStore.Height = 32
    $btnOpenStore.Anchor = 'Left,Bottom'
    $tabBackup.Controls.Add($btnOpenStore)

    $lblSummary = New-Object System.Windows.Forms.Label
    $lblSummary.Text = "Ready"
    $lblSummary.Left = 15
    $lblSummary.Top = 492
    $lblSummary.Width = 560
    $lblSummary.Height = 22
    $lblSummary.Anchor = 'Left,Right,Bottom'
    $lblSummary.AutoEllipsis = $true
    $form.Controls.Add($lblSummary)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Top = 488
    $btnClose.Left = 590
    $btnClose.Width = 100
    $btnClose.Height = 30
    $btnClose.Anchor = 'Right,Bottom'
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)
    $form.CancelButton = $btnClose

    $toolTip.SetToolTip($btnAdd, "Add a new credential entry.")
    $toolTip.SetToolTip($btnUpdate, "Update the password for the selected username.")
    $toolTip.SetToolTip($btnUsage, "Inspect every configured share that uses the selected username.")
    $toolTip.SetToolTip($btnRemove, "Remove the selected credential.")
    $toolTip.SetToolTip($btnRemoveUnused, "Removes credentials that are not referenced by any configured share.")
    $toolTip.SetToolTip($btnImportReplace, "Use carefully. This replaces the entire credential store.")
    $toolTip.SetToolTip($btnOpenStore, "Opens the Share Manager data folder.")

    Add-CtrlASupport -TextBox $txtSearch

    function Get-CredentialUsageMap {
        $usage = @{}
        $shares = @(Get-ShareConfiguration)
        foreach ($share in $shares) {
            if (-not $share) { continue }
            $username = if ($share.PSObject.Properties['Username']) { [string]$share.Username } else { "" }
            if ([string]::IsNullOrWhiteSpace($username)) { continue }
            $usernameKey = $username.ToLowerInvariant()
            if (-not $usage.ContainsKey($usernameKey)) { $usage[$usernameKey] = 0 }
            $usage[$usernameKey] = [int]$usage[$usernameKey] + 1
        }
        return $usage
    }

    function Get-SharesForCredential {
        param([string]$Username)

        if ([string]::IsNullOrWhiteSpace($Username)) {
            return @()
        }

        return @(
            Get-ShareConfiguration |
            Where-Object { $_.Username -and $_.Username -ieq $Username } |
            Sort-Object Name
        )
    }

    function Update-CredentialActionState {
        $hasSelection = $listView.SelectedItems.Count -gt 0
        $btnUpdate.Enabled = $hasSelection
        $btnUsage.Enabled = $hasSelection
        $btnRemove.Enabled = $hasSelection
    }

    function Update-CredentialSelectionSummary {
        if ($listView.SelectedItems.Count -eq 0) {
            $lblCredHint.Text = "Tip: Select a credential to inspect exactly which shares use it."
            return
        }

        $selectedUsername = [string]$listView.SelectedItems[0].Tag
        if ([string]::IsNullOrWhiteSpace($selectedUsername)) {
            $lblCredHint.Text = "Tip: Select a credential to inspect exactly which shares use it."
            return
        }

        $sharesUsing = @(Get-SharesForCredential -Username $selectedUsername)
        if ($sharesUsing.Count -eq 0) {
            $lblCredHint.Text = "Selected '$selectedUsername' is not used by any configured share."
            return
        }

        $names = @($sharesUsing | ForEach-Object { if ($_.Name) { $_.Name } else { "(unnamed share)" } })
        $previewCount = [Math]::Min($names.Count, 3)
        $previewNames = @($names | Select-Object -First $previewCount)
        $summary = "Used by $($sharesUsing.Count) share(s): " + ($previewNames -join ", ")
        if ($names.Count -gt $previewCount) {
            $summary += ", ..."
        }
        $lblCredHint.Text = $summary
    }

    function Update-CredentialList {
        $listView.BeginUpdate()
        $listView.Items.Clear()

        $store = Import-CredentialStore
        $entries = @()
        if ($store -and $store.Entries) {
            $entries = @($store.Entries)
        }

        $usageMap = Get-CredentialUsageMap
        $searchText = $txtSearch.Text.Trim()

        if (-not [string]::IsNullOrWhiteSpace($searchText)) {
            $entries = @($entries | Where-Object {
                $_.Username -and $_.Username -like "*$searchText*"
            })
        }

        $entries = @($entries | Sort-Object Username)

        foreach ($entry in $entries) {
            $username = [string]$entry.Username
            if ([string]::IsNullOrWhiteSpace($username)) { continue }

            $encryptionType = if ($entry.PSObject.Properties['EncryptionType'] -and $entry.EncryptionType) {
                [string]$entry.EncryptionType
            } else {
                "DPAPI"
            }

            $shareCount = 0
            $usernameKey = $username.ToLowerInvariant()
            if ($usageMap.ContainsKey($usernameKey)) {
                $shareCount = [int]$usageMap[$usernameKey]
            }

            $item = New-Object System.Windows.Forms.ListViewItem($username)
            [void]$item.SubItems.Add($encryptionType)
            [void]$item.SubItems.Add($shareCount.ToString())
            $item.Tag = $username

            if ($shareCount -eq 0) {
                $item.ForeColor = [System.Drawing.Color]::DimGray
            }

            [void]$listView.Items.Add($item)
        }

        $listView.EndUpdate()

        $totalStored = if ($store -and $store.Entries) {
            @($store.Entries | Where-Object { $_.Username -and $_.Username.Trim().Length -gt 0 }).Count
        } else {
            0
        }
        $filtered = $listView.Items.Count
        $assignedUsernames = @($usageMap.Keys).Count
        $lblSummary.Text = "Showing $filtered of $totalStored credentials | Usernames referenced by shares: $assignedUsernames"

        Update-CredentialActionState
        Update-CredentialSelectionSummary
    }

    function Show-CredentialUsageDialog {
        param([string]$Username)

        if ([string]::IsNullOrWhiteSpace($Username)) { return }

        $sharesUsing = @(Get-SharesForCredential -Username $Username)

        $usageForm = New-Object System.Windows.Forms.Form
        $usageForm.Text = "Credential Usage - $Username"
        $usageForm.Width = 700
        $usageForm.Height = 420
        $usageForm.StartPosition = "CenterParent"
        $usageForm.FormBorderStyle = "Sizable"
        $usageForm.MinimumSize = New-Object System.Drawing.Size(700, 420)

        $lblUsageInfo = New-Object System.Windows.Forms.Label
        $lblUsageInfo.Left = 12
        $lblUsageInfo.Top = 12
        $lblUsageInfo.Width = 660
        $lblUsageInfo.Height = 18
        $lblUsageInfo.Anchor = 'Top,Left,Right'
        $lblUsageInfo.Text = "Username '$Username' is referenced by $($sharesUsing.Count) configured share(s)."
        $usageForm.Controls.Add($lblUsageInfo)

        $usageList = New-Object System.Windows.Forms.ListView
        $usageList.View = 'Details'
        $usageList.FullRowSelect = $true
        $usageList.GridLines = $true
        $usageList.Top = 38
        $usageList.Left = 12
        $usageList.Width = 660
        $usageList.Height = 300
        $usageList.Anchor = 'Top,Left,Right,Bottom'
        [void]$usageList.Columns.Add("Share Name", 170)
        [void]$usageList.Columns.Add("Drive", 70)
        [void]$usageList.Columns.Add("Path", 310)
        [void]$usageList.Columns.Add("Enabled", 80)

        foreach ($share in $sharesUsing) {
            $shareName = if ($share.Name) { [string]$share.Name } else { "(unnamed share)" }
            $drive = if ($share.DriveLetter) { "$($share.DriveLetter):" } else { "-" }
            $path = if ($share.SharePath) { [string]$share.SharePath } else { "-" }
            $enabled = if ($share.Enabled) { "Yes" } else { "No" }

            $row = New-Object System.Windows.Forms.ListViewItem($shareName)
            [void]$row.SubItems.Add($drive)
            [void]$row.SubItems.Add($path)
            [void]$row.SubItems.Add($enabled)
            [void]$usageList.Items.Add($row)
        }

        $usageForm.Controls.Add($usageList)

        $btnUsageClose = New-Object System.Windows.Forms.Button
        $btnUsageClose.Text = "Close"
        $btnUsageClose.Top = 348
        $btnUsageClose.Left = 572
        $btnUsageClose.Width = 100
        $btnUsageClose.Height = 30
        $btnUsageClose.Anchor = 'Bottom,Right'
        $btnUsageClose.Add_Click({ $usageForm.Close() })
        $usageForm.Controls.Add($btnUsageClose)
        $usageForm.CancelButton = $btnUsageClose

        [void]$usageForm.ShowDialog($form)
    }

    function Invoke-CredentialCapture {
        param([string]$DefaultUsername = "")

        $username = Show-InputBox -Prompt "Enter username:" -Title "Credential Center" -DefaultValue $DefaultUsername
        if ([string]::IsNullOrWhiteSpace($username)) { return }

        $cred = Get-Credential -Message "Enter password for $username" -UserName $username
        if (-not $cred) { return }

        Save-Credential -Credential $cred
        Update-CredentialList
        [System.Windows.Forms.MessageBox]::Show(
            "Credential saved for '$username'.",
            "Credential Center",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }

    function Invoke-CredentialImport {
        param([bool]$MergeMode)

        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = "Select Credentials Backup File"
        $ofd.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
        $ofd.InitialDirectory = $baseFolder
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

        if (-not $MergeMode) {
            $replaceResult = [System.Windows.Forms.MessageBox]::Show(
                "Replace all stored credentials with this file?`n`nThis action cannot be undone.",
                "Confirm Replace",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($replaceResult -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }

        Import-Credentials -ImportPath $ofd.FileName -Merge:$MergeMode
        Update-CredentialList
    }

    # List context menu for quick actions
    $listMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miListAdd = New-Object System.Windows.Forms.ToolStripMenuItem
    $miListAdd.Text = "Add Credential..."
    $miListAdd.Add_Click({ Invoke-CredentialCapture })
    $listMenu.Items.Add($miListAdd) | Out-Null

    $miListUpdate = New-Object System.Windows.Forms.ToolStripMenuItem
    $miListUpdate.Text = "Update Selected..."
    $miListUpdate.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $username = [string]$listView.SelectedItems[0].Tag
        if ([string]::IsNullOrWhiteSpace($username)) { return }
        Invoke-CredentialCapture -DefaultUsername $username
    })
    $listMenu.Items.Add($miListUpdate) | Out-Null

    $miListUsage = New-Object System.Windows.Forms.ToolStripMenuItem
    $miListUsage.Text = "Inspect Usage..."
    $miListUsage.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $username = [string]$listView.SelectedItems[0].Tag
        if ([string]::IsNullOrWhiteSpace($username)) { return }
        Show-CredentialUsageDialog -Username $username
    })
    $listMenu.Items.Add($miListUsage) | Out-Null

    $miListRemove = New-Object System.Windows.Forms.ToolStripMenuItem
    $miListRemove.Text = "Remove Selected"
    $miListRemove.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) { return }
        $btnRemove.PerformClick()
    })
    $listMenu.Items.Add($miListRemove) | Out-Null

    $listView.ContextMenuStrip = $listMenu

    $btnAdd.Add_Click({ Invoke-CredentialCapture })

    $btnUsage.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Select a credential first.",
                "No Selection",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        $username = [string]$listView.SelectedItems[0].Tag
        if ([string]::IsNullOrWhiteSpace($username)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to resolve selected username.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        Show-CredentialUsageDialog -Username $username
    })

    $btnUpdate.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Select a credential first.",
                "No Selection",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        $username = [string]$listView.SelectedItems[0].Tag
        if ([string]::IsNullOrWhiteSpace($username)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to resolve selected username.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        Invoke-CredentialCapture -DefaultUsername $username
    })

    $btnRemove.Add_Click({
        if ($listView.SelectedItems.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Select a credential first.",
                "No Selection",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        $item = $listView.SelectedItems[0]
        $username = [string]$item.Tag
        if ([string]::IsNullOrWhiteSpace($username)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to resolve selected username.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        $sharesUsing = 0
        if ($item.SubItems.Count -ge 3) {
            [void][int]::TryParse($item.SubItems[2].Text, [ref]$sharesUsing)
        }

        $usageNote = ""
        if ($sharesUsing -gt 0) {
            $usageNote = "`n`nThis username is still referenced by $sharesUsing configured share(s)."
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Remove credential for '$username'?$usageNote",
            "Confirm Remove",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            [void](Remove-Credential -Username $username)
            Update-CredentialList
            [System.Windows.Forms.MessageBox]::Show(
                "Credential removed for '$username'.",
                "Credential Center",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })

    $btnRemoveUnused.Add_Click({
        $store = Import-CredentialStore
        $entries = @()
        if ($store -and $store.Entries) {
            $entries = @($store.Entries)
        }

        if ($entries.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "No credentials are currently stored.",
                "Credential Center",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }

        $usageMap = Get-CredentialUsageMap
        $unusedUsernames = @(
            $entries |
            Where-Object {
                $candidate = if ($_.PSObject.Properties['Username']) { [string]$_.Username } else { "" }
                $candidate -and -not $usageMap.ContainsKey($candidate.ToLowerInvariant())
            } |
            Select-Object -ExpandProperty Username -Unique
        )

        if ($unusedUsernames.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "No unused credentials found.",
                "Credential Center",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Remove $($unusedUsernames.Count) unused credential(s)?`n`nOnly credentials not referenced by any configured share will be removed.",
            "Remove Unused Credentials",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        foreach ($unused in $unusedUsernames) {
            if (-not [string]::IsNullOrWhiteSpace($unused)) {
                [void](Remove-Credential -Username $unused)
            }
        }

        Update-CredentialList
        [System.Windows.Forms.MessageBox]::Show(
            "Removed $($unusedUsernames.Count) unused credential(s).",
            "Credential Center",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    })

    $btnRefreshCreds.Add_Click({ Update-CredentialList })
    $txtSearch.Add_TextChanged({ Update-CredentialList })
    $listView.Add_SelectedIndexChanged({
        Update-CredentialActionState
        Update-CredentialSelectionSummary
    })
    $listView.Add_DoubleClick({
        if ($listView.SelectedItems.Count -gt 0) {
            $btnUpdate.PerformClick()
        }
    })

    $btnExportCreds.Add_Click({ Export-Credentials })
    $btnImportMerge.Add_Click({ Invoke-CredentialImport -MergeMode $true })
    $btnImportReplace.Add_Click({ Invoke-CredentialImport -MergeMode $false })
    $btnOpenStore.Add_Click({
        try {
            if (-not (Test-Path $baseFolder)) {
                New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
            }
            Invoke-Item -Path $baseFolder
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to open folder:`n$_",
                "Credential Center",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    })

    if ($StartPage -eq 'Backup') {
        $tabs.SelectedTab = $tabBackup
    } else {
        $tabs.SelectedTab = $tabCredentials
    }

    Update-CredentialList
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
            UncProbeTimeoutSeconds = 3
            NetUseTimeoutSeconds = 15
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

    Set-GuiVisualStyle -Theme $cfgTheme

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

    # Top menu bar for professional navigation.
    $mainMenu = New-Object System.Windows.Forms.MenuStrip
    $mainMenu.RenderMode = [System.Windows.Forms.ToolStripRenderMode]::System
    $mainMenu.Dock = [System.Windows.Forms.DockStyle]::Top
    $form.MainMenuStrip = $mainMenu
    $form.Controls.Add($mainMenu)

    # Keep content below the menu strip.
    $headerTop = 35
    $hintTop = 65
    $listTop = 90
    $listHeight = 330

    # Title Label
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = "Network Shares"
    # Always ensure the title pops
    $lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI",12,[System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize = $true
    $lblTitle.Top      = $headerTop
    $lblTitle.Left     = 15
    $lblTitle.Anchor   = 'Top,Left'
    $form.Controls.Add($lblTitle)
    
    # Search/Filter Box
    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Width = 200
    $txtSearch.Top = $headerTop
    $txtSearch.Left = 370
    $txtSearch.Text = "Search shares..."
    $txtSearch.ForeColor = [System.Drawing.Color]::Gray
    $txtSearch.Anchor = 'Top,Right'
    
    # Category Filter
    $cmbCategory = New-Object System.Windows.Forms.ComboBox
    $cmbCategory.Width = 120
    $cmbCategory.Top = $headerTop
    $cmbCategory.Left = 240
    $cmbCategory.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $cmbCategory.Anchor = 'Top,Right'
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
    $chkFavoritesOnly.Top = $headerTop
    $chkFavoritesOnly.Left = 580
    $chkFavoritesOnly.Anchor = 'Top,Right'
    $form.Controls.Add($chkFavoritesOnly)
    
    $form.Controls.Add($txtSearch)

    # Hint Label
    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text     = "Double-click to connect/disconnect | Right-click for more options"
    $lblHint.Font     = New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Italic)
    $lblHint.ForeColor = [System.Drawing.Color]::Gray
    $lblHint.AutoSize = $true
    $lblHint.AutoEllipsis = $true
    $lblHint.Top      = $hintTop
    $lblHint.Left     = 15
    $lblHint.Anchor   = 'Top,Left,Right'
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
    $listView.Top = $listTop
    $listView.Left = 15
    $listView.Width = 660
    $listView.Height = $listHeight
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
    $form.Add_Resize({
        Set-ListViewColumns
        Update-MainLayout
    })

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
        if (-not $share) {
            Show-GuiStatusMessage -Message "Unable to resolve selected share." -DurationMs 3000
            return
        }

        $shareName = if ($share.Name) { $share.Name } else { "(unnamed share)" }
        $isShareEnabled = if ($share.PSObject.Properties['Enabled']) { [bool]$share.Enabled } else { $true }

        if (-not $isShareEnabled) {
            Show-GuiStatusMessage -Message "Share is disabled: $shareName" -DurationMs 3200
            return
        }

        Show-GuiStatusMessage -Message "Checking connection state for: $shareName" -DurationMs 0
        [System.Windows.Forms.Application]::DoEvents()

        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            Show-GuiStatusMessage -Message "Already connected: $shareName" -DurationMs 2600
            return
        }
        
        Show-GuiStatusMessage -Message "Looking up credentials for: $shareName" -DurationMs 0
        [System.Windows.Forms.Application]::DoEvents()
        $cred = Get-CredentialForShare -Username $share.Username
        if (-not $cred) {
            Show-GuiStatusMessage -Message "Credentials needed for: $shareName" -DurationMs 0
            [System.Windows.Forms.Application]::DoEvents()
            # Prompt for credentials
            $result = [System.Windows.Forms.MessageBox]::Show(
                "No saved credentials found for $($share.Username).`n`nWould you like to enter credentials now?",
                "Share Manager v$version",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                Show-GuiStatusMessage -Message "Connect cancelled for: $shareName" -DurationMs 2600
                return
            }
            
            # Show credential form
            $newCred = Show-CredentialForm -Username $share.Username
            if (-not $newCred) {
                Show-GuiStatusMessage -Message "No credentials entered for: $shareName" -DurationMs 3000
                return
            }
            $cred = $newCred
        }
        
        $netUseTimeout = Get-PreferenceValue -Name "NetUseTimeoutSeconds" -Default 15 -AsInteger
        if ($netUseTimeout -lt 5) { $netUseTimeout = 5 }
        if ($netUseTimeout -gt 120) { $netUseTimeout = 120 }
        Show-GuiStatusMessage -Message "Mapping $shareName to $($share.DriveLetter): (timeout ${netUseTimeout}s)..." -DurationMs 0
        [System.Windows.Forms.Application]::DoEvents()
        $result = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
        if (-not $result.Success) {
            [System.Windows.Forms.MessageBox]::Show(
                "Connection failed: $($result.ErrorMessage)",
                "Connection Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            Show-GuiStatusMessage -Message "Connection failed: $shareName" -DurationMs 4200
        } else {
            Show-GuiStatusMessage -Message "Connected: $shareName" -DurationMs 3000
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
        if (-not $share) {
            Show-GuiStatusMessage -Message "Unable to resolve selected share." -DurationMs 3000
            return
        }

        $shareName = if ($share.Name) { $share.Name } else { "(unnamed share)" }
        $isShareEnabled = if ($share.PSObject.Properties['Enabled']) { [bool]$share.Enabled } else { $true }

        if (-not $isShareEnabled) {
            Show-GuiStatusMessage -Message "Share is disabled: $shareName" -DurationMs 3200
            return
        }
        
        Show-GuiStatusMessage -Message "Disconnecting $shareName from $($share.DriveLetter):..." -DurationMs 0
        [System.Windows.Forms.Application]::DoEvents()
        $disconnectResult = Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent -ReturnStatus
        if ($disconnectResult.Success) {
            Show-GuiStatusMessage -Message "Disconnected: $shareName" -DurationMs 2800
        } elseif ($disconnectResult.ErrorType -eq "NotMapped") {
            Show-GuiStatusMessage -Message "Not connected: $shareName" -DurationMs 2600
        } else {
            $errorText = if ($disconnectResult.ErrorMessage) { $disconnectResult.ErrorMessage } else { "disconnect failed" }
            Show-GuiStatusMessage -Message "Disconnect failed: $shareName" -DurationMs 4200
            [System.Windows.Forms.MessageBox]::Show(
                "Disconnect failed: $errorText",
                "Disconnect Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
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

        if (-not $share) {
            Show-GuiStatusMessage -Message "Unable to resolve selected share." -DurationMs 3000
            return
        }

        $shareName = if ($share.Name) { $share.Name } else { "(unnamed share)" }
        $isShareEnabled = if ($share.PSObject.Properties['Enabled']) { [bool]$share.Enabled } else { $true }
        if (-not $isShareEnabled) {
            Show-GuiStatusMessage -Message "Share is disabled: $shareName" -DurationMs 3200
            return
        }

        # Route through existing handlers so double-click behavior stays in sync.
        if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
            $menuDisconnect.PerformClick()
        } else {
            $menuConnect.PerformClick()
        }
    })

    # Toolbar panel (below ListView)
    # ListView: Top=90, Height=330, so bottom is at 420
    $toolbarY = 430
    
    # Group: Share Actions
    $grpShares = New-Object System.Windows.Forms.GroupBox
    $grpShares.Text = "Share Actions"
    $grpShares.Top = $toolbarY
    $grpShares.Left = 15
    $grpShares.Width = 435
    $grpShares.Height = 75
    $grpShares.Anchor = 'Left,Right,Bottom'
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
        $shares = @(Get-ShareConfiguration | Where-Object { $_.Enabled })
        $success = 0
        $failed = 0
        $skipped = 0
        $connectedShares = @()
        $failedShares = @()
        $skippedShares = @()
        
        $shareCount = if ($shares) { $shares.Count } else { 0 }
        Write-ActionLog -Message "Connect All: Starting bulk connection ($shareCount enabled shares)" -Category 'Connection'

        $netUseTimeout = Get-PreferenceValue -Name "NetUseTimeoutSeconds" -Default 15 -AsInteger
        if ($netUseTimeout -lt 5) { $netUseTimeout = 5 }
        if ($netUseTimeout -gt 120) { $netUseTimeout = 120 }

        Set-GuiBulkOperationState -InProgress $true -Message "Connect All: preparing $shareCount share(s)..."
        try {
            $index = 0
            foreach ($share in $shares) {
                $index++
                $shareName = if ($share.Name) { $share.Name } else { "Unknown" }
                
                Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): checking $shareName..." -DurationMs 0
                [System.Windows.Forms.Application]::DoEvents()
                
                if (Test-ShareConnection -DriveLetter $share.DriveLetter) { 
                    Write-ActionLog -Message "Connect All: Skipping $shareName (already connected)" -Level DEBUG -Category 'Connection'
                    $skipped++
                    $skippedShares += $shareName
                    Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): already connected: $shareName" -DurationMs 0
                    [System.Windows.Forms.Application]::DoEvents()
                    continue 
                }
                $cred = Get-CredentialForShare -Username $share.Username
                if (-not $cred) {
                    Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): credentials needed for $shareName" -DurationMs 0
                    [System.Windows.Forms.Application]::DoEvents()
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
                    Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): mapping $shareName to $($share.DriveLetter): (timeout ${netUseTimeout}s)..." -DurationMs 0
                    [System.Windows.Forms.Application]::DoEvents()
                    $connectResult = Connect-NetworkShare -SharePath $share.SharePath -DriveLetter $share.DriveLetter -Credential $cred -ReturnStatus -Silent
                    if ($connectResult.Success -or (Test-ShareConnection -DriveLetter $share.DriveLetter)) {
                        $success++
                        $connectedShares += $shareName
                        $config = Get-CachedConfig -Force
                        $shareObj = $config.Shares | Where-Object { $_.Id -eq $share.Id }
                        if ($shareObj) {
                            $shareObj.LastConnected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            Save-AllShares -Config $config | Out-Null
                        }
                        Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): connected $shareName" -DurationMs 0
                        [System.Windows.Forms.Application]::DoEvents()
                        Write-ActionLog -Message "Connect All: Connected $shareName" -Category 'Connection'
                    } else {
                        $failed++
                        $failedShares += $shareName
                        $errorText = if ($connectResult.ErrorMessage) { $connectResult.ErrorMessage } else { "connection did not verify" }
                        Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): failed $shareName - $errorText" -DurationMs 0
                        [System.Windows.Forms.Application]::DoEvents()
                        Write-ActionLog -Message "Connect All: Connection failed for $shareName - $errorText" -Level WARN -Category 'Connection'
                    }
                } catch {
                    $failed++
                    $failedShares += $shareName
                    Show-GuiStatusMessage -Message "Connect All ($index/$shareCount): error on $shareName" -DurationMs 0
                    [System.Windows.Forms.Application]::DoEvents()
                    Write-ActionLog -Message "Connect All: Exception for $shareName - $_" -Level ERROR -Category 'Connection'
                }
            }
        }
        finally {
            Set-GuiBulkOperationState -InProgress $false
        }
        
        Write-ActionLog -Message "Connect All: Complete (success: $success, failed: $failed, skipped: $skipped)" -Category 'Connection'
        Update-ShareList
        Show-GuiStatusMessage -Message "Connect All: $success connected, $failed failed, $skipped skipped" -DurationMs 5000
        
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
            $shares = @(Get-ShareConfiguration)
            $disconnected = 0
            $skipped = 0
            $failed = 0
            $disconnectedShares = @()
            $skippedShares = @()
            $failedShares = @()
            
            $shareCount = if ($shares) { $shares.Count } else { 0 }
            Write-ActionLog -Message "Disconnect All: Starting bulk disconnection ($shareCount total shares)" -Category 'Connection'
            
            Set-GuiBulkOperationState -InProgress $true -Message "Disconnect All: preparing $shareCount share(s)..."
            try {
                $index = 0
                foreach ($share in $shares) {
                    $index++
                    $shareName = if ($share.Name) { $share.Name } else { "Unknown" }
                    
                    Show-GuiStatusMessage -Message "Disconnect All ($index/$shareCount): disconnecting $shareName..." -DurationMs 0
                    [System.Windows.Forms.Application]::DoEvents()
                    
                    $disconnectResult = Disconnect-NetworkShare -DriveLetter $share.DriveLetter -Silent -ReturnStatus
                    if ($disconnectResult.Success) {
                        $disconnected++
                        $disconnectedShares += $shareName
                        Show-GuiStatusMessage -Message "Disconnect All ($index/$shareCount): disconnected $shareName" -DurationMs 0
                        [System.Windows.Forms.Application]::DoEvents()
                        Write-ActionLog -Message "Disconnect All: Disconnected $shareName" -Category 'Connection'
                    } elseif ($disconnectResult.ErrorType -eq "NotMapped") {
                        $skipped++
                        $skippedShares += $shareName
                        Show-GuiStatusMessage -Message "Disconnect All ($index/$shareCount): not mapped: $shareName" -DurationMs 0
                        [System.Windows.Forms.Application]::DoEvents()
                    } else {
                        $failed++
                        $failedShares += $shareName
                        $errorText = if ($disconnectResult.ErrorMessage) { $disconnectResult.ErrorMessage } else { "disconnect failed" }
                        Show-GuiStatusMessage -Message "Disconnect All ($index/$shareCount): failed $shareName - $errorText" -DurationMs 0
                        [System.Windows.Forms.Application]::DoEvents()
                        Write-ActionLog -Message "Disconnect All: Failed $shareName - $errorText" -Level WARN -Category 'Connection'
                    }
                }
            }
            finally {
                Set-GuiBulkOperationState -InProgress $false
            }
            
            Write-ActionLog -Message "Disconnect All: Complete (disconnected: $disconnected, skipped: $skipped, failed: $failed)" -Category 'Connection'
            Update-ShareList
            Show-GuiStatusMessage -Message "Disconnect All: $disconnected disconnected, $skipped not mapped, $failed failed" -DurationMs 5000
            
            if ($disconnected -gt 0 -or $skipped -gt 0 -or $failed -gt 0) {
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
                if ($failed -gt 0) {
                    $summary += "`n`nFailed: $failed"
                    if ($failedShares.Count -gt 0) {
                        $summary += "`n  " + ($failedShares -join ', ')
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
        Show-GuiStatusMessage -Message "Share list refreshed" -DurationMs 2200
    })
    $grpShares.Controls.Add($btnRefresh)
    
    # Group: System
    $grpSystem = New-Object System.Windows.Forms.GroupBox
    $grpSystem.Text = "System"
    $grpSystem.Top = $toolbarY
    $grpSystem.Left = 460
    $grpSystem.Width = 215
    $grpSystem.Height = 120
    $grpSystem.Anchor = 'Right,Bottom'
    $form.Controls.Add($grpSystem)
    
    $btnCredentials = New-Object System.Windows.Forms.Button
    $btnCredentials.Text = "Credentials..."
    $btnCredentials.Width = 95
    $btnCredentials.Height = 40
    $btnCredentials.Top = 25
    $btnCredentials.Left = 10

    # Primary action opens the full credential center.
    $btnCredentials.Add_Click({
        Show-CredentialsDialog -StartPage Credentials
    })

    # Right-click quick menu for common credential tasks.
    $invokeCredentialImport = {
        param([bool]$MergeMode)

        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Title = "Select Credentials Backup File"
        $ofd.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
        $ofd.InitialDirectory = $baseFolder
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

        if (-not $MergeMode) {
            $replaceConfirm = [System.Windows.Forms.MessageBox]::Show(
                "Replace all stored credentials with this file?`n`nThis action cannot be undone.",
                "Confirm Replace",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($replaceConfirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }

        Import-Credentials -ImportPath $ofd.FileName -Merge:$MergeMode
    }

    $credMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miOpenCredCenter = New-Object System.Windows.Forms.ToolStripMenuItem
    $miOpenCredCenter.Text = "Open Credential Center"
    $miOpenCredCenter.Add_Click({ Show-CredentialsDialog -StartPage Credentials })
    $credMenu.Items.Add($miOpenCredCenter) | Out-Null

    $credMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miExportCreds = New-Object System.Windows.Forms.ToolStripMenuItem
    $miExportCreds.Text = "Export Credentials Backup..."
    $miExportCreds.Add_Click({ Export-Credentials })
    $credMenu.Items.Add($miExportCreds) | Out-Null

    $miImportMerge = New-Object System.Windows.Forms.ToolStripMenuItem
    $miImportMerge.Text = "Import and Merge..."
    $miImportMerge.Add_Click({ & $invokeCredentialImport $true })
    $credMenu.Items.Add($miImportMerge) | Out-Null

    $miImportReplace = New-Object System.Windows.Forms.ToolStripMenuItem
    $miImportReplace.Text = "Import and Replace..."
    $miImportReplace.Add_Click({ & $invokeCredentialImport $false })
    $credMenu.Items.Add($miImportReplace) | Out-Null

    $btnCredentials.ContextMenuStrip = $credMenu
    $grpSystem.Controls.Add($btnCredentials)
    
    $btnSettings = New-Object System.Windows.Forms.Button
    $btnSettings.Text = "Settings"
    $btnSettings.Width = 95
    $btnSettings.Height = 40
    $btnSettings.Top = 25
    $btnSettings.Left = 110
    $btnSettings.Add_Click({
        $formSettings = New-Object System.Windows.Forms.Form
        $formSettings.Text = "System Tools"
        $formSettings.Width = 380
        $formSettings.Height = 280
        $formSettings.StartPosition = "CenterParent"
        $formSettings.FormBorderStyle = "FixedDialog"
        $formSettings.MaximizeBox = $false
        
        $lblTools = New-Object System.Windows.Forms.Label
        $lblTools.Text = "Open the section you want to manage:"
        $lblTools.Top = 15
        $lblTools.Left = 30
        $lblTools.Width = 310
        $lblTools.Height = 18
        $lblTools.ForeColor = [System.Drawing.Color]::DimGray
        $formSettings.Controls.Add($lblTools)

        $yPos = 40

        $btnCredentialCenter = New-Object System.Windows.Forms.Button
        $btnCredentialCenter.Text = "Credential Center"
        $btnCredentialCenter.Width = 300
        $btnCredentialCenter.Height = 35
        $btnCredentialCenter.Top = $yPos
        $btnCredentialCenter.Left = 30
        $btnCredentialCenter.Add_Click({
            Show-CredentialsDialog -StartPage Credentials
        })
        $formSettings.Controls.Add($btnCredentialCenter)

        $yPos += 45
        
        $btnPref = New-Object System.Windows.Forms.Button
        $btnPref.Text = "Preferences"
        $btnPref.Width = 300
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
        $btnBackup.Width = 300
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
        $btnLog.Width = 300
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
    $btnExit.Anchor = 'Bottom,Right'
    $btnExit.Add_Click({
        $form.Close()
    })
    $form.Controls.Add($btnExit)

    # Status bar
    $statusBar = New-Object System.Windows.Forms.StatusBar
    $statusBar.Text = "Ready"
    $statusBar.Tag = $statusBar.Text
    $form.Controls.Add($statusBar)
    $script:GuiBulkOperationInProgress = $false

    $statusResetTimer = New-Object System.Windows.Forms.Timer
    $statusResetTimer.Interval = 3200
    $statusResetTimer.Add_Tick({
        $statusResetTimer.Stop()
        $lastStatusSummaryText = [string]$statusBar.Tag
        if ([string]::IsNullOrWhiteSpace($lastStatusSummaryText)) {
            $statusBar.Text = "Ready"
        } else {
            $statusBar.Text = $lastStatusSummaryText
        }
    })

    function Show-GuiStatusMessage {
        param(
            [string]$Message,
            [int]$DurationMs = 3200
        )

        if ([string]::IsNullOrWhiteSpace($Message)) { return }

        $statusResetTimer.Stop()
        $statusBar.Text = $Message
        if ($DurationMs -gt 0) {
            if ($DurationMs -lt 500) { $DurationMs = 500 }
            $statusResetTimer.Interval = $DurationMs
            $statusResetTimer.Start()
        }
    }

    function Set-GuiBulkOperationState {
        param(
            [bool]$InProgress,
            [string]$Message
        )

        $script:GuiBulkOperationInProgress = $InProgress
        foreach ($control in @($btnConnectAll, $btnDisconnectAll, $btnRefresh, $btnAdd)) {
            if ($control) {
                $control.Enabled = -not $InProgress
            }
        }

        if ($InProgress) {
            $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            if ($Message) {
                Show-GuiStatusMessage -Message $Message -DurationMs 0
            }
        } else {
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
        [System.Windows.Forms.Application]::DoEvents()
    }

    $resetFilters = {
        if ($cmbCategory.Items.Count -gt 0) {
            $cmbCategory.SelectedIndex = 0
        }
        $chkFavoritesOnly.Checked = $false
        $txtSearch.Text = "Search shares..."
        $txtSearch.ForeColor = [System.Drawing.Color]::Gray
        Update-ShareList
        Show-GuiStatusMessage -Message "Filters reset" -DurationMs 2200
    }

    $requireShareSelection = {
        if ($listView.SelectedItems.Count -gt 0) { return $true }

        [System.Windows.Forms.MessageBox]::Show(
            "Select at least one share first.",
            "No Selection",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

        return $false
    }

    function Show-KeyboardShortcutsDialog {
        $shortcutForm = New-Object System.Windows.Forms.Form
        $shortcutForm.Text = "Keyboard Shortcuts"
        $shortcutForm.Width = 640
        $shortcutForm.Height = 470
        $shortcutForm.StartPosition = "CenterParent"
        $shortcutForm.FormBorderStyle = "Sizable"
        $shortcutForm.MinimumSize = New-Object System.Drawing.Size(640, 470)

        $lblIntro = New-Object System.Windows.Forms.Label
        $lblIntro.Text = "Available shortcuts in GUI mode (grouped by workflow)"
        $lblIntro.Left = 12
        $lblIntro.Top = 12
        $lblIntro.Width = 600
        $lblIntro.Height = 18
        $lblIntro.Anchor = 'Top,Left,Right'
        $lblIntro.ForeColor = [System.Drawing.Color]::DimGray
        $shortcutForm.Controls.Add($lblIntro)

        $shortcutList = New-Object System.Windows.Forms.ListView
        $shortcutList.View = 'Details'
        $shortcutList.FullRowSelect = $true
        $shortcutList.GridLines = $true
        $shortcutList.MultiSelect = $false
        $shortcutList.HideSelection = $false
        $shortcutList.Left = 12
        $shortcutList.Top = 36
        $shortcutList.Width = 600
        $shortcutList.Height = 350
        $shortcutList.Anchor = 'Top,Left,Right,Bottom'
        $shortcutList.ShowGroups = $true
        [void]$shortcutList.Columns.Add("Shortcut", 190)
        [void]$shortcutList.Columns.Add("Action", 390)

        $groupNavigation = New-Object System.Windows.Forms.ListViewGroup
        $groupNavigation.Header = "Navigation and Filters"
        $groupNavigation.Name = "navigation"
        [void]$shortcutList.Groups.Add($groupNavigation)

        $groupSelection = New-Object System.Windows.Forms.ListViewGroup
        $groupSelection.Header = "Selection and Share Actions"
        $groupSelection.Name = "selection"
        [void]$shortcutList.Groups.Add($groupSelection)

        $groupCredentials = New-Object System.Windows.Forms.ListViewGroup
        $groupCredentials.Header = "Credentials"
        $groupCredentials.Name = "credentials"
        [void]$shortcutList.Groups.Add($groupCredentials)

        $addShortcutRow = {
            param(
                [string]$Shortcut,
                [string]$Action,
                [System.Windows.Forms.ListViewGroup]$Group
            )

            $item = New-Object System.Windows.Forms.ListViewItem($Shortcut)
            [void]$item.SubItems.Add($Action)
            $item.Group = $Group
            [void]$shortcutList.Items.Add($item)
        }

        & $addShortcutRow 'Ctrl+N' 'Add new share' $groupNavigation
        & $addShortcutRow 'Ctrl+F' 'Focus search box' $groupNavigation
        & $addShortcutRow 'Ctrl+R' 'Refresh list' $groupNavigation
        & $addShortcutRow 'Ctrl+Shift+F' 'Reset all filters' $groupNavigation
        & $addShortcutRow 'F5' 'Refresh list' $groupNavigation

        & $addShortcutRow 'Ctrl+A' 'Select all visible shares or active text' $groupSelection
        & $addShortcutRow 'Ctrl+Shift+A' 'Connect all enabled shares' $groupSelection
        & $addShortcutRow 'Ctrl+D' 'Disconnect all connected shares' $groupSelection
        & $addShortcutRow 'Delete' 'Delete selected share(s)' $groupSelection

        & $addShortcutRow 'Ctrl+Shift+K' 'Open Credential Center' $groupCredentials

        if ($shortcutList.Items.Count -gt 0) {
            $shortcutList.Items[0].Selected = $true
            $shortcutList.Items[0].Focused = $true
        }
        $shortcutForm.Controls.Add($shortcutList)

        $btnCloseShortcuts = New-Object System.Windows.Forms.Button
        $btnCloseShortcuts.Text = "Close"
        $btnCloseShortcuts.Left = 512
        $btnCloseShortcuts.Top = 394
        $btnCloseShortcuts.Width = 100
        $btnCloseShortcuts.Height = 30
        $btnCloseShortcuts.Anchor = 'Right,Bottom'
        $btnCloseShortcuts.Add_Click({ $shortcutForm.Close() })
        $shortcutForm.Controls.Add($btnCloseShortcuts)

        $shortcutForm.AcceptButton = $btnCloseShortcuts
        $shortcutForm.CancelButton = $btnCloseShortcuts

        [void]$shortcutForm.ShowDialog($form)
    }

    # File menu
    $menuFile = New-Object System.Windows.Forms.ToolStripMenuItem("&File")

    $miFileSwitchCli = New-Object System.Windows.Forms.ToolStripMenuItem("Switch to &CLI")
    $miFileSwitchCli.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::L
    $miFileSwitchCli.Add_Click({ $btnCLI.PerformClick() })
    $menuFile.DropDownItems.Add($miFileSwitchCli) | Out-Null

    $menuFile.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miFileExit = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit")
    $miFileExit.ShortcutKeys = [System.Windows.Forms.Keys]::Alt -bor [System.Windows.Forms.Keys]::F4
    $miFileExit.Add_Click({ $btnExit.PerformClick() })
    $menuFile.DropDownItems.Add($miFileExit) | Out-Null

    # Shares menu
    $menuShares = New-Object System.Windows.Forms.ToolStripMenuItem("&Shares")

    $miShareAdd = New-Object System.Windows.Forms.ToolStripMenuItem("&Add New Share")
    $miShareAdd.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::N
    $miShareAdd.Add_Click({ $btnAdd.PerformClick() })
    $menuShares.DropDownItems.Add($miShareAdd) | Out-Null

    $miShareEdit = New-Object System.Windows.Forms.ToolStripMenuItem("&Edit Selected")
    $miShareEdit.Add_Click({
        if (-not (& $requireShareSelection)) { return }
        $menuEdit.PerformClick()
    })
    $menuShares.DropDownItems.Add($miShareEdit) | Out-Null

    $miShareDelete = New-Object System.Windows.Forms.ToolStripMenuItem("&Delete Selected")
    $miShareDelete.Add_Click({
        if (-not (& $requireShareSelection)) { return }
        $menuDelete.PerformClick()
    })
    $menuShares.DropDownItems.Add($miShareDelete) | Out-Null

    $menuShares.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miShareConnect = New-Object System.Windows.Forms.ToolStripMenuItem("&Connect Selected")
    $miShareConnect.Add_Click({
        if (-not (& $requireShareSelection)) { return }
        $menuConnect.PerformClick()
    })
    $menuShares.DropDownItems.Add($miShareConnect) | Out-Null

    $miShareDisconnect = New-Object System.Windows.Forms.ToolStripMenuItem("D&isconnect Selected")
    $miShareDisconnect.Add_Click({
        if (-not (& $requireShareSelection)) { return }
        $menuDisconnect.PerformClick()
    })
    $menuShares.DropDownItems.Add($miShareDisconnect) | Out-Null

    $menuShares.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miShareConnectAll = New-Object System.Windows.Forms.ToolStripMenuItem("Connect &All")
    $miShareConnectAll.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::A
    $miShareConnectAll.Add_Click({ $btnConnectAll.PerformClick() })
    $menuShares.DropDownItems.Add($miShareConnectAll) | Out-Null

    $miShareDisconnectAll = New-Object System.Windows.Forms.ToolStripMenuItem("Disconnect A&ll")
    $miShareDisconnectAll.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D
    $miShareDisconnectAll.Add_Click({ $btnDisconnectAll.PerformClick() })
    $menuShares.DropDownItems.Add($miShareDisconnectAll) | Out-Null

    $menuShares.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miShareRefresh = New-Object System.Windows.Forms.ToolStripMenuItem("&Refresh")
    $miShareRefresh.ShortcutKeys = [System.Windows.Forms.Keys]::F5
    $miShareRefresh.Add_Click({ $btnRefresh.PerformClick() })
    $menuShares.DropDownItems.Add($miShareRefresh) | Out-Null

    $menuShares.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miShareResetFilters = New-Object System.Windows.Forms.ToolStripMenuItem("Reset &Filters")
    $miShareResetFilters.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::F
    $miShareResetFilters.Add_Click({ & $resetFilters })
    $menuShares.DropDownItems.Add($miShareResetFilters) | Out-Null

    # Credentials menu
    $menuCreds = New-Object System.Windows.Forms.ToolStripMenuItem("&Credentials")

    $miCredCenter = New-Object System.Windows.Forms.ToolStripMenuItem("Open Credential &Center")
    $miCredCenter.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::K
    $miCredCenter.Add_Click({ Show-CredentialsDialog -StartPage Credentials })
    $menuCreds.DropDownItems.Add($miCredCenter) | Out-Null

    $miCredBackup = New-Object System.Windows.Forms.ToolStripMenuItem("Open Credential &Backups")
    $miCredBackup.Add_Click({ Show-CredentialsDialog -StartPage Backup })
    $menuCreds.DropDownItems.Add($miCredBackup) | Out-Null

    $menuCreds.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $miCredExport = New-Object System.Windows.Forms.ToolStripMenuItem("&Export Credentials Backup...")
    $miCredExport.Add_Click({ Export-Credentials })
    $menuCreds.DropDownItems.Add($miCredExport) | Out-Null

    $miCredImportMerge = New-Object System.Windows.Forms.ToolStripMenuItem("Import and &Merge...")
    $miCredImportMerge.Add_Click({ & $invokeCredentialImport $true })
    $menuCreds.DropDownItems.Add($miCredImportMerge) | Out-Null

    $miCredImportReplace = New-Object System.Windows.Forms.ToolStripMenuItem("Import and &Replace...")
    $miCredImportReplace.Add_Click({ & $invokeCredentialImport $false })
    $menuCreds.DropDownItems.Add($miCredImportReplace) | Out-Null

    # Tools menu
    $menuTools = New-Object System.Windows.Forms.ToolStripMenuItem("&Tools")

    $miToolsPreferences = New-Object System.Windows.Forms.ToolStripMenuItem("&Preferences")
    $miToolsPreferences.Add_Click({ Show-PreferencesDialog })
    $menuTools.DropDownItems.Add($miToolsPreferences) | Out-Null

    $miToolsBackup = New-Object System.Windows.Forms.ToolStripMenuItem("Backup / &Restore")
    $miToolsBackup.Add_Click({ Show-BackupDialog })
    $menuTools.DropDownItems.Add($miToolsBackup) | Out-Null

    $menuToolsLogs = New-Object System.Windows.Forms.ToolStripMenuItem("Open &Logs")
    $miToolsLogText = New-Object System.Windows.Forms.ToolStripMenuItem("Open Text Log")
    $miToolsLogText.Add_Click({ Invoke-LogFileOpen -Target text })
    $menuToolsLogs.DropDownItems.Add($miToolsLogText) | Out-Null

    $miToolsLogEvents = New-Object System.Windows.Forms.ToolStripMenuItem("Open Structured Log")
    $miToolsLogEvents.Add_Click({ Invoke-LogFileOpen -Target events })
    $menuToolsLogs.DropDownItems.Add($miToolsLogEvents) | Out-Null

    $miToolsLogFolder = New-Object System.Windows.Forms.ToolStripMenuItem("Open Logs Folder")
    $miToolsLogFolder.Add_Click({ Invoke-LogFileOpen -Target folder })
    $menuToolsLogs.DropDownItems.Add($miToolsLogFolder) | Out-Null
    $menuTools.DropDownItems.Add($menuToolsLogs) | Out-Null

    # Help menu
    $menuHelp = New-Object System.Windows.Forms.ToolStripMenuItem("&Help")

    $miHelpShortcuts = New-Object System.Windows.Forms.ToolStripMenuItem("Keyboard &Shortcuts")
    $miHelpShortcuts.ShortcutKeys = [System.Windows.Forms.Keys]::F1
    $miHelpShortcuts.Add_Click({
        Show-KeyboardShortcutsDialog
    })
    $menuHelp.DropDownItems.Add($miHelpShortcuts) | Out-Null

    $miHelpUpdates = New-Object System.Windows.Forms.ToolStripMenuItem("Check for &Updates")
    $miHelpUpdates.Add_Click({ Update-ShareManager -UseGUI })
    $menuHelp.DropDownItems.Add($miHelpUpdates) | Out-Null

    $miHelpAbout = New-Object System.Windows.Forms.ToolStripMenuItem("&About")
    $miHelpAbout.Add_Click({ $btnAbout.PerformClick() })
    $menuHelp.DropDownItems.Add($miHelpAbout) | Out-Null

    $mainMenu.Items.AddRange(@($menuFile, $menuShares, $menuCreds, $menuTools, $menuHelp))

    function Update-SelectedShareActions {
        $selectedIds = @($listView.SelectedItems | ForEach-Object { $_.Tag })
        $selectedCount = $selectedIds.Count
        $singleSelection = ($selectedCount -eq 1)

        $menuEdit.Enabled = $singleSelection
        $menuToggle.Enabled = $singleSelection
        $menuFavorite.Enabled = $singleSelection
        $miShareEdit.Enabled = $singleSelection

        $hasSelection = $selectedCount -gt 0
        $menuDelete.Enabled = $hasSelection
        $miShareDelete.Enabled = $hasSelection

        if (-not $hasSelection) {
            $menuConnect.Enabled = $false
            $menuDisconnect.Enabled = $false
            $miShareConnect.Enabled = $false
            $miShareDisconnect.Enabled = $false
            return
        }

        # Connect/Disconnect actions operate on the primary selected item.
        $primaryShareId = $listView.SelectedItems[0].Tag
        $primaryShare = Get-ShareConfiguration -ShareId $primaryShareId
        if (-not $primaryShare) {
            $menuConnect.Enabled = $false
            $menuDisconnect.Enabled = $false
            $miShareConnect.Enabled = $false
            $miShareDisconnect.Enabled = $false
            return
        }

        $isPrimaryEnabled = if ($primaryShare.PSObject.Properties['Enabled']) { [bool]$primaryShare.Enabled } else { $true }
        if (-not $isPrimaryEnabled) {
            $menuConnect.Enabled = $false
            $menuDisconnect.Enabled = $false
            $miShareConnect.Enabled = $false
            $miShareDisconnect.Enabled = $false
            return
        }

        $isPrimaryConnected = Test-ShareConnection -DriveLetter $primaryShare.DriveLetter
        $menuConnect.Enabled = -not $isPrimaryConnected
        $miShareConnect.Enabled = -not $isPrimaryConnected
        $menuDisconnect.Enabled = $isPrimaryConnected
        $miShareDisconnect.Enabled = $isPrimaryConnected
    }

    # Keep toolbar and top filters readable across different window sizes.
    function Update-MainLayout {
        try {
            $clientWidth = $form.ClientSize.Width
            $rightMargin = 15
            $controlGap = 8

            # Right-align filter controls in the header row.
            $chkFavoritesOnly.Left = [Math]::Max(15, $clientWidth - $rightMargin - $chkFavoritesOnly.Width)
            $txtSearch.Left = [Math]::Max(15, $chkFavoritesOnly.Left - $controlGap - $txtSearch.Width)
            $cmbCategory.Left = [Math]::Max(15, $txtSearch.Left - $controlGap - $cmbCategory.Width)

            # Keep hint label readable when the form width is reduced.
            $hintWidth = [Math]::Max(100, $clientWidth - ($lblHint.Left + $rightMargin))
            $lblHint.MaximumSize = New-Object System.Drawing.Size($hintWidth, 0)

            # Maintain a stable split between share actions and system controls.
            $groupGap = 10
            $grpSystem.Left = [Math]::Max(15, $clientWidth - $rightMargin - $grpSystem.Width)
            $grpShares.Width = [Math]::Max(320, $grpSystem.Left - $groupGap - $grpShares.Left)

            # Layout buttons inside Share Actions group.
            $innerPadding = 10
            $buttonGap = 5
            $buttonCount = 4
            $availableWidth = $grpShares.ClientSize.Width - ($innerPadding * 2) - ($buttonGap * ($buttonCount - 1))
            $buttonWidth = [int][Math]::Floor($availableWidth / $buttonCount)
            if ($buttonWidth -lt 80) { $buttonWidth = 80 }

            $x = $innerPadding
            foreach ($btn in @($btnAdd, $btnConnectAll, $btnDisconnectAll, $btnRefresh)) {
                $btn.Left = $x
                $btn.Width = $buttonWidth
                $x += ($buttonWidth + $buttonGap)
            }

            # Let the final button absorb any remainder to avoid visual gaps.
            $remaining = $grpShares.ClientSize.Width - $innerPadding - ($btnRefresh.Left + $btnRefresh.Width)
            if ($remaining -gt 0) {
                $btnRefresh.Width += $remaining
            }

            # Layout buttons inside System group.
            $sysPad = 10
            $sysGap = 5
            $topButtonWidth = [int][Math]::Floor(($grpSystem.ClientSize.Width - ($sysPad * 2) - $sysGap) / 2)
            if ($topButtonWidth -lt 80) { $topButtonWidth = 80 }

            $btnCredentials.Left = $sysPad
            $btnCredentials.Width = $topButtonWidth
            $btnSettings.Left = $btnCredentials.Left + $btnCredentials.Width + $sysGap
            $btnSettings.Width = [Math]::Max(80, $grpSystem.ClientSize.Width - $sysPad - $btnSettings.Left)
            $btnAbout.Left = $sysPad
            $btnAbout.Width = [Math]::Max(100, $grpSystem.ClientSize.Width - ($sysPad * 2))

            # Keep bottom action buttons balanced.
            $bottomGap = 10
            $halfWidth = [int][Math]::Floor(($clientWidth - 30 - $bottomGap) / 2)
            if ($halfWidth -lt 150) { $halfWidth = 150 }

            $btnCLI.Left = 15
            $btnCLI.Width = $halfWidth
            $btnExit.Left = $btnCLI.Right + $bottomGap
            $btnExit.Width = [Math]::Max(150, $clientWidth - 15 - $btnExit.Left)
        }
        catch {
            Write-ActionLog -Message "Update-MainLayout failed: $_" -Level DEBUG -Category 'GUI' -OncePerSeconds 5
        }
    }

    Update-MainLayout

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
        $visible = $shares.Count
        $totalAvailable = if ($allShares) { $allShares.Count } else { 0 }
        $total = $shares.Count
        $connectedCount = 0
        foreach ($share in $shares) {
            if (Test-ShareConnection -DriveLetter $share.DriveLetter) {
                $connectedCount++
            }
        }

        $activeFilters = @()
        if ($cmbCategory.SelectedItem -and $cmbCategory.SelectedItem -ne "All Categories") {
            $activeFilters += "Category"
        }
        if ($chkFavoritesOnly.Checked) {
            $activeFilters += "Favorites"
        }
        if ($searchText -and $searchText -ne "Search shares..." -and $searchText.Trim().Length -gt 0) {
            $activeFilters += "Search"
        }

        $statusBar.Text = "Visible: $visible | Total: $totalAvailable | Connected: $connectedCount | Disconnected: $($total - $connectedCount)"
        if ($activeFilters.Count -gt 0) {
            $statusBar.Text += " | Filters: " + ($activeFilters -join ', ')
        }
        $statusBar.Tag = $statusBar.Text
        
        # Update button states based on share status
        $hasDisconnected = ($total - $connectedCount) -gt 0
        $hasConnected = $connectedCount -gt 0
        
        # Enable Connect All only if there are disconnected shares
        $btnConnectAll.Enabled = ($hasDisconnected -and -not $script:GuiBulkOperationInProgress)
        if (-not $hasDisconnected) {
            $btnConnectAll.ForeColor = [System.Drawing.Color]::Gray
        } else {
            $btnConnectAll.ForeColor = [System.Drawing.Color]::Black
        }
        
        # Enable Disconnect All only if there are connected shares
        $btnDisconnectAll.Enabled = ($hasConnected -and -not $script:GuiBulkOperationInProgress)
        if (-not $hasConnected) {
            $btnDisconnectAll.ForeColor = [System.Drawing.Color]::Gray
        } else {
            $btnDisconnectAll.ForeColor = [System.Drawing.Color]::Black
        }
        
        Update-SelectedShareActions
    }
    
    # Selection changed event to update context menu
    $listView.Add_SelectedIndexChanged({
        Update-SelectedShareActions
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
        $null = $eventSender
        
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
        # Ctrl+Shift+F: Reset all filters
        elseif ($e.Control -and $e.Shift -and $e.KeyCode -eq 'F') {
            & $resetFilters
            $e.Handled = $true
        }
        # F5: Refresh (alternative)
        elseif ($e.KeyCode -eq 'F5') {
            Clear-ConfigCache
            Update-ShareList
            $e.Handled = $true
        }
        # Ctrl+Shift+A: Connect All
        elseif ($e.Control -and $e.Shift -and $e.KeyCode -eq 'A') {
            $btnConnectAll.PerformClick()
            $e.Handled = $true
        }
        # Ctrl+A: Select all (text or visible shares)
        elseif ($e.Control -and $e.KeyCode -eq 'A') {
            if ($form.ActiveControl -is [System.Windows.Forms.TextBoxBase]) {
                $form.ActiveControl.SelectAll()
            }
            elseif ($listView.Items.Count -gt 0) {
                $listView.Focus()
                $listView.BeginUpdate()
                try {
                    foreach ($item in $listView.Items) {
                        $item.Selected = $true
                    }
                    $listView.Items[0].Focused = $true
                    $listView.EnsureVisible(0)
                }
                finally {
                    $listView.EndUpdate()
                }
                Show-GuiStatusMessage -Message "Selected all visible shares" -DurationMs 2000
            }
            $e.SuppressKeyPress = $true
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
            if ($statusResetTimer) {
                $statusResetTimer.Stop()
                $statusResetTimer.Dispose()
            }
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

# Allow test harnesses to load functions without executing startup flow.
if ($env:SM_SKIP_ENTRYPOINT -eq '1') { return }

if ($ApplyCleanup -and -not $CleanupData) { throw 'Use -CleanupData with -ApplyCleanup. Run -CleanupData alone to preview first.' }
if ($CleanupData) {
    $cleanupResults = @(Invoke-DataCleanup -CurrentScriptPath $script:ApplicationPath -Apply:$ApplyCleanup)
    if ($cleanupResults.Count) { $cleanupResults | Format-Table -AutoSize }
    else { Write-Host 'No old log archives or updater backups are eligible for cleanup.' }
    if (-not $ApplyCleanup) { Write-Host 'Preview only. Add -ApplyCleanup to delete eligible files. Recent rollback backups and active data are preserved.' }
    return
}

Invoke-StartupDataCleanup

# Log script startup
Write-ActionLog -Message "Share Manager v$version starting" -Level INFO -Category 'Startup' -Data @{ 
    mode = if ($StartupMode) { $StartupMode } else { "Auto" }
    psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
    psEdition = $PSVersionTable.PSEdition
}

# Migrate legacy config first time
Convert-LegacyConfig

$cfg = Import-AllShares
$needsSetup = Test-FirstRunNeeded -Config $cfg

Write-ActionLog -Message "Configuration loaded: $($cfg.Shares.Count) share(s)" -Level INFO -Category 'Startup'

# If StartupMode parameter is provided, override preference
if ($StartupMode -eq "CLI" -or $StartupMode -eq "GUI") {
    if ($StartupMode -eq "CLI") {
        $script:UseGUI = $false
        if ($needsSetup) {
            $cliSetup = Initialize-Config-CLI
            if (-not $cliSetup) { Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow; return }
        }
        Start-CliMode
        return
    }
    elseif ($StartupMode -eq "GUI") {
        $script:UseGUI = $true
        if ($needsSetup) {
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
if (-not $needsSetup) {
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
Set-TerminalBlackBackground
Write-Host ""
Write-Host "Choose startup mode for Share Manager v${version}:" -ForegroundColor Cyan
Write-Host "1. CLI Mode"
Write-Host "2. GUI Mode"
try { $mode = Read-CliPrompt "Enter 1 or 2" }
catch [System.OperationCanceledException] { return }

    switch ($mode) {
    "1" {
        $script:UseGUI = $false
        if ($needsSetup) {
            $cliSetup = Initialize-Config-CLI
            if (-not $cliSetup) { Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow; return }
        }
        Start-CliMode
    }
    "2" {
        $script:UseGUI = $true
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName Microsoft.VisualBasic
        if ($needsSetup) {
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
        if ($needsSetup) {
            $cliSetup = Initialize-Config-CLI
            if (-not $cliSetup) { Write-Host "Setup cancelled. Exiting..." -ForegroundColor Yellow; return }
        }
        Start-CliMode
    }
}#endregion
