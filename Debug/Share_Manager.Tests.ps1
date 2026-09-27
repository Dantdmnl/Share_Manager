#Requires -Version 5.1
<#
.SYNOPSIS
    Regression tests for Share Manager core behavior.

.DESCRIPTION
    Focused tests for logic that is easy to regress:
    - Boolean preference conversion
    - UNC path validation
    - Merge import contract and multi-match handling

    These tests run without launching the interactive entry point by setting
    SM_SKIP_ENTRYPOINT before dot-sourcing Share_Manager.ps1.
#>

$script:ScriptPath = Join-Path $PSScriptRoot '..\Share_Manager.ps1'
$script:OriginalSkipEntryPoint = $env:SM_SKIP_ENTRYPOINT
$env:SM_SKIP_ENTRYPOINT = '1'

Describe "Share Manager core regressions" {
$script:OriginalAppData = $env:APPDATA
try {
    $env:APPDATA = $TestDrive
    . $script:ScriptPath
}
finally {
    $env:APPDATA = $script:OriginalAppData
}

    BeforeAll {
        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ShareManagerTests_" + [Guid]::NewGuid().ToString('N'))
        New-Item -Path $script:TestRoot -ItemType Directory -Force | Out-Null

        $script:OriginalState = @{
            baseFolder = $baseFolder
            sharesPath = $sharesPath
            configPath = $configPath
            credentialPath = $credentialPath
            credentialsStorePath = $credentialsStorePath
            keyPath = $keyPath
            logPath = $logPath
            eventsPath = $eventsPath
            cachedConfig = $script:CachedConfig
            configCacheTime = $script:ConfigCacheTime
            logThrottle = $script:LogThrottle
        }

        $baseFolder = $script:TestRoot
        $sharesPath = Join-Path $baseFolder 'shares.json'
        $configPath = Join-Path $baseFolder 'config.json'
        $credentialPath = Join-Path $baseFolder 'cred.txt'
        $credentialsStorePath = Join-Path $baseFolder 'creds.json'
        $keyPath = Join-Path $baseFolder 'key.bin'
        $logPath = Join-Path $baseFolder 'Share_Manager.log'
        $eventsPath = Join-Path $baseFolder 'Share_Manager.events.jsonl'

        $script:CachedConfig = $null
        $script:ConfigCacheTime = $null
        $script:LogThrottle = @{}

        function New-TestPreferences {
            return [PSCustomObject]@{
                UnmapOldMapping = $true
                PreferredMode = 'Prompt'
                PersistentMapping = $false
                AutoReconnect = $true
                ReconnectInterval = 300
                Theme = 'Classic'
                SyncShareNameToDriveLabel = $true
            }
        }
    }

    AfterEach {
        if (Test-Path $sharesPath) { Remove-Item -Path $sharesPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $configPath) { Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $logPath) { Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $eventsPath) { Remove-Item -Path $eventsPath -Force -ErrorAction SilentlyContinue }
        $script:CachedConfig = $null
        $script:ConfigCacheTime = $null
    }

    AfterAll {
        Set-Variable -Name baseFolder -Value $script:OriginalState.baseFolder -Scope Script
        Set-Variable -Name sharesPath -Value $script:OriginalState.sharesPath -Scope Script
        Set-Variable -Name configPath -Value $script:OriginalState.configPath -Scope Script
        Set-Variable -Name credentialPath -Value $script:OriginalState.credentialPath -Scope Script
        Set-Variable -Name credentialsStorePath -Value $script:OriginalState.credentialsStorePath -Scope Script
        Set-Variable -Name keyPath -Value $script:OriginalState.keyPath -Scope Script
        Set-Variable -Name logPath -Value $script:OriginalState.logPath -Scope Script
        Set-Variable -Name eventsPath -Value $script:OriginalState.eventsPath -Scope Script
        $script:CachedConfig = $script:OriginalState.cachedConfig
        $script:ConfigCacheTime = $script:OriginalState.configCacheTime
        $script:LogThrottle = $script:OriginalState.logThrottle

        if (Test-Path $script:TestRoot) {
            Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }

        if ($null -eq $script:OriginalSkipEntryPoint) {
            Remove-Item Env:SM_SKIP_ENTRYPOINT -ErrorAction SilentlyContinue
        } else {
            $env:SM_SKIP_ENTRYPOINT = $script:OriginalSkipEntryPoint
        }
    }

    Context "ConvertTo-SafeBoolean" {
        It "parses common true values" {
            (ConvertTo-SafeBoolean -Value 'true' -Default $false) | Should Be $true
            (ConvertTo-SafeBoolean -Value 'yes' -Default $false) | Should Be $true
            (ConvertTo-SafeBoolean -Value '1' -Default $false) | Should Be $true
            (ConvertTo-SafeBoolean -Value 1 -Default $false) | Should Be $true
        }

        It "parses common false values" {
            (ConvertTo-SafeBoolean -Value 'false' -Default $true) | Should Be $false
            (ConvertTo-SafeBoolean -Value 'no' -Default $true) | Should Be $false
            (ConvertTo-SafeBoolean -Value '0' -Default $true) | Should Be $false
            (ConvertTo-SafeBoolean -Value 0 -Default $true) | Should Be $false
        }

        It "falls back to default for unsupported values" {
            (ConvertTo-SafeBoolean -Value 'maybe' -Default $false) | Should Be $false
            (ConvertTo-SafeBoolean -Value 'maybe' -Default $true) | Should Be $true
            (ConvertTo-SafeBoolean -Value $null -Default $true) | Should Be $true
        }
    }

    Context "Test-ValidUncPath" {
        It "accepts valid UNC paths" {
            (Test-ValidUncPath -Path '\\server\share') | Should Be $true
            (Test-ValidUncPath -Path '\\server\share\folder') | Should Be $true
            (Test-ValidUncPath -Path '\\server\share\folder\') | Should Be $true
        }

        It "rejects invalid UNC paths" {
            (Test-ValidUncPath -Path 'server\share') | Should Be $false
            (Test-ValidUncPath -Path '\\s\share') | Should Be $false
            (Test-ValidUncPath -Path '\\server\') | Should Be $false
            (Test-ValidUncPath -Path '') | Should Be $false
        }
    }

    Context "WinForms helper compatibility" {
        It "accepts ComboBox controls for Ctrl+A support" {
            Add-Type -AssemblyName System.Windows.Forms
            $combo = New-Object System.Windows.Forms.ComboBox
            $passwordBox = New-Object System.Windows.Forms.TextBox

            { Add-CtrlASupport -TextBox $combo -NextControl $passwordBox } | Should Not Throw
        }
    }

    Context "Default configuration isolation" {
        It "returns a fresh default shares config when shares.json is missing" {
            $first = Import-AllShares
            $first.Shares += (New-ShareEntry -Name 'Temp' -SharePath '\\srv\temp' -DriveLetter 'T' -Username 'DOMAIN\user')
            $first.Preferences.PreferredMode = 'GUI'

            $second = Import-AllShares
            $second.Shares.Count | Should Be 0
            $second.Preferences.PreferredMode | Should Be 'Prompt'
        }

        It "returns a fresh default shares config after corrupt JSON" {
            Set-Content -Path $sharesPath -Value '{ invalid json' -Encoding UTF8

            $first = Import-AllShares
            $first.Shares += (New-ShareEntry -Name 'Temp' -SharePath '\\srv\temp' -DriveLetter 'T' -Username 'DOMAIN\user')

            $second = Import-AllShares
            $second.Shares.Count | Should Be 0
        }

        It "backfills missing preferences without sharing the default object" {
            $rawConfig = [PSCustomObject]@{
                Shares = @()
            }
            $rawConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $sharesPath -Encoding UTF8

            $first = Import-AllShares
            $first.Preferences.PreferredMode = 'CLI'

            Remove-Item -Path $sharesPath -Force
            $second = Import-AllShares
            $second.Preferences.PreferredMode | Should Be 'Prompt'
        }

        It "backfills legacy preferences without sharing the default object" {
            $legacyConfig = [PSCustomObject]@{
                SharePath = '\\srv\legacy'
                DriveLetter = 'L'
                Username = 'DOMAIN\legacy'
            }
            $legacyConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8

            $first = Import-ShareConfig
            $first.Preferences.PreferredMode = 'GUI'

            Remove-Item -Path $configPath -Force
            $legacyConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8

            $second = Import-ShareConfig
            $second.Preferences.PreferredMode | Should Be 'Prompt'
        }
    }

    Context "Credential argument boundaries" {
        It "passes separate arguments for manual and generated AutoMap credentials" {
            $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $autoMapSource = $sourceAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $node.Value -like '*function Set-AutoMapCredentialTarget*'
            }, $true).Value
            $autoMapAst = [System.Management.Automation.Language.Parser]::ParseInput($autoMapSource, [ref]$null, [ref]$null)
            $definition = $autoMapAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-AutoMapCredentialTarget' }, $true)
            . ([scriptblock]::Create($definition.Extent.Text))
            function cmdkey {
                $script:CapturedCredentialArguments = @($args | ForEach-Object { $_ })
                $global:LASTEXITCODE = 0
            }
            $password = 'synthetic password & $value'
            Invoke-CmdKeyAdd -Target 'server' -Username 'domain\test' -Password $password | Out-Null
            $script:CapturedCredentialArguments.Count | Should Be 3
            $script:CapturedCredentialArguments[0] | Should Be '/add:server'
            $script:CapturedCredentialArguments[1] | Should Be '/user:domain\test'
            $script:CapturedCredentialArguments[2] | Should Be ('/pass:' + $password)
            Set-AutoMapCredentialTarget -ServerTarget '\\server' -Username 'domain\test' -Password $password | Out-Null
            $script:CapturedCredentialArguments.Count | Should Be 3
            $script:CapturedCredentialArguments[0] | Should Be '/add:\\server'
            $script:CapturedCredentialArguments[1] | Should Be '/user:domain\test'
            $script:CapturedCredentialArguments[2] | Should Be ('/pass:' + $password)
        }

        It "stops and removes a timed-out mapping job" {
            $script:StoppedJob = $null
            $script:RemovedJob = $null
            function Start-Job { param($ScriptBlock, $ArgumentList) return 'test-job' }
            function Wait-Job { param($Job, $Timeout) return $null }
            function Stop-Job { [CmdletBinding()] param($Job) $script:StoppedJob = $Job }
            function Remove-Job { param($Job, [switch]$Force) $script:RemovedJob = $Job }
            $result = Invoke-NetUseWithCredential -DriveLetter Z -SharePath '\\server\share' -Username test -Password synthetic -PersistentFlag '/PERSISTENT:NO' -TimeoutSeconds 1
            $result.ExitCode | Should Be 1460
            $script:StoppedJob | Should Be 'test-job'
            $script:RemovedJob | Should Be 'test-job'
        }
    }

    Context "Mapping reliability contract" {
        It "refreshes persistent credentials without deleting them or blocking explicit mapping" {
            Mock Get-PreferenceValue { if ($Name -eq 'PersistentMapping') { return $true }; return $Default }
            Mock Test-DrivePath { return $false }
            Mock Test-ShareOnline { return $true }
            Mock Invoke-CmdKeyAdd { return [PSCustomObject]@{ ExitCode = 1; Output = 'synthetic failure' } }
            Mock Invoke-CmdKeyDelete { throw 'Must not delete credentials during connect' }
            Mock Invoke-CmdKeyList { throw 'Must not infer password freshness from username' }
            Mock Invoke-NetUseWithCredential { return [PSCustomObject]@{ ExitCode = 0; Output = '' } }
            Mock Set-MappedDriveLabel { }
            Mock Install-LogonScript { }
            Mock Write-ActionLog { }
            $credential = New-Object System.Management.Automation.PSCredential('test-user', (ConvertTo-SecureString 'synthetic-new-password' -AsPlainText -Force))
            $result = Connect-NetworkShare -DriveLetter Z -SharePath '\\srv\docs' -Credential $credential -Silent -ReturnStatus
            $result.Success | Should Be $true
            Assert-MockCalled Invoke-CmdKeyAdd -Times 2 -Exactly -Scope It -ParameterFilter { $Password -eq 'synthetic-new-password' }
            Assert-MockCalled Invoke-NetUseWithCredential -Times 1 -Exactly -Scope It -ParameterFilter { $Username -eq 'test-user' -and $Password -eq 'synthetic-new-password' }
            Assert-MockCalled Invoke-CmdKeyDelete -Times 0 -Exactly -Scope It
        }

        It "creates both bare-server and UNC credential targets" {
            $targets = @(Get-CredentialTargetsForSharePath -SharePath '\\srv\docs')

            ($targets -contains 'srv') | Should Be $true
            ($targets -contains '\\srv') | Should Be $true
        }

        It "always passes supplied credentials to net use" {
            $connectText = (Get-Command Connect-NetworkShare).ScriptBlock.ToString()
            $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $wrapperText = $sourceAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-NetUseWithCredential' }, $true).Extent.Text

            $connectText | Should Match 'Invoke-NetUseWithCredential'
            $connectText | Should Match '-Username \$user'
            $connectText | Should Match '-Password \$plainPassword'
            $wrapperText | Should Match 'net use "\$drive`:\" \$share /USER:\$username \$password \$flag'
        }

        It "uses cmdkey only for persistent mappings" {
            $functionText = (Get-Command Connect-NetworkShare).ScriptBlock.ToString()
            $persistentBlock = [regex]::Match($functionText, 'if \(\$persistent\) \{(?s).*?\n        \}\r?\n        \r?\n        \$netUseTimeout')

            $persistentBlock.Success | Should Be $true
            $persistentBlock.Value | Should Match 'Invoke-CmdKey'

            $outsidePersistentBlock = $functionText.Remove($persistentBlock.Index, $persistentBlock.Length)
            $outsidePersistentBlock | Should Not Match 'Invoke-CmdKey'
            $outsidePersistentBlock | Should Not Match 'cmdkey'
        }
    }

    Context "CLI disconnect reliability" {
        It "dispatches Disconnect All even when no share appears connected" {
            $cliAst = (Get-Command Start-CliMode).ScriptBlock.Ast
            $switchAst = $cliAst.Find({ param($node) $node -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
            $disconnectClause = @($switchAst.Clauses | Where-Object { $_.Item1.Value -eq 'D' })[0].Item2
            Mock Disconnect-AllSharesCli { }
            function Test-ShareConnection { return $false }
            & ([scriptblock]::Create($disconnectClause.Extent.Text.TrimStart('{').TrimEnd('}')))
            Assert-MockCalled Disconnect-AllSharesCli -Times 1 -Exactly -Scope It
        }

        It "detects mappings visible to net use when Test-Path cannot see the drive" {
            Mock Test-DrivePath { return $false }
            Mock Invoke-NetUseQuery { return "Status       OK`r`nRemote name  \\srv\docs`r`n" }

            (Test-ShareConnection -DriveLetter 'Z') | Should Be $true
        }

        It "treats unavailable red-X mappings as disconnected" {
            Mock Test-DrivePath { return $false }
            Mock Invoke-NetUseQuery { return "Unavailable  Z:  \\srv\docs  Microsoft Windows Network`r`nRemote name  \\srv\docs`r`n" }

            (Test-ShareConnection -DriveLetter 'Z') | Should Be $false
        }

        It "returns success when disconnecting a mapping visible only to net use" {
            Mock Test-ShareConnection { return $true }
            Mock Invoke-NetUseDelete { return 0 }
            Mock Remove-LogonScript { }

            $result = Disconnect-NetworkShare -DriveLetter 'Z' -Silent -ReturnStatus

            $result.Success | Should Be $true
        }

        It "attempts disconnect even when connection detection misses the mapping" {
            Mock Test-ShareConnection { return $false }
            Mock Invoke-NetUseDelete { return [PSCustomObject]@{ ExitCode = 0; Output = "" } }
            Mock Remove-LogonScript { }

            $result = Disconnect-NetworkShare -DriveLetter 'Z' -Silent -ReturnStatus

            $result.Success | Should Be $true
        }

        It "reports not mapped when delete fails and no mapping remains detectable" {
            Mock Test-ShareConnection { return $false }
            Mock Invoke-NetUseDelete { return [PSCustomObject]@{ ExitCode = 2; Output = "The network connection could not be found." } }

            $result = Disconnect-NetworkShare -DriveLetter 'Z' -Silent -ReturnStatus

            $result.Success | Should Be $false
            $result.ErrorType | Should Be "NotMapped"
        }
    }

    Context "GUI bulk operation feedback" {
        It "updates progress while connecting all shares" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'Connect All \(\$index/\$shareCount\): mapping'
            $scriptText | Should Match 'Connect-NetworkShare[\s\S]+-ReturnStatus[\s\S]+-Silent'
            $scriptText | Should Match 'Set-GuiBulkOperationState -InProgress \$true'
        }

        It "reports not-mapped disconnect results separately" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'Disconnect All \(\$index/\$shareCount\): disconnecting'
            $scriptText | Should Match '\$disconnectResult\.ErrorType -eq "NotMapped"'
            $scriptText | Should Match 'not mapped, \$failed failed'
        }

        It "updates progress for manual GUI connect and disconnect" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'Checking connection state for: \$shareName'
            $scriptText | Should Match 'Mapping \$shareName to \$\(\$share\.DriveLetter\):'
            $scriptText | Should Match 'Disconnecting \$shareName from \$\(\$share\.DriveLetter\):'
        }
    }

    Context "CLI feedback improvements" {
        It "uses return status and timeout details for CLI Connect All" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match '\(\$index/\$\(\$shares\.Count\)\) \$shareName'
            $scriptText | Should Match 'timeout \$\{netUseTimeout\}s'
            $scriptText | Should Match 'Connect-NetworkShare[\s\S]+-ReturnStatus[\s\S]+-Silent'
        }

        It "lets single-share CLI disconnect attempt configured drive letters" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'Configured Shares:'
            $scriptText | Should Match 'not detected'
            $scriptText | Should Match 'Disconnect-NetworkShare -DriveLetter \$share\.DriveLetter -ReturnStatus'
        }
    }

    Context "Persistent AutoMap script" {
        It "uses the configured net use timeout and structured wrapper" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'function Invoke-AutoMapNetUseMap'
            $scriptText | Should Match '\$cfg\.Preferences\.PSObject\.Properties\[''NetUseTimeoutSeconds''\]'
            $scriptText | Should Match 'Wait-Job -Job \$job -Timeout \$TimeoutSeconds'
            $scriptText | Should Match 'Mapping attempt \$\{i\}: \$drive -> \$share \(\$name, timeout \$\{netUseTimeoutSeconds\}s\)'
        }

        It "does not map through cmd.exe with interpolated passwords" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Not Match 'cmd /c "net use `"\$drive`" `"\$share`" /user:\$user \$plainPW'
            $scriptText | Should Match 'net use \$drive \$share /USER:\$username \$password /PERSISTENT:YES'
        }

        It "frees SecureString BSTR memory after plaintext extraction" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'function Convert-SecureStringToPlainText'
            $scriptText | Should Match 'ZeroFreeBSTR\(\$bstrPtr\)'
        }

        It "prepares Windows credential targets before persistent mapping" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'function Get-AutoMapCredentialTargets'
            $scriptText | Should Match 'function Set-AutoMapCredentialTarget'
            $scriptText | Should Not Match 'cmdkey /delete:\$ServerTarget'
            $scriptText | Should Match "'/add:' \+ \`$ServerTarget"
            $scriptText | Should Match 'foreach \(\$credentialTarget in @\(Get-AutoMapCredentialTargets -SharePath \$share\)\)'
            $scriptText | Should Match 'Set-AutoMapCredentialTarget -ServerTarget \$credentialTarget -Username \$user -Password \$plainPW'
        }

        It "logs active SMB sessions when Windows reports credential conflicts" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'function Get-AutoMapServerConnections'
            $scriptText | Should Match '\$errorType -eq "MultipleConnections"'
            $scriptText | Should Match 'Existing SMB sessions may need to be disconnected'
        }

        It "repairs red-X unavailable SMB mappings before remapping" {
            $scriptText = Get-Content -Path $script:ScriptPath -Raw

            $scriptText | Should Match 'function Repair-AutoMapUnavailableSmbMapping'
            $scriptText | Should Match '\[string\]\$mapping\.Status -ne ''Unavailable'''
            $scriptText | Should Match 'New-SmbMapping -LocalPath \$Drive -RemotePath \$Share'
            $scriptText | Should Match 'Repair-AutoMapUnavailableSmbMapping -Drive \$drive -Share \$share -Username \$user -Password \$plainPW -Name \$name'
        }
    }

    Context "Stable release updater" {
        BeforeEach {
            $script:UpdateTarget = Join-Path $script:TestRoot 'updater-target.ps1'
            $script:UpdateDownload = Join-Path $script:TestRoot 'updater-download.ps1'
            $script:OldUpdateContent = '$version = ''2.4.0''; function Connect-NetworkShare {}; function Start-CliMode {}; function Show-GUI {}'
            $script:NewUpdateContent = $script:OldUpdateContent.Replace('2.4.0', '2.4.1')
            [IO.File]::WriteAllText($script:UpdateTarget, $script:OldUpdateContent)
            [IO.File]::WriteAllText($script:UpdateDownload, $script:NewUpdateContent)
            $script:RawRelease = [PSCustomObject]@{
                tag_name = 'V2.4.1'; draft = $false; prerelease = $false
                assets = @([PSCustomObject]@{
                    name = 'Share_Manager.ps1'; state = 'uploaded'
                    digest = 'sha256:' + (Get-FileHash -LiteralPath $script:UpdateDownload -Algorithm SHA256).Hash
                    size = (Get-Item -LiteralPath $script:UpdateDownload).Length
                    browser_download_url = 'https://github.com/Dantdmnl/Share_Manager/releases/download/V2.4.1/Share_Manager.ps1'
                })
            }
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $script:UpdateDownload -Destination $OutFile }
        }

        It "accepts a stable release and compares versions numerically" {
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            $release.Version | Should Be '2.4.1'
            ([version]'2.10.0' -gt [version]$release.Version) | Should Be $true
        }

        It "rejects prereleases and unsupported tags" {
            $script:RawRelease.prerelease = $true
            { ConvertTo-ShareManagerReleaseInfo $script:RawRelease } | Should Throw
            $script:RawRelease.prerelease = $false
            $script:RawRelease.tag_name = 'V2.4.1-preview'
            { ConvertTo-ShareManagerReleaseInfo $script:RawRelease } | Should Throw
        }

        It "rejects missing digests, foreign URLs, and duplicate assets" {
            $originalDigest = $script:RawRelease.assets[0].digest
            $script:RawRelease.assets[0].digest = $null
            { ConvertTo-ShareManagerReleaseInfo $script:RawRelease } | Should Throw
            $script:RawRelease.assets[0].digest = $originalDigest
            $script:RawRelease.assets[0].browser_download_url = 'https://example.com/Share_Manager.ps1'
            { ConvertTo-ShareManagerReleaseInfo $script:RawRelease } | Should Throw
            $script:RawRelease.assets += $script:RawRelease.assets[0]
            { ConvertTo-ShareManagerReleaseInfo $script:RawRelease } | Should Throw
        }

        It "installs verified bytes and retains an exact backup" {
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            $installed = Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be $script:NewUpdateContent
            [IO.File]::ReadAllText($installed.BackupPath) | Should Be $script:OldUpdateContent
            @(Get-ChildItem -LiteralPath $script:TestRoot -Filter '*.update.ps1' -Force).Count | Should Be 0
        }

        It "keeps the original script after download failure" {
            Mock Invoke-WebRequest { throw 'synthetic network failure' }
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be $script:OldUpdateContent
        }

        It "rejects corrupted bytes without replacing the script" {
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            [IO.File]::WriteAllText($script:UpdateDownload, $script:NewUpdateContent.Replace('2.4.1', '9.9.9'))
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be $script:OldUpdateContent
            @(Get-ChildItem -LiteralPath $script:TestRoot -Filter '*.update.ps1' -Force).Count | Should Be 0
        }

        It "rejects truncated downloads before replacing the script" {
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            [IO.File]::WriteAllText($script:UpdateDownload, 'truncated')
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be $script:OldUpdateContent
            Assert-MockCalled Invoke-WebRequest -Times 1 -Exactly -Scope It
        }

        It "keeps the original when verified bytes contain invalid syntax" {
            [IO.File]::WriteAllText($script:UpdateDownload, 'function {')
            $script:RawRelease.assets[0].digest = 'sha256:' + (Get-FileHash -LiteralPath $script:UpdateDownload -Algorithm SHA256).Hash
            $script:RawRelease.assets[0].size = (Get-Item -LiteralPath $script:UpdateDownload).Length
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be $script:OldUpdateContent
            Assert-MockCalled Invoke-WebRequest -Times 1 -Exactly -Scope It
        }

        It "rejects a valid checksum when the script version disagrees with the tag" {
            [IO.File]::WriteAllText($script:UpdateDownload, $script:NewUpdateContent.Replace('2.4.1', '2.4.2'))
            $script:RawRelease.assets[0].digest = 'sha256:' + (Get-FileHash -LiteralPath $script:UpdateDownload -Algorithm SHA256).Hash
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be $script:OldUpdateContent
        }

        It "rejects scripts with parser errors or missing application functions" {
            [IO.File]::WriteAllText($script:UpdateDownload, 'function {')
            { Get-ShareManagerScriptVersion -Path $script:UpdateDownload } | Should Throw
            [IO.File]::WriteAllText($script:UpdateDownload, '$version = ''2.4.1''')
            { Get-ShareManagerScriptVersion -Path $script:UpdateDownload } | Should Throw
        }

        It "refuses repeat installs and downgrades before downloading" {
            [IO.File]::WriteAllText($script:UpdateTarget, $script:NewUpdateContent)
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::WriteAllText($script:UpdateTarget, $script:NewUpdateContent.Replace('2.4.1', '2.5.0'))
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
        }

        It "preserves local edits made during the download" {
            Mock Invoke-WebRequest {
                Copy-Item -LiteralPath $script:UpdateDownload -Destination $OutFile
                [IO.File]::WriteAllText($script:UpdateTarget, '# concurrent edit')
            }
            $release = ConvertTo-ShareManagerReleaseInfo $script:RawRelease
            { Install-ShareManagerUpdate -Release $release -CurrentScriptPath $script:UpdateTarget } | Should Throw
            [IO.File]::ReadAllText($script:UpdateTarget) | Should Be '# concurrent edit'
        }

        It "does not install after the user declines" {
            Mock Invoke-ShareManagerUpdateTask { return [PSCustomObject]@{ Version = '99.0.0'; ReleaseUrl = 'https://github.com/Dantdmnl/Share_Manager/releases' } }
            Mock Read-Host { return 'n' }
            Mock Write-Host { }
            Update-ShareManager
            Assert-MockCalled Invoke-ShareManagerUpdateTask -Times 0 -Exactly -Scope It -ParameterFilter { $Operation -eq 'Install' }
        }
    }

    Context "Release CLI presentation" {
        BeforeEach {
            $script:MenuOutput = ''
            Mock Clear-Host { }
            Mock Write-Host {
                $script:MenuOutput += [string]$Object
                if (-not $NoNewline) { $script:MenuOutput += "`n" }
            }
            Mock Test-ShareConnection { return $DriveLetter -eq 'X' }
        }

        It "counts enabled disconnected shares and puts Updates before Quit" {
            Mock Get-ShareConfiguration {
                return @(
                    [PSCustomObject]@{ DriveLetter = 'X'; Enabled = $true },
                    [PSCustomObject]@{ DriveLetter = 'Y'; Enabled = $true },
                    [PSCustomObject]@{ DriveLetter = 'Z'; Enabled = $false }
                )
            }
            Show-CLI-Menu
            $script:MenuOutput | Should Match 'SHARE MANAGER v2\.5\.0'
            $script:MenuOutput | Should Match 'Connect All \(1 disconnected\)'
            $script:MenuOutput | Should Match 'U - Updates'
            ($script:MenuOutput.IndexOf('U - Updates') -lt $script:MenuOutput.IndexOf('Quit')) | Should Be $true
        }

        It "does not suggest connecting disabled shares" {
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ DriveLetter = 'Z'; Enabled = $false } }
            Show-CLI-Menu
            $script:MenuOutput | Should Match 'no enabled shares'
            $script:MenuOutput | Should Match 'Disconnect All'
            $script:MenuOutput | Should Not Match '\d+ disconnected'
        }

        It "shows Add Share only once for an empty configuration" {
            Mock Get-ShareConfiguration { return @() }
            Show-CLI-Menu
            ([regex]::Matches($script:MenuOutput, '1 - Add')).Count | Should Be 1
        }
    }

    Context "Credential diagnostics" {
        It "reports configured same-server username conflicts" {
            $config = [PSCustomObject]@{
                Shares = @(
                    (New-ShareEntry -Name 'One' -SharePath '\\srv\one' -DriveLetter 'O' -Username 'DOMAIN\one'),
                    (New-ShareEntry -Name 'Two' -SharePath '\\srv\two' -DriveLetter 'T' -Username 'DOMAIN\two')
                )
                Preferences = (New-TestPreferences)
            }
            (Save-AllShares -Config $config) | Should Be $true

            $diagnostics = @(Get-ShareCredentialDiagnostics)

            $diagnostics.Count | Should Be 1
            $diagnostics[0].Issue | Should Be 'MultipleConfiguredUsernames'
        }
    }

    Context "Import-ShareConfiguration merge behavior" {
        It "returns Updated and Skipped counts for duplicate merge entries" {
            $config = [PSCustomObject]@{
                Shares = @(
                    (New-ShareEntry -Name 'Docs' -SharePath '\\srv\docs' -DriveLetter 'Z' -Username 'DOMAIN\user')
                )
                Preferences = (New-TestPreferences)
            }
            (Save-AllShares -Config $config) | Should Be $true

            $importPath = Join-Path $baseFolder 'import_merge.json'
            $importData = [PSCustomObject]@{
                Shares = @(
                    [PSCustomObject]@{
                        Id = [Guid]::NewGuid().ToString()
                        Name = 'Docs Updated'
                        SharePath = '\\srv\docs'
                        DriveLetter = 'Y'
                        Username = 'DOMAIN\user2'
                        Description = 'Updated by merge'
                        Enabled = $true
                        Category = 'Work'
                        IsFavorite = $true
                    }
                )
                Preferences = (New-TestPreferences)
            }
            $importData | ConvertTo-Json -Depth 10 | Set-Content -Path $importPath -Encoding UTF8

            $result = Import-ShareConfiguration -ImportPath $importPath -Merge $true
            $result.Success | Should Be $true
            $result.Skipped | Should Be 1
            $result.Updated | Should Be 1
            $result.Added | Should Be 0
        }

        It "handles multiple existing matches without throwing" {
            $config = [PSCustomObject]@{
                Shares = @(
                    (New-ShareEntry -Name 'One' -SharePath '\\srv\one' -DriveLetter 'Z' -Username 'DOMAIN\user1'),
                    (New-ShareEntry -Name 'Two' -SharePath '\\srv\two' -DriveLetter 'Z' -Username 'DOMAIN\user2')
                )
                Preferences = (New-TestPreferences)
            }
            (Save-AllShares -Config $config) | Should Be $true

            $importPath = Join-Path $baseFolder 'import_multimatch.json'
            $importData = [PSCustomObject]@{
                Shares = @(
                    [PSCustomObject]@{
                        Id = [Guid]::NewGuid().ToString()
                        Name = 'Three'
                        SharePath = '\\srv\three'
                        DriveLetter = 'Z'
                        Username = 'DOMAIN\user3'
                        Description = 'Should update first match only'
                        Enabled = $true
                    }
                )
                Preferences = (New-TestPreferences)
            }
            $importData | ConvertTo-Json -Depth 10 | Set-Content -Path $importPath -Encoding UTF8

            { Import-ShareConfiguration -ImportPath $importPath -Merge $true | Out-Null } | Should Not Throw
            $result = Import-ShareConfiguration -ImportPath $importPath -Merge $true
            $result.Success | Should Be $true
            $result.Updated | Should Be 1
        }
    }
}
