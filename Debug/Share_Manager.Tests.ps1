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

            $scriptText | Should Match 'function Get-AutoMapSmbMapping'
            $scriptText | Should Match 'New-SmbMapping -LocalPath \$Drive -RemotePath \$Share'
            $scriptText | Should Match 'Reconnect in place first'
        }
    }

    Context "Friendly GUI network path entry" {
        It "trims pasted whitespace and matching surrounding quotes" {
            (ConvertTo-UncPathInput -Path '  "\\server\share"  ').Path | Should Be '\\server\share'
            (ConvertTo-UncPathInput -Path "  '\\server\share'  ").Path | Should Be '\\server\share'
        }
        It "suggests the malformed server prefix without silently changing it" {
            $result = ConvertTo-UncPathInput -Path '\\`\192.168.1.2\backup'
            $result.Path | Should Be '\\`\192.168.1.2\backup'
            $result.Suggestion | Should Be '\\192.168.1.2\backup'
        }
        It "preserves backticks inside share and folder names" {
            $result = ConvertTo-UncPathInput -Path '\\server\back`up\folder`name'
            $result.Path | Should Be '\\server\back`up\folder`name'
            $result.Suggestion | Should BeNullOrEmpty
        }
        It "supports omitted UNC prefixes and leaves empty input invalid" {
            (ConvertTo-UncPathInput -Path 'server\share').Path | Should Be '\\server\share'
            (Test-ValidUncPath -Path (ConvertTo-UncPathInput -Path ' ').Path) | Should Be $false
        }
    }

    Context "Shared share credential workflow" {
        BeforeEach {
            function Get-ShareConfiguration { return @([PSCustomObject]@{ Name = 'Other share'; Username = 'test' }) }
            function Write-Host { param($Object, $ForegroundColor) }
            function Get-CredentialForShare { param($Username) return (New-Object System.Management.Automation.PSCredential('test', (ConvertTo-SecureString synthetic -AsPlainText -Force))) }
            function Save-Credential { param($Credential, [switch]$PassThru) $script:CredentialWrites++; return $true }
            $script:CredentialWrites = 0
        }
        It "reuses a saved credential without writing or prompting for a password" {
            function Read-Host { param($Prompt) return '' }
            function Read-Password { param($Prompt) throw 'Unexpected password prompt' }
            (Confirm-ShareCredential -Username test) | Should Be $true
            $script:CredentialWrites | Should Be 0
        }
        It "cancels without writing credentials" {
            function Read-Host { param($Prompt) return 'C' }
            (Confirm-ShareCredential -Username test) | Should Be $false
            $script:CredentialWrites | Should Be 0
        }

        It "keeps unchanged credentials without asking any questions" {
            function Read-Host { param($Prompt) throw 'Unexpected prompt' }
            (Confirm-ShareCredential -Username test -KeepExisting) | Should Be $true
            $script:CredentialWrites | Should Be 0
        }

        It "requires confirmation for an explicit password replacement" {
            function Read-Host { param($Prompt) return 'N' }
            function Read-Password { param($Prompt) throw 'Unexpected password capture' }
            (Confirm-ShareCredential -Username test -KeepExisting -ReplaceExisting) | Should Be $false
            $script:CredentialWrites | Should Be 0
        }

        It "goes directly to password entry when only the edited share uses it" {
            function Get-ShareConfiguration { return @([PSCustomObject]@{ Id = 'current'; Name = 'Test'; Username = 'test' }) }
            function Read-Host { param($Prompt) throw 'Unnecessary confirmation' }
            function Read-Password { param($Prompt) return (ConvertTo-SecureString replacement -AsPlainText -Force) }
            (Confirm-ShareCredential -Username test -ReplaceExisting -ShareId current) | Should Be $true
            $script:CredentialWrites | Should Be 1
        }

        It "continues editing with the existing password after empty replacement input" {
            function Get-ShareConfiguration { return @() }
            function Read-Password { param($Prompt) return (New-Object System.Security.SecureString) }
            (Confirm-ShareCredential -Username test -ReplaceExisting -ShareId current) | Should Be $true
            $script:CredentialWrites | Should Be 0
        }

        It "does not accept empty input when no saved credential exists" {
            function Get-CredentialForShare { param($Username) return $null }
            function Get-ShareConfiguration { return @() }
            function Read-Password { param($Prompt) return (New-Object System.Security.SecureString) }
            (Confirm-ShareCredential -Username test -ReplaceExisting -ShareId current) | Should Be $false
            $script:CredentialWrites | Should Be 0
        }

        It "still captures missing credentials when keeping the username" {
            function Get-CredentialForShare { param($Username) return $null }
            function Get-ShareConfiguration { return @() }
            function Read-Password { param($Prompt) return (ConvertTo-SecureString synthetic -AsPlainText -Force) }
            (Confirm-ShareCredential -Username test -KeepExisting) | Should Be $true
            $script:CredentialWrites | Should Be 1
        }
        It "replaces a credential only after the explicit update choice" {
            function Read-Host { param($Prompt) return 'U' }
            function Read-Password { param($Prompt) return (ConvertTo-SecureString replacement -AsPlainText -Force) }
            (Confirm-ShareCredential -Username test) | Should Be $true
            $script:CredentialWrites | Should Be 1
        }
        It "propagates a credential save failure" {
            function Read-Host { param($Prompt) return 'U' }
            function Read-Password { param($Prompt) return (ConvertTo-SecureString replacement -AsPlainText -Force) }
            function Save-Credential { param($Credential, [switch]$PassThru) return $false }
            (Confirm-ShareCredential -Username test) | Should Be $false
        }
    }

    Context "Conservative data cleanup" {
        BeforeEach {
            $cleanupFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $cleanupFolder | Out-Null
            foreach ($name in @('Share_Manager_2020-01-01_000000.log', 'Share_Manager_2020-02-01_000000.log', 'Share_Manager_2020-03-01_000000.log', 'shares_preimport_20200101_000000.json', 'creds.json', 'Share_Manager.log', 'unknown.log')) {
                $path = Join-Path $cleanupFolder $name
                Set-Content -LiteralPath $path -Value 'fixture'
                (Get-Item -LiteralPath $path).LastWriteTime = [datetime]'2020-01-01'
            }
        }
        It "previews only old recognized archives while retaining the newest two" {
            $result = @(Invoke-DataCleanup -Folder $cleanupFolder)
            $result.Count | Should Be 1
            $result[0].Name | Should Be 'Share_Manager_2020-01-01_000000.log'
            $result[0].Status | Should Be 'Preview'
            @(Get-ChildItem -LiteralPath $cleanupFolder).Count | Should Be 7
        }
        It "deletes only eligible archives on explicit apply" {
            $result = @(Invoke-DataCleanup -Folder $cleanupFolder -Apply -Confirm:$false)
            $result[0].Status | Should Be 'Removed'
            @(Get-ChildItem -LiteralPath $cleanupFolder).Count | Should Be 6
            (Test-Path -LiteralPath (Join-Path $cleanupFolder 'creds.json')) | Should Be $true
            (Test-Path -LiteralPath (Join-Path $cleanupFolder 'shares_preimport_20200101_000000.json')) | Should Be $true
        }
        It "honors WhatIf and preserves recently modified archives" {
            Invoke-DataCleanup -Folder $cleanupFolder -Apply -WhatIf | Out-Null
            @(Get-ChildItem -LiteralPath $cleanupFolder).Count | Should Be 7
            (Get-Item -LiteralPath (Join-Path $cleanupFolder 'Share_Manager_2020-01-01_000000.log')).LastWriteTime = Get-Date
            @(Get-DataCleanupCandidates -Folder $cleanupFolder).Count | Should Be 0
        }
    }

    Context "Automatic startup cleanup" {
        It "applies cleanup without prompting and logs the result" {
            function Invoke-DataCleanup {
                [CmdletBinding(SupportsShouldProcess)] param([switch]$Apply, $CurrentScriptPath)
                $Apply.IsPresent | Should Be $true
                $PSBoundParameters['Confirm'] | Should Be $false
                return [PSCustomObject]@{ Status = 'Removed' }
            }
            function Write-ActionLog { param($Message, $Level, $Category) $script:CleanupMessage = $Message }
            Invoke-StartupDataCleanup
            $script:CleanupMessage | Should Match '1 removed, 0 failed'
        }
        It "does not stop startup when cleanup or logging fails" {
            function Invoke-DataCleanup { [CmdletBinding(SupportsShouldProcess)] param([switch]$Apply, $CurrentScriptPath) throw 'Synthetic access denied' }
            function Write-ActionLog { param($Message, $Level, $Category) throw 'Synthetic log failure' }
            { Invoke-StartupDataCleanup } | Should Not Throw
        }
    }

    Context "Updater backup retention" {
        BeforeEach {
            $backupFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $backupFolder | Out-Null
            $targetScript = Join-Path $backupFolder 'Custom Manager.ps1'
            Set-Content -LiteralPath $targetScript -Value '# fixture'
            $oldBackup = $null
            foreach ($stamp in @('20200101-000000', '20200201-000000', '20200301-000000')) {
                $path = $targetScript + '.' + $stamp + '.' + [guid]::NewGuid().ToString('N') + '.bak'
                Set-Content -LiteralPath $path -Value 'backup'
                (Get-Item -LiteralPath $path).LastWriteTime = [datetime]'2020-01-01'
                if (-not $oldBackup) { $oldBackup = $path }
            }
            Set-Content -LiteralPath ($targetScript + '.bak') -Value 'manual backup'
            Set-Content -LiteralPath (Join-Path $backupFolder 'Other.ps1.20200101-000000.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bak') -Value 'other script'
        }
        It "previews exact updater backups without touching manual or other-script backups" {
            $result = @(Invoke-DataCleanup -Folder $backupFolder -CurrentScriptPath $targetScript)
            $result.Count | Should Be 1
            $result[0].Status | Should Be 'Preview'
            (Test-Path -LiteralPath $oldBackup) | Should Be $true
        }
        It "keeps two rollback backups on apply and honors WhatIf" {
            Invoke-DataCleanup -Folder $backupFolder -CurrentScriptPath $targetScript -Apply -WhatIf | Out-Null
            (Test-Path -LiteralPath $oldBackup) | Should Be $true
            Invoke-DataCleanup -Folder $backupFolder -CurrentScriptPath $targetScript -Apply -Confirm:$false | Out-Null
            (Test-Path -LiteralPath $oldBackup) | Should Be $false
            @(Get-ChildItem -LiteralPath $backupFolder).Count | Should Be 5
        }
        It "preserves recently modified backups despite old filename timestamps" {
            (Get-Item -LiteralPath $oldBackup).LastWriteTime = Get-Date
            @(Get-UpdateBackupCleanupCandidates -CurrentScriptPath $targetScript).Count | Should Be 0
        }
    }

    Context "Category suggestions" {
        It "offers starter categories without creating empty filters" {
            function Get-CachedConfig { return [PSCustomObject]@{ Shares = @() } }
            @(Get-ShareCategories -IncludeSuggestions).Count | Should Be 6
            @(Get-ShareCategories).Count | Should Be 1
        }
        It "preserves custom categories without duplicating defaults" {
            function Get-CachedConfig { return [PSCustomObject]@{ Shares = @([PSCustomObject]@{ Category = 'home' }, [PSCustomObject]@{ Category = 'Archive' }) } }
            $categories = @(Get-ShareCategories -IncludeSuggestions)
            $categories.Count | Should Be 7
            ($categories -contains 'Archive') | Should Be $true
            @($categories | Where-Object { $_ -eq 'Home' }).Count | Should Be 1
        }
    }

    Context "First-time setup save failures" {
        It "stops CLI setup when preferences cannot be saved" {
            function Set-TerminalBlackBackground { param([switch]$Refresh) }
            function Read-Host { param($Prompt) return '' }
            function Write-Host { param($Object, $ForegroundColor) }
            function Import-AllShares { return (New-DefaultSharesConfig) }
            function Get-CachedConfig { return (New-DefaultSharesConfig) }
            function Save-AllShares { param($Config) return $false }
            function Clear-ConfigCache { $script:SetupCacheCleared = $true }
            $script:SetupCacheCleared = $false
            $result = Initialize-Config-CLI
            $result | Should Be $false
            $script:SetupCacheCleared | Should Be $true
        }

        It "reports failed replacement and preserves the previous configuration" {
            $sharesPath = Join-Path $TestDrive 'failed-save.json'
            $UseGUI = $false
            $original = '{"Shares":[],"marker":"original"}'
            Set-Content -LiteralPath $sharesPath -Value $original
            function Move-Item {
                [CmdletBinding()] param($LiteralPath, $Destination, [switch]$Force)
                Write-Error 'Synthetic replacement failure'
            }
            function Write-ActionLog { param($Message, $Level, $Category, $Data) }
            (Save-AllShares -Config (New-DefaultSharesConfig)) | Should Be $false
            (Get-Content -LiteralPath $sharesPath -Raw).Trim() | Should Be $original
            (Test-Path -LiteralPath "$sharesPath.tmp") | Should Be $false
        }
    }

    Context "AutoMap authentication and access" {
        BeforeEach {
            $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $autoSource = $sourceAst.Find({ param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*function Set-AutoMapCredentialTarget*' }, $true).Value
            $autoErrors = $null
            $autoAst = [System.Management.Automation.Language.Parser]::ParseInput($autoSource, [ref]$null, [ref]$autoErrors)
            $autoErrors.Count | Should Be 0
            foreach ($definition in @($autoAst.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })) {
                . ([scriptblock]::Create($definition.Extent.Text))
            }
            $loop = $autoAst.Find({ param($node) $node -is [System.Management.Automation.Language.ForEachStatementAst] -and $node.Extent.Text -like 'foreach ($s in $cfg.Shares)*' }, $true)
            $script:AutoLoop = [scriptblock]::Create($loop.Extent.Text)
            $script:NativeCalls = 0
            $script:FallbackCalls = 0
            $script:DeletedMappings = 0
            $script:MapCalls = 0
            $script:WorkerResult = $null
            function Start-Job { param($ScriptBlock, $ArgumentList) $workerArguments = @($ArgumentList); $script:WorkerResult = & $ScriptBlock @workerArguments; return 'synthetic-job' }
            function Wait-Job { param($Job, $Timeout) return $Job }
            function Receive-Job { [CmdletBinding()] param($Job) return $script:WorkerResult }
            function Stop-Job { [CmdletBinding()] param($Job) }
            function Remove-Job { [CmdletBinding()] param($Job, [switch]$Force) }
            function net { $script:FallbackCalls++; $global:LASTEXITCODE = 0 }
            function New-SmbMapping {
                [CmdletBinding()] param($LocalPath, $RemotePath, $UserName, $Password, $Persistent, [switch]$SaveCredentials)
                $script:NativeCalls++
                $script:NativePassword = $Password
                $script:NativeSaved = $SaveCredentials.IsPresent
            }
            function Write-Log { param($Message, $Level, $Category, $Data) }
            function Get-AutoMapLocalDrive { param($Drive) return $null }
            function Get-AutoMapSmbMapping { param($Drive) return $null }
            function Invoke-AutoMapNetUseQuery { param($Drive, $TimeoutSeconds) return '' }
        }

        It "saves explicitly supplied credentials through the SMB API" {
            $result = Invoke-AutoMapNetUseMap -Drive 'Z:' -Share '\\srv\docs' -Username 'test' -Password 'synthetic "& password' -TimeoutSeconds 5
            $result.ExitCode | Should Be 0
            $script:NativeCalls | Should Be 1
            $script:NativeSaved | Should Be $true
            $script:NativePassword | Should Be 'synthetic "& password'
            $script:FallbackCalls | Should Be 0
        }

        It "uses explicit net use directly when the server credential was prepared" {
            function net { $script:FallbackArguments = @($args); $script:FallbackCalls++; $global:LASTEXITCODE = 0 }
            $result = Invoke-AutoMapNetUseMap -Drive 'Z:' -Share '\\\\srv\docs' -Username test -Password synthetic -TimeoutSeconds 5 -CredentialPrepared $true
            $result.ExitCode | Should Be 0
            $result.Backend | Should Be 'net use'
            $result.SaveErrorCode | Should BeNullOrEmpty
            $script:NativeCalls | Should Be 0
            $script:FallbackCalls | Should Be 1
            ($script:FallbackArguments -contains '/USER:test') | Should Be $true
            ($script:FallbackArguments -contains 'synthetic') | Should Be $true
            ($script:FallbackArguments -contains '/PERSISTENT:YES') | Should Be $true
        }

        It "retains the explicit net use fallback if saving SMB credentials fails" {
            function New-SmbMapping { [CmdletBinding()] param($LocalPath, $RemotePath, $UserName, $Password, $Persistent, [switch]$SaveCredentials) throw 'Synthetic policy restriction' }
            function net { $script:FallbackArguments = @($args); $script:FallbackCalls++; $global:LASTEXITCODE = 0 }
            $result = Invoke-AutoMapNetUseMap -Drive 'Z:' -Share '\\srv\docs' -Username test -Password synthetic -TimeoutSeconds 5
            $result.ExitCode | Should Be 0
            $script:FallbackCalls | Should Be 1
            ($script:FallbackArguments -contains '/USER:test') | Should Be $true
            ($script:FallbackArguments -contains 'synthetic') | Should Be $true
        }

        It "does not retry rejected SMB credentials through net use" {
            function New-SmbMapping {
                [CmdletBinding()] param($LocalPath, $RemotePath, $UserName, $Password, $Persistent, [switch]$SaveCredentials)
                throw (New-Object System.Runtime.InteropServices.COMException('Synthetic logon failure', -2147023570))
            }
            $result = Invoke-AutoMapNetUseMap -Drive 'Z:' -Share '\\srv\docs' -Username test -Password synthetic -TimeoutSeconds 5
            $result.ExitCode | Should Be 1326
            $script:FallbackCalls | Should Be 0
        }

        It "refuses to switch identities when the configured password is missing" {
            $result = Invoke-AutoMapNetUseMap -Drive 'Z:' -Share '\\srv\docs' -Username test -TimeoutSeconds 5
            $result.ExitCode | Should Be 1326
            $script:NativeCalls | Should Be 0
            $script:FallbackCalls | Should Be 0
        }

        It "records the SMB fallback reason without exposing the password" {
            function New-SmbMapping {
                [CmdletBinding()] param($LocalPath, $RemotePath, $UserName, $Password, $Persistent, [switch]$SaveCredentials)
                throw "Synthetic rejection of $Password"
            }
            $result = Invoke-AutoMapNetUseMap -Drive 'Z:' -Share '\\\\srv\docs' -Username test -Password secret123 -TimeoutSeconds 5
            $result.ExitCode | Should Be 0
            $result.SaveErrorType | Should Not BeNullOrEmpty
            $result.SaveErrorMessage | Should Match '\[REDACTED\]'
            $result.SaveErrorMessage | Should Not Match 'secret123'
        }

        It "checks the drive root literally rather than a remembered mapping entry" {
            function Test-Path { [CmdletBinding()] param($LiteralPath, $PathType) $script:ProbePath = $LiteralPath; return $false }
            (Test-AutoMapDriveAccess -Drive 'Z:' -TimeoutSeconds 5) | Should Be $false
            $script:ProbePath | Should Be 'Z:\'
        }

        It "does not count a successful mapping command as accessible" {
            $cfg = [PSCustomObject]@{ Shares = @([PSCustomObject]@{ Enabled = $true; DriveLetter = 'Z'; SharePath = '\\srv\docs'; Username = 'test'; Name = 'Test' }) }
            $credMap = @{ test = (ConvertTo-SecureString synthetic -AsPlainText -Force) }
            $successCount = 0; $failCount = 0; $skipCount = 0; $netUseTimeoutSeconds = 5
            function Set-AutoMapCredentialTarget { param($ServerTarget, $Username, $Password) return @{ Updated = $true; ExitCode = 0 } }
            function Repair-AutoMapUnavailableSmbMapping { param($Drive, $Share, $Username, $Password, $Name) return $false }
            function Get-AutoMapSmbMapping { param($Drive) return $null }
            function Invoke-AutoMapNetUseQuery { param($Drive) return '' }
            function Invoke-AutoMapNetUseMap { param($Drive, $Share, $Username, $Password, $TimeoutSeconds) $script:MapCalls++; return @{ ExitCode = 0; Output = '' } }
            function Test-AutoMapDriveAccess { param($Drive, $TimeoutSeconds) return $false }
            function Start-Sleep { param($Seconds) }
            . $script:AutoLoop
            $successCount | Should Be 0
            $failCount | Should Be 1
            $script:MapCalls | Should Be 3
        }

        It "attempts the configured share directly and recovers from transient network failures" {
            $autoSource | Should Not Match 'Test-NetworkAvailable|Get-NetIPAddress|Get-NetAdapter|8\.8\.8\.8'
            $cfg = [PSCustomObject]@{ Shares = @([PSCustomObject]@{ Enabled = $true; DriveLetter = 'Z'; SharePath = '\\srv\docs'; Username = 'test'; Name = 'Test' }) }
            $credMap = @{ test = (ConvertTo-SecureString synthetic -AsPlainText -Force) }
            $successCount = 0; $failCount = 0; $skipCount = 0; $netUseTimeoutSeconds = 5
            function Set-AutoMapCredentialTarget { param($ServerTarget, $Username, $Password) return @{ Updated = $true; ExitCode = 0 } }
            function Repair-AutoMapUnavailableSmbMapping { param($Drive, $Share, $Username, $Password, $Name) return $false }
            function Get-AutoMapSmbMapping { param($Drive) return $null }
            function Invoke-AutoMapNetUseQuery { param($Drive) return '' }
            function Invoke-AutoMapNetUseMap {
                param($Drive, $Share, $Username, $Password, $TimeoutSeconds)
                $script:MapCalls++
                if ($script:MapCalls -lt 3) { return @{ ExitCode = 2; Output = 'System error 53' } }
                return @{ ExitCode = 0; Output = '' }
            }
            function Test-AutoMapDriveAccess { param($Drive, $TimeoutSeconds) return $true }
            function Start-Sleep { param($Seconds) }
            . $script:AutoLoop
            $script:MapCalls | Should Be 3
            $successCount | Should Be 1
            $failCount | Should Be 0
        }

        It "leaves existing mappings untouched when credentials cannot be loaded" {
            $cfg = [PSCustomObject]@{ Shares = @([PSCustomObject]@{ Enabled = $true; DriveLetter = 'Z'; SharePath = '\\srv\docs'; Username = 'test'; Name = 'Test' }) }
            $credMap = @{}
            $successCount = 0; $failCount = 0; $skipCount = 0
            function Invoke-AutoMapNetUseDelete { param($Drive) $script:DeletedMappings++ }
            function Invoke-AutoMapNetUseMap { param($Drive, $Share, $Username, $Password, $TimeoutSeconds) $script:MapCalls++ }
            . $script:AutoLoop
            $failCount | Should Be 1
            $script:DeletedMappings | Should Be 0
            $script:MapCalls | Should Be 0
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
            $script:MenuOutput | Should Match ('SHARE MANAGER v' + [regex]::Escape($version))
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
