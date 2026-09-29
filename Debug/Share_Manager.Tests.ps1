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
            (Test-ValidUncPath -Path '\\192.168.1.2\backup') | Should Be $true
        }

        It "rejects invalid UNC paths" {
            (Test-ValidUncPath -Path 'server\share') | Should Be $false
            (Test-ValidUncPath -Path '\\s\share') | Should Be $false
            (Test-ValidUncPath -Path '\\server\') | Should Be $false
            (Test-ValidUncPath -Path '') | Should Be $false
            (Test-ValidUncPath -Path '\\192..168.1.2\backup') | Should Be $false
            (Test-ValidUncPath -Path '\\999.168.1.2\backup') | Should Be $false
        }

        It "suggests a single-dot IPv4 correction without silently applying it" {
            $check = Get-UncPathValidation -Path '\\192.168..1.2\backup'
            $check.Valid | Should Be $false
            $check.Message | Should Match 'consecutive dots'
            $check.Suggestion | Should Be '\\192.168.1.2\backup'
            (Get-UncPathValidation -Path '\\999.168.1.2\backup').Suggestion | Should BeNullOrEmpty
        }

        It "uses a malformed-server suggestion only after CLI confirmation" {
            $script:UncAnswers = @('\\192.168..1.2\backup', 'y')
            $script:UncAnswerIndex = 0
            Mock Read-CliPrompt { $answer = $script:UncAnswers[$script:UncAnswerIndex]; $script:UncAnswerIndex++; return $answer }
            Mock Write-Host { }
            (Read-CliUncPath) | Should Be '\\192.168.1.2\backup'
            $script:UncAnswerIndex | Should Be 2
        }

        It "accepts the suggested correction when Enter selects the default" {
            $script:UncAnswers = @('\\192.168..1.2\backup', '')
            $script:UncAnswerIndex = 0
            Mock Read-CliPrompt { $answer = $script:UncAnswers[$script:UncAnswerIndex]; $script:UncAnswerIndex++; return $answer }
            Mock Write-Host { }
            (Read-CliUncPath) | Should Be '\\192.168.1.2\backup'
            $script:UncAnswerIndex | Should Be 2
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

    Context "GUI console handoff" {
        It "hides a dedicated console instead of leaving a minimized taskbar button" {
            $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $handoff = $sourceAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Hide-ConsoleWindow' }, $true)
            $handoff.Extent.Text | Should Match 'GetConsoleProcessList'
            $handoff.Extent.Text | Should Match 'GetConsoleProcessList\(\$consoleProcesses, \$consoleProcesses.Length\) -ne 1'
            $handoff.Extent.Text | Should Match 'ShowWindow\(\$hWnd, 0\)'
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
        It "stops CLI setup when its initial state cannot be saved" {
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

    Context "First-time setup choices" {
        It "requires setup for new and explicitly unfinished configs, but accepts legacy shares" {
            (Test-FirstRunNeeded -Config (New-DefaultSharesConfig)) | Should Be $true
            (Test-FirstRunNeeded -Config ([PSCustomObject]@{ Shares = @([PSCustomObject]@{ Name = 'Legacy' }) })) | Should Be $false
            (Test-FirstRunNeeded -Config ([PSCustomObject]@{ Shares = @(); SetupCompleted = $true })) | Should Be $false
            (Test-FirstRunNeeded -Config ([PSCustomObject]@{ Shares = @([PSCustomObject]@{ Name = 'Partial' }); SetupCompleted = $false })) | Should Be $true
            (Test-FirstRunNeeded -Config ([PSCustomObject]@{ Shares = @(); SetupCompleted = 'false' })) | Should Be $true
            (Test-FirstRunNeeded -Config ([PSCustomObject]@{ Shares = $null })) | Should Be $true
        }

        It "marks setup unfinished before the share action and complete only at the end" {
            $script:SetupConfig = New-DefaultSharesConfig
            Mock Get-CachedConfig { return $script:SetupConfig }
            Mock Save-AllShares { return $true }
            (Start-FirstRunSetup) | Should Be $true
            $script:SetupConfig.SetupCompleted | Should Be $false
            $prefs = (New-DefaultSharesConfig).Preferences
            $prefs.PreferredMode = 'CLI'
            (Complete-FirstRunSetup -Preferences $prefs) | Should Be $true
            $script:SetupConfig.SetupCompleted | Should Be $true
            $script:SetupConfig.Preferences.PreferredMode | Should Be 'CLI'
        }

        It "lets CLI users start empty without launching the add-share dialog" {
            $script:SetupAnswers = @('', '3')
            $script:SetupAnswerIndex = 0
            Mock Read-CliPrompt { $answer = $script:SetupAnswers[$script:SetupAnswerIndex]; $script:SetupAnswerIndex++; return $answer }
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Get-ShareConfiguration { return @() }
            Mock Add-NewShareCli { }
            Mock Set-TerminalBlackBackground { }
            Mock Write-Host { }
            Mock Write-CliMenuOption { }
            (Initialize-Config-CLI) | Should Be $true
            Assert-MockCalled Add-NewShareCli -Times 0 -Exactly -Scope It
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It -ParameterFilter { $Preferences.PreferredMode -eq 'CLI' }
        }

        It "returns to CLI setup choices after a cancelled add" {
            $script:SetupAnswers = @('', '1', '3')
            $script:SetupAnswerIndex = 0
            Mock Read-CliPrompt { $answer = $script:SetupAnswers[$script:SetupAnswerIndex]; $script:SetupAnswerIndex++; return $answer }
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Get-ShareConfiguration { return @() }
            Mock Add-NewShareCli { }
            Mock Set-TerminalBlackBackground { }
            Mock Write-Host { }
            Mock Write-CliMenuOption { }
            (Initialize-Config-CLI) | Should Be $true
            Assert-MockCalled Add-NewShareCli -Times 1 -Exactly -Scope It
            $script:SetupAnswerIndex | Should Be 3
        }

        It "completes CLI setup after a share is actually saved" {
            $script:SetupAnswers = @('', '1')
            $script:SetupAnswerIndex = 0
            $script:SavedShareCount = 0
            Mock Read-CliPrompt { $answer = $script:SetupAnswers[$script:SetupAnswerIndex]; $script:SetupAnswerIndex++; return $answer }
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Get-ShareConfiguration { if ($script:SavedShareCount -gt 0) { return [PSCustomObject]@{ Name = 'Saved' } }; return @() }
            Mock Add-NewShareCli { $script:SavedShareCount++ }
            Mock Set-TerminalBlackBackground { }
            Mock Write-Host { }
            Mock Write-CliMenuOption { }
            (Initialize-Config-CLI) | Should Be $true
            Assert-MockCalled Add-NewShareCli -Times 1 -Exactly -Scope It
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It
        }

        It "keeps all advanced CLI setup preferences available and bounded" {
            $script:SetupAnswers = @('y', '2', 'y', 'n', 'y', '2', '7', '30', '3')
            $script:SetupAnswerIndex = 0
            $script:SavedSetupPreferences = $null
            Mock Read-CliPrompt { $answer = $script:SetupAnswers[$script:SetupAnswerIndex]; $script:SetupAnswerIndex++; return $answer }
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { $script:SavedSetupPreferences = $Preferences; return $true }
            Mock Get-ShareConfiguration { return @() }
            Mock Set-TerminalBlackBackground { }
            Mock Write-Host { }
            Mock Write-CliMenuOption { }
            (Initialize-Config-CLI) | Should Be $true
            $script:SavedSetupPreferences.PreferredMode | Should Be 'GUI'
            $script:SavedSetupPreferences.PersistentMapping | Should Be $true
            $script:SavedSetupPreferences.UnmapOldMapping | Should Be $false
            $script:SavedSetupPreferences.SyncShareNameToDriveLabel | Should Be $true
            $script:SavedSetupPreferences.Theme | Should Be 'Modern'
            $script:SavedSetupPreferences.UncProbeTimeoutSeconds | Should Be 7
            $script:SavedSetupPreferences.NetUseTimeoutSeconds | Should Be 30
        }

        It "lets CLI users retry after a failed restore" {
            $script:SetupAnswers = @('', '2', 'missing.json', '3')
            $script:SetupAnswerIndex = 0
            Mock Read-CliPrompt { $answer = $script:SetupAnswers[$script:SetupAnswerIndex]; $script:SetupAnswerIndex++; return $answer }
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Get-ShareConfiguration { return @() }
            Mock Import-ShareConfiguration { return @{ Success = $false; Added = 0 } }
            Mock Set-TerminalBlackBackground { }
            Mock Write-Host { }
            Mock Write-CliMenuOption { }
            (Initialize-Config-CLI) | Should Be $true
            Assert-MockCalled Import-ShareConfiguration -Times 1 -Exactly -Scope It
            $script:SetupAnswerIndex | Should Be 4
        }

        It "lets GUI users start empty with GUI as the default startup mode" {
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI { return [PSCustomObject]@{ Action = 'Finish' } }
            Mock Show-FirstRunMessageGUI { }
            Mock Get-ShareConfiguration { return @() }
            Mock Show-AddShareDialog { }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Show-AddShareDialog -Times 0 -Exactly -Scope It
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It -ParameterFilter { $Preferences.PreferredMode -eq 'GUI' -and $Preferences.Theme -eq 'Modern' -and -not $Preferences.PersistentMapping }
        }

        It "opens preferences during GUI setup and saves the selected values" {
            $script:GuiSetupChoices = @('Preferences', 'Finish')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action }
            }
            Mock Show-PreferencesForm {
                $CurrentPrefs.PersistentMapping = $true
                $CurrentPrefs.Theme = 'Classic'
                return $CurrentPrefs
            }
            Mock Show-FirstRunMessageGUI { }
            Mock Get-ShareConfiguration { return @() }
            Mock Set-GuiVisualStyle { }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Show-PreferencesForm -Times 1 -Exactly -Scope It
            Assert-MockCalled Set-GuiVisualStyle -Times 1 -Exactly -Scope It -ParameterFilter { $Theme -eq 'Modern' }
            Assert-MockCalled Set-GuiVisualStyle -Times 1 -Exactly -Scope It -ParameterFilter { $Theme -eq 'Classic' }
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It -ParameterFilter { $Preferences.PersistentMapping -and $Preferences.Theme -eq 'Classic' }
        }

        It "does not complete GUI setup after a cancelled add" {
            $script:GuiSetupChoices = @('Add', 'Cancel')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action; Advanced = $false }
            }
            Mock Show-FirstRunMessageGUI { }
            Mock Get-ShareConfiguration { return @() }
            Mock Show-AddShareDialog { }
            (Initialize-Config-GUI) | Should Be $false
            Assert-MockCalled Complete-FirstRunSetup -Times 0 -Exactly -Scope It
            $script:GuiSetupChoiceIndex | Should Be 2
        }

        It "returns to GUI setup after each added share until Finish is chosen" {
            $script:SavedShareCount = 0
            $script:GuiSetupChoices = @('Add', 'Add', 'Finish')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action }
            }
            Mock Show-FirstRunMessageGUI { }
            Mock Get-ShareConfiguration {
                for ($i = 1; $i -le $script:SavedShareCount; $i++) { [PSCustomObject]@{ Name = "Saved $i" } }
            }
            Mock Show-AddShareDialog { $script:SavedShareCount++ }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Show-AddShareDialog -Times 2 -Exactly -Scope It
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It
            $script:GuiSetupChoiceIndex | Should Be 3
        }

        It "lets GUI setup edit a saved share before finishing" {
            $script:GuiSetupChoices = @('Edit', 'Finish')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action; ShareId = 'share-1' }
            }
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'share-1'; Name = 'Saved' } }
            Mock Show-ManageShareDialog { }
            Mock Show-FirstRunMessageGUI { }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Show-ManageShareDialog -Times 1 -Exactly -Scope It -ParameterFilter { $ShareId -eq 'share-1' -and $FromSetup }
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It
        }

        It "lets GUI setup remove an accidental share before finishing" {
            $script:GuiSetupChoices = @('Remove', 'Finish')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action; ShareId = 'share-1' }
            }
            Mock Get-ShareConfiguration { return @() }
            Mock Remove-FirstRunShareGUI { return $true }
            Mock Show-FirstRunMessageGUI { }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Remove-FirstRunShareGUI -Times 1 -Exactly -Scope It -ParameterFilter { $ShareId -eq 'share-1' }
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It
        }

        It "returns to GUI choices after a failed restore" {
            $script:GuiSetupChoices = @('Restore', 'Finish')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action; Advanced = $false }
            }
            Mock Select-FirstRunBackupGUI { return 'missing.json' }
            Mock Import-ShareConfiguration { return @{ Success = $false; Added = 0 } }
            Mock Show-FirstRunMessageGUI { }
            Mock Get-ShareConfiguration { return @() }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Import-ShareConfiguration -Times 1 -Exactly -Scope It
            $script:GuiSetupChoiceIndex | Should Be 2
        }

        It "returns to GUI choices after a successful restore" {
            $script:GuiSetupChoices = @('Restore', 'Finish')
            $script:GuiSetupChoiceIndex = 0
            Mock Start-FirstRunSetup { return $true }
            Mock Complete-FirstRunSetup { return $true }
            Mock Show-FirstRunChoiceGUI {
                $action = $script:GuiSetupChoices[$script:GuiSetupChoiceIndex]
                $script:GuiSetupChoiceIndex++
                return [PSCustomObject]@{ Action = $action }
            }
            Mock Select-FirstRunBackupGUI { return 'backup.json' }
            Mock Import-ShareConfiguration { return @{ Success = $true; Added = 1 } }
            Mock Show-FirstRunMessageGUI { }
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Name = 'Restored' } }
            (Initialize-Config-GUI) | Should Be $true
            Assert-MockCalled Import-ShareConfiguration -Times 1 -Exactly -Scope It
            Assert-MockCalled Complete-FirstRunSetup -Times 1 -Exactly -Scope It
            $script:GuiSetupChoiceIndex | Should Be 2
        }
    }

    Context "First-time setup persistence" {
        It "persists an intentionally empty setup across configuration reloads" {
            $sharesPath = Join-Path $TestDrive 'first-run.json'
            Mock Write-ActionLog { }
            Clear-ConfigCache
            (Start-FirstRunSetup) | Should Be $true
            Clear-ConfigCache
            (Test-FirstRunNeeded -Config (Import-AllShares)) | Should Be $true
            $prefs = (New-DefaultSharesConfig).Preferences
            $prefs.PreferredMode = 'CLI'
            (Complete-FirstRunSetup -Preferences $prefs) | Should Be $true
            Clear-ConfigCache
            $saved = Import-AllShares
            (Test-FirstRunNeeded -Config $saved) | Should Be $false
            $saved.Shares.Count | Should Be 0
            $saved.Preferences.PreferredMode | Should Be 'CLI'
        }
    }

    Context "CLI add-share review" {
        BeforeEach {
            $script:AddFields = @('Test', 'Z', 'user')
            $script:AddFieldIndex = 0
            $script:AddPrompts = @('notes', '2')
            $script:AddPromptIndex = 0
            $script:AddOutput = ''
            Mock Clear-Host { }
            Mock Write-Host { $script:AddOutput += [string]$Object + "`n" }
            Mock Write-CliMenuOption { }
            Mock Read-ValidatedInput { $value = $script:AddFields[$script:AddFieldIndex]; $script:AddFieldIndex++; return $value }
            Mock Read-CliUncPath { return '\\server\share' }
            Mock Read-CliPrompt { $value = $script:AddPrompts[$script:AddPromptIndex]; $script:AddPromptIndex++; return $value }
            Mock Get-ShareConfiguration { return @() }
            Mock Get-RecentUsernames { return @() }
            Mock Get-CachedConfig { return [PSCustomObject]@{ Shares = @() } }
            Mock Get-CredentialForShare { return (New-Object System.Management.Automation.PSCredential('user', (ConvertTo-SecureString 'synthetic' -AsPlainText -Force))) }
            Mock Confirm-ShareCredential { return $true }
            Mock Add-ShareConfiguration { return [PSCustomObject]@{ Id = 'saved-id' } }
            Mock Connect-NetworkShare { return @{ Success = $true; Verified = $true } }
        }

        It "saves without a second credential or connect prompt when Save only is chosen" {
            Add-NewShareCli
            Assert-MockCalled Confirm-ShareCredential -Times 1 -Exactly -Scope It
            Assert-MockCalled Add-ShareConfiguration -Times 1 -Exactly -Scope It
            Assert-MockCalled Connect-NetworkShare -Times 0 -Exactly -Scope It
            $script:AddPromptIndex | Should Be 2
            $script:AddOutput | Should Match 'saved as Z:'
        }

        It "shows that a password prompt follows the review action" {
            $script:CredentialLookups = 0
            Mock Get-CredentialForShare {
                $script:CredentialLookups++
                if ($script:CredentialLookups -eq 1) { return $null }
                return (New-Object System.Management.Automation.PSCredential('user', (ConvertTo-SecureString 'synthetic' -AsPlainText -Force)))
            }
            $script:AddPrompts = @('notes', '2')
            Add-NewShareCli
            Assert-MockCalled Write-CliMenuOption -Times 1 -Exactly -Scope It -ParameterFilter { $Label -eq 'Enter password, save and connect' }
            Assert-MockCalled Write-CliMenuOption -Times 1 -Exactly -Scope It -ParameterFilter { $Label -eq 'Enter password and save only' }
        }

        It "does not call an unverified mapping a verified connection" {
            $script:AddPrompts = @('notes', '1')
            Mock Connect-NetworkShare { return @{ Success = $true; Verified = $false } }
            Add-NewShareCli
            Assert-MockCalled Connect-NetworkShare -Times 1 -Exactly -Scope It -ParameterFilter { $ReturnStatus -and $Silent }
            $script:AddOutput | Should Match 'could not be verified'
            $script:AddOutput | Should Not Match 'connected and verified'
        }

        It "keeps a saved share when its immediate connection fails" {
            $script:AddPrompts = @('notes', '1')
            Mock Connect-NetworkShare { return @{ Success = $false; ErrorMessage = 'Server unavailable' } }
            Add-NewShareCli
            Assert-MockCalled Add-ShareConfiguration -Times 1 -Exactly -Scope It
            $script:AddOutput | Should Match 'Share saved, but connection failed: Server unavailable'
            $script:AddOutput | Should Not Match 'connected and verified'
        }

        It "returns from a cancelled password step to review with fields intact" {
            $script:AddPrompts = @('notes', '1', '2')
            $script:CredentialAttempts = 0
            Mock Confirm-ShareCredential {
                $script:CredentialAttempts++
                return $script:CredentialAttempts -gt 1
            }
            Add-NewShareCli
            $script:CredentialAttempts | Should Be 2
            Assert-MockCalled Add-ShareConfiguration -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'Test' -and $SharePath -eq '\\server\share' }
            $script:AddOutput | Should Match 'entries are still here for review'
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
            $script:MenuOutput | Should Match 'C Connect all \(1 remaining\)'
            $script:MenuOutput | Should Match '1/2 connected \(enabled shares\) \(1 disabled\)'
            $script:MenuOutput | Should Match 'U Updates'
            $script:MenuOutput | Should Match 'H Help'
            ($script:MenuOutput.IndexOf('U Updates') -lt $script:MenuOutput.IndexOf('Quit')) | Should Be $true
        }

        It "does not suggest connecting disabled shares" {
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ DriveLetter = 'Z'; Enabled = $false } }
            Show-CLI-Menu
            $script:MenuOutput | Should Match 'no enabled shares'
            $script:MenuOutput | Should Match 'Disconnect All'
            $script:MenuOutput | Should Not Match '\d+ disconnected'
            $script:MenuOutput | Should Not Match 'N Reconnect all'
        }

        It "does not count a connected disabled share as enabled" {
            Mock Test-ShareConnection { return $true }
            Mock Get-ShareConfiguration {
                return @(
                    [PSCustomObject]@{ DriveLetter = 'X'; Enabled = $true },
                    [PSCustomObject]@{ DriveLetter = 'Z'; Enabled = $false }
                )
            }
            Show-CLI-Menu
            $script:MenuOutput | Should Match '1/1 connected \(enabled shares\) \(1 disabled\)'
            $script:MenuOutput | Should Not Match '2/1'
        }

        It "does not show Connect All as an available action when all enabled shares are connected" {
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ DriveLetter = 'X'; Enabled = $true } }
            Show-CLI-Menu
            $script:MenuOutput | Should Match '1/1 connected'
            $script:MenuOutput | Should Not Match 'C Connect all'
            $script:MenuOutput | Should Not Match 'Names and prefixes'
        }

        It "shows Add Share only once for an empty configuration" {
            Mock Get-ShareConfiguration { return @() }
            Show-CLI-Menu
            ([regex]::Matches($script:MenuOutput, '1 Add')).Count | Should Be 1
            $script:MenuOutput | Should Match 'Try adding a network share to get started!'
        }

        It "highlights shortcut keys without relying on colour for labels" {
            Mock Get-ShareConfiguration { return @() }
            Show-CLI-Menu
            Assert-MockCalled Write-Host -Scope It -ParameterFilter { $Object -eq '  SHARES' -and $ForegroundColor -eq 'Cyan' }
            Assert-MockCalled Write-Host -Scope It -ParameterFilter { $Object -eq '  1' -and $ForegroundColor -eq 'Yellow' }
            Assert-MockCalled Write-Host -Scope It -ParameterFilter { $Object -eq ' Add share      ' -and $ForegroundColor -eq 'Gray' }
            Assert-MockCalled Write-Host -Scope It -ParameterFilter { $Object -eq 'Q' -and $ForegroundColor -eq 'Yellow' }
        }
    }

    Context "Modern CLI commands" {
        BeforeEach { Mock Test-CliInteractiveInput { return $false } }
        It "accepts text editing and Escape in interactive CLI prompts" {
            $script:PromptKeys = @(
                [PSCustomObject]@{ VirtualKeyCode = 65; Character = 'a' },
                [PSCustomObject]@{ VirtualKeyCode = 8; Character = [char]8 },
                [PSCustomObject]@{ VirtualKeyCode = 66; Character = 'b' },
                [PSCustomObject]@{ VirtualKeyCode = 13; Character = [char]13 },
                [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 }
            )
            $script:PromptKeyIndex = 0
            Mock Test-CliInteractiveInput { return $true }
            Mock Write-Host { }
            Mock Read-CliKey {
                if ($script:PromptKeyIndex -ge $script:PromptKeys.Count) { throw 'Unexpected extra key read' }
                $key = $script:PromptKeys[$script:PromptKeyIndex]
                $script:PromptKeyIndex++
                return $key
            }
            (Read-CliPrompt 'Choice') | Should Be 'b'
            { Read-CliPrompt 'Choice' } | Should Throw
        }
        It "cancels password entry with Escape instead of appending it" {
            Mock Write-Host { }
            Mock Read-CliKey { return [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 } }
            { Read-Password 'Password: ' } | Should Throw
        }
        It "accepts readable commands and preserves existing shortcuts" {
            (Resolve-CliCommand 'CONNECT-ALL') | Should Be 'C'
            (Resolve-CliCommand 'c') | Should Be 'C'
            (Resolve-CliCommand 'disconnect-all') | Should Be 'D'
            (Resolve-CliCommand 'd') | Should Be 'D'
            (Resolve-CliCommand 'con a') | Should Be 'C'
            (Resolve-CliCommand 'disc a') | Should Be 'D'
            (Resolve-CliCommand 'stat') | Should Be '3'
            (Resolve-CliCommand 'pref') | Should Be 'P'
            (Resolve-CliCommand '1') | Should Be '1'
            (Resolve-CliCommand 'add') | Should Be '1'
            (Resolve-CliCommand 'preferences') | Should Be 'P'
            (Resolve-CliCommand '?') | Should Be 'H'
            (Resolve-CliCommand 'exit') | Should Be 'Q'
        }
        It "rejects unknown and blank commands without guessing" {
            (Resolve-CliCommand 'connect-one') | Should BeNullOrEmpty
            (Resolve-CliCommand 'connect') | Should BeNullOrEmpty
            (Resolve-CliCommand 'disconnect') | Should BeNullOrEmpty
            (Resolve-CliCommand 'con') | Should BeNullOrEmpty
            (Resolve-CliCommand 'co a') | Should BeNullOrEmpty
            (Resolve-CliPrefix -InputText 'st' -Commands @{ status = 'S'; startup = 'P' }) | Should BeNullOrEmpty
            (Resolve-CliCommand ' ') | Should BeNullOrEmpty
            (Resolve-CliCommand $null) | Should BeNullOrEmpty
        }
        It "accepts readable Manage Shares commands and share numbers" {
            (Resolve-CliManageCommand 'status') | Should Be 'S'
            (Resolve-CliManageCommand 'stat') | Should Be 'S'
            (Resolve-CliManageCommand 'edi') | Should Be 'E'
            (Resolve-CliManageCommand 'edit') | Should Be 'E'
            (Resolve-CliManageCommand 'delete') | Should Be 'R'
            (Resolve-CliManageCommand 'search') | Should Be 'F'
            (Resolve-CliManageCommand 'batch') | Should Be 'X'
            (Resolve-CliManageCommand 'back') | Should Be 'B'
            (Resolve-CliManageCommand '12') | Should Be '12'
            (Resolve-CliManageCommand 'wat') | Should BeNullOrEmpty
        }
        It "matches Manage and Batch filters as literal text" {
            $shares = @(
                [PSCustomObject]@{ Name = 'NAS*Backup'; SharePath = '\\srv\backup'; DriveLetter = 'X' },
                [PSCustomObject]@{ Name = 'NAS?Media'; SharePath = '\\srv\media'; DriveLetter = 'Y' },
                [PSCustomObject]@{ Name = 'NAS-Work'; SharePath = '\\srv\work'; DriveLetter = 'Z' }
            )
            @(Select-CliSharesByFilter -Shares $shares -FilterText '*').Count | Should Be 1
            @(Select-CliSharesByFilter -Shares $shares -FilterText '?').Count | Should Be 1
            @(Select-CliSharesByFilter -Shares $shares -FilterText 'NAS').Count | Should Be 3
        }
        It "uses selected visible shares, otherwise the focused row" {
            $shares = @(
                [PSCustomObject]@{ Id = 'one'; Name = 'One' },
                [PSCustomObject]@{ Id = 'two'; Name = 'Two' }
            )
            $selected = @{ one = $true }
            @(Get-CliManageTargets -VisibleShares $shares -FocusedIndex 1 -SelectedIds $selected)[0].Id | Should Be 'one'
            @(Get-CliManageTargets -VisibleShares $shares -FocusedIndex 1 -SelectedIds @{})[0].Id | Should Be 'two'
            @(Get-CliManageTargets -VisibleShares @() -FocusedIndex 0 -SelectedIds @{}).Count | Should Be 0
        }
        It "does not connect disabled shares in the picker" {
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $false; DriveLetter = 'X' } }
            Mock Test-ShareConnection { return $false }
            Mock Connect-NetworkShare { throw 'Unexpected connection attempt' }
            Mock Write-Host { }
            Invoke-CliManageAction -Action C -Targets @([PSCustomObject]@{ Id = 'one' })
            Assert-MockCalled Connect-NetworkShare -Times 0 -Exactly -Scope It
        }
        It "updates batch selection by ID when names repeat" {
            $script:BatchConfig = [PSCustomObject]@{
                Shares = @(
                    [PSCustomObject]@{ Id = 'one'; Name = 'NAS'; Enabled = $false },
                    [PSCustomObject]@{ Id = 'two'; Name = 'NAS'; Enabled = $false }
                )
            }
            Mock Get-ShareConfiguration { return $script:BatchConfig.Shares }
            Mock Get-CachedConfig { return $script:BatchConfig }
            Mock Save-AllShares { return $true }
            Mock Read-Host { return 'Y' }
            Mock Write-Host { }
            Invoke-CliManageAction -Action Enable -Targets @([PSCustomObject]@{ Id = 'two' })
            $script:BatchConfig.Shares[0].Enabled | Should Be $false
            $script:BatchConfig.Shares[1].Enabled | Should Be $true
            Assert-MockCalled Save-AllShares -Times 1 -Exactly -Scope It
        }
        It "moves focus, selects a row, and acts on the selected ID" {
            $script:PickerKeys = @(
                [PSCustomObject]@{ VirtualKeyCode = 40; Character = [char]0 },
                [PSCustomObject]@{ VirtualKeyCode = 32; Character = ' ' },
                [PSCustomObject]@{ VirtualKeyCode = 67; Character = 'c' },
                [PSCustomObject]@{ VirtualKeyCode = 13; Character = [char]13 },
                [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 }
            )
            $script:PickerKeyIndex = 0
            $script:PickerTarget = $null
            Mock Get-ShareConfiguration {
                return @(
                    [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $true; DriveLetter = 'X'; SharePath = '\\srv\one' },
                    [PSCustomObject]@{ Id = 'two'; Name = 'Two'; Enabled = $true; DriveLetter = 'Y'; SharePath = '\\srv\two' }
                )
            }
            Mock Test-ShareConnection { return $false }
            Mock Clear-Host { }
            Mock Write-Host { }
            Mock Read-CliKey {
                if ($script:PickerKeyIndex -ge $script:PickerKeys.Count) { throw 'Unexpected extra key read' }
                $key = $script:PickerKeys[$script:PickerKeyIndex]
                $script:PickerKeyIndex++
                return $key
            }
            Mock Invoke-CliManageAction { $script:PickerTarget = [string]$Targets[0].Id; return $true }
            (Show-CliInteractiveManageShares) | Should Be $true
            $script:PickerTarget | Should Be 'two'
            Assert-MockCalled Invoke-CliManageAction -Times 1 -Exactly -Scope It -ParameterFilter { $Action -eq 'C' }
        }
        It "falls back to the typed menu when key reading is unavailable" {
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $true; DriveLetter = 'X'; SharePath = '\\srv\one' } }
            Mock Test-ShareConnection { return $false }
            Mock Clear-Host { }
            Mock Write-Host { }
            Mock Read-CliKey { throw 'No interactive key input' }
            (Show-CliInteractiveManageShares) | Should Be $false
        }
        It "requires confirmation before disconnecting multiple selected shares" {
            Mock Get-ShareConfiguration {
                return @(
                    [PSCustomObject]@{ Id = 'one'; Name = 'One'; DriveLetter = 'X' },
                    [PSCustomObject]@{ Id = 'two'; Name = 'Two'; DriveLetter = 'Y' }
                )
            }
            Mock Read-Host { return '' }
            Mock Write-Host { }
            Mock Disconnect-NetworkShare { throw 'Unexpected disconnect attempt' }
            Invoke-CliManageAction -Action D -Targets @(
                [PSCustomObject]@{ Id = 'one' }, [PSCustomObject]@{ Id = 'two' }
            )
            Assert-MockCalled Disconnect-NetworkShare -Times 0 -Exactly -Scope It
        }
        It "does not open selection actions when nothing is selected" {
            $script:PickerKeys = @(
                [PSCustomObject]@{ VirtualKeyCode = 88; Character = 'x' },
                [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 }
            )
            $script:PickerKeyIndex = 0
            $script:PickerOutput = ''
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $true; DriveLetter = 'X'; SharePath = '\\srv\one' } }
            Mock Test-ShareConnection { return $true }
            Mock Clear-Host { }
            Mock Write-Host { $script:PickerOutput += [string]$Object + "`n" }
            Mock Read-CliKey {
                if ($script:PickerKeyIndex -ge $script:PickerKeys.Count) { throw 'Unexpected extra key read' }
                $key = $script:PickerKeys[$script:PickerKeyIndex]
                $script:PickerKeyIndex++
                return $key
            }
            (Show-CliInteractiveManageShares) | Should Be $true
            $script:PickerKeyIndex | Should Be 2
            $script:PickerOutput | Should Not Match '1 Enable selected'
            $script:PickerOutput | Should Not Match 'X Enable/disable'
            $script:PickerOutput | Should Not Match 'Press any key to return'
        }
        It "returns directly when cancelling the selected-shares menu" {
            $script:PickerKeys = @(
                [PSCustomObject]@{ VirtualKeyCode = 32; Character = ' ' },
                [PSCustomObject]@{ VirtualKeyCode = 88; Character = 'x' },
                [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 },
                [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 }
            )
            $script:PickerKeyIndex = 0
            $script:PickerOutput = ''
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $true; DriveLetter = 'X'; SharePath = '\\srv\one' } }
            Mock Test-ShareConnection { return $true }
            Mock Clear-Host { }
            Mock Write-Host { $script:PickerOutput += [string]$Object + "`n" }
            Mock Read-CliKey {
                if ($script:PickerKeyIndex -ge $script:PickerKeys.Count) { throw 'Unexpected extra key read' }
                $key = $script:PickerKeys[$script:PickerKeyIndex]
                $script:PickerKeyIndex++
                return $key
            }
            (Show-CliInteractiveManageShares) | Should Be $true
            $script:PickerKeyIndex | Should Be 4
            $script:PickerOutput | Should Match 'Disable selected'
            $script:PickerOutput | Should Not Match '1 Enable selected'
            $script:PickerOutput | Should Not Match 'C Connect selected'
            $script:PickerOutput | Should Not Match 'Press any key to return'
        }
        It "returns to Manage after cancelling a nested edit" {
            $script:ManageChoices = @('E', 'B')
            $script:ManageChoiceIndex = 0
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $true; DriveLetter = 'X'; SharePath = '\\srv\one' } }
            Mock Test-ShareConnection { return $false }
            Mock Clear-Host { }
            Mock Write-Host { }
            Mock Read-CliPrompt {
                $choice = $script:ManageChoices[$script:ManageChoiceIndex]
                $script:ManageChoiceIndex++
                return $choice
            }
            Mock Edit-ShareCli { throw [System.OperationCanceledException]::new('cancel') }
            Show-ManageSharesMenu
            $script:ManageChoiceIndex | Should Be 2
            Assert-MockCalled Edit-ShareCli -Times 1 -Exactly -Scope It
        }
        It "lists command families in help" {
            $script:HelpOutput = ''
            Mock Clear-Host { }
            Mock Write-Host { $script:HelpOutput += [string]$Object + "`n" }
            Show-CliHelp -NoPause
            $script:HelpOutput | Should Match 'add, manage, status'
            $script:HelpOutput | Should Match 'connect-all, disconnect-all, reconnect-all'
            $script:HelpOutput | Should Match 'gui, help, quit'
        }
        It "exits CLI mode cleanly when Escape cancels the main prompt" {
            Mock Write-ActionLog { }
            Mock Set-TerminalBlackBackground { }
            Mock Convert-LegacyConfig { }
            Mock Get-PreferenceValue { return $false }
            Mock Show-CLI-Menu { }
            Mock Write-Host { }
            Mock Read-CliPrompt { throw [System.OperationCanceledException]::new('cancel') }
            { Start-CliMode } | Should Not Throw
            Assert-MockCalled Show-CLI-Menu -Times 1 -Exactly -Scope It
        }
    }

    Context "Manage picker colour" {
        It "distinguishes focus, selection, and connection state" {
            $script:PickerColours = @()
            Mock Clear-Host { }
            Mock Get-ShareConfiguration { return [PSCustomObject]@{ Id = 'one'; Name = 'One'; Enabled = $true; DriveLetter = 'X'; SharePath = '\\srv\one' } }
            Mock Test-ShareConnection { return $true }
            Mock Read-CliKey { return [PSCustomObject]@{ VirtualKeyCode = 27; Character = [char]27 } }
            Mock Write-Host { $script:PickerColours += [PSCustomObject]@{ Text = [string]$Object; Colour = [string]$ForegroundColor } }
            (Show-CliInteractiveManageShares) | Should Be $true
            @($script:PickerColours | Where-Object { $_.Text -eq '  > ' -and $_.Colour -eq 'Cyan' }).Count | Should Be 1
            @($script:PickerColours | Where-Object { $_.Text -eq 'Connected' -and $_.Colour -eq 'Green' }).Count | Should Be 1
            @($script:PickerColours | Where-Object { $_.Text -eq '  Esc' -and $_.Colour -eq 'Yellow' }).Count | Should Be 1
        }
    }

    Context "CLI option colours" {
        It "uses the same key, label, and value colours across menus" {
            $script:OptionColours = @()
            Mock Write-Host { $script:OptionColours += [PSCustomObject]@{ Text = [string]$Object; Colour = [string]$ForegroundColor } }
            Write-CliMenuOption -Key '1.' -Label 'Setting: ' -Value 'True'
            @($script:OptionColours | Where-Object { $_.Text -eq '  1.' -and $_.Colour -eq 'Yellow' }).Count | Should Be 1
            @($script:OptionColours | Where-Object { $_.Text -eq ' Setting: ' -and $_.Colour -eq 'Gray' }).Count | Should Be 1
            @($script:OptionColours | Where-Object { $_.Text -eq 'True' -and $_.Colour -eq 'White' }).Count | Should Be 1
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
