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

. $script:ScriptPath

Describe "Share Manager core regressions" {
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

    Context "Mapping reliability contract" {
        It "creates both bare-server and UNC credential targets" {
            $targets = @(Get-CredentialTargetsForSharePath -SharePath '\\srv\docs')

            ($targets -contains 'srv') | Should Be $true
            ($targets -contains '\\srv') | Should Be $true
        }

        It "always passes supplied credentials to net use" {
            $connectText = (Get-Command Connect-NetworkShare).ScriptBlock.ToString()
            $wrapperText = (Get-Command Invoke-NetUseWithCredential).ScriptBlock.ToString()

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
            $scriptText | Should Match 'cmdkey /delete:\$ServerTarget'
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
