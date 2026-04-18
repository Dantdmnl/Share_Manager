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
