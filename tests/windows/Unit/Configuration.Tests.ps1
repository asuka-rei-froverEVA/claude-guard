BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows guard configuration' {
    It 'parses the official-lane schema and applies explicit environment overrides' {
        $configPath = Join-Path $TestDrive 'safe.json'
        $configDirectory = Join-Path $TestDrive 'profile'
        $settingsPath = Join-Path $TestDrive 'override-settings.json'
        New-Item -ItemType Directory -Path $configDirectory | Out-Null
        '{}' | Set-Content -LiteralPath $settingsPath
        @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($configDirectory.Replace('\', '\\'))",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": ["203.0.113.0/24"],
  "client_version": "1.2.3",
  "client_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "client_macos_team_id": "",
  "blocked_plugins": ["blocked@example"],
  "blocked_models": ["blocked-model"],
  "require_unpinned_model": true,
  "notify": false,
  "future_field": "ignored"
}
"@ | Set-Content -LiteralPath $configPath

        $environment = @{
            CLAUDE_GUARD_SETTINGS            = $settingsPath
            CLAUDE_GUARD_PROXY               = 'http://127.0.0.1:18080'
            CLAUDE_GUARD_CA_CERT             = (Join-Path $TestDrive 'roots.pem')
            CLAUDE_GUARD_UI                  = 'never'
            CLAUDE_GUARD_FINGERPRINT_MODE    = 'strict'
            CLAUDE_GUARD_LEGACY_PROFILE_MODE = 'off'
        }

        InModuleScope ClaudeGuard -Parameters @{
            ConfigPath = $configPath
            Environment = $environment
            SettingsPath = $settingsPath
        } {
            $parsed = Read-GuardConfiguration -Path $ConfigPath -Environment $Environment

            $parsed.Result.status | Should -BeExactly 'pass'
            $parsed.Configuration.command | Should -BeExactly (Get-Command pwsh).Source
            $parsed.Configuration.settings_path | Should -BeExactly $SettingsPath
            $parsed.Configuration.proxy_uri.AbsoluteUri | Should -BeExactly 'http://127.0.0.1:18080/'
            $parsed.Configuration.ca_cert_path | Should -BeExactly (Join-Path $TestDrive 'roots.pem')
            $parsed.Configuration.ui_mode | Should -BeExactly 'never'
            $parsed.Configuration.fingerprint_mode | Should -BeExactly 'strict'
            $parsed.Configuration.legacy_profile_mode | Should -BeExactly 'off'
            $parsed.Configuration.require_unpinned_model | Should -BeTrue
            @($parsed.Configuration.PSObject.Properties.Name) | Should -Not -Contain 'future_field'
        }
    }

    It 'rejects malformed JSON with the compatible config exit code' {
        $configPath = Join-Path $TestDrive 'malformed.json'
        '{ invalid' | Set-Content -LiteralPath $configPath

        InModuleScope ClaudeGuard -Parameters @{ ConfigPath = $configPath } {
            $parsed = Read-GuardConfiguration -Path $ConfigPath -Environment @{}

            $parsed.Configuration | Should -BeNullOrEmpty
            $parsed.Result.code | Should -BeExactly 'CG_CONFIG_JSON_INVALID'
            $parsed.Result.exit_code | Should -Be 2
        }
    }

    It 'rejects a non-empty macOS team ID instead of pretending Windows can verify it' {
        $configPath = Join-Path $TestDrive 'team-id.json'
        @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($TestDrive.Replace('\', '\\'))",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": [],
  "client_macos_team_id": "TEAMID"
}
"@ | Set-Content -LiteralPath $configPath

        InModuleScope ClaudeGuard -Parameters @{ ConfigPath = $configPath } {
            $parsed = Read-GuardConfiguration -Path $ConfigPath -Environment @{}

            $parsed.Result.code | Should -BeExactly 'CG_WINDOWS_TEAM_ID_UNSUPPORTED'
            $parsed.Result.exit_code | Should -Be 2
        }
    }

    It 'rejects an explicitly empty security override instead of falling back' {
        $configPath = Join-Path $TestDrive 'empty-override.json'
        @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($TestDrive.Replace('\', '\\'))",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": []
}
"@ | Set-Content -LiteralPath $configPath

        InModuleScope ClaudeGuard -Parameters @{ ConfigPath = $configPath } {
            $parsed = Read-GuardConfiguration `
                -Path $ConfigPath `
                -Environment @{ CLAUDE_GUARD_PROXY = '' }

            $parsed.Result.code | Should -BeExactly 'CG_CONFIG_OVERRIDE_EMPTY'
            $parsed.Result.exit_code | Should -Be 2
        }
    }

    It 'rejects schema values with the wrong JSON type' -ForEach @(
        @{ Name = 'allowed_ips'; Value = '"203.0.113.10"' }
        @{ Name = 'allowed_cidrs'; Value = 'false' }
        @{ Name = 'blocked_plugins'; Value = '{}' }
        @{ Name = 'blocked_models'; Value = '1' }
        @{ Name = 'require_unpinned_model'; Value = '"false"' }
        @{ Name = 'notify'; Value = '0' }
    ) {
        $configPath = Join-Path $TestDrive ("wrong-{0}.json" -f $Name)
        $json = @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($TestDrive.Replace('\', '\\'))",
  "allowed_ips": [],
  "allowed_cidrs": [],
  "$Name": $Value
}
"@
        $json | Set-Content -LiteralPath $configPath

        InModuleScope ClaudeGuard -Parameters @{ ConfigPath = $configPath } {
            $parsed = Read-GuardConfiguration -Path $ConfigPath -Environment @{}

            $parsed.Result.code | Should -BeExactly 'CG_CONFIG_SCHEMA_INVALID'
            $parsed.Result.exit_code | Should -Be 2
        }
    }
}
