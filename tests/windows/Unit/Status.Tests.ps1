BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Offline Windows status' {
    It 'reports local-only readiness without connecting to the configured proxy' {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
            $configDirectory = Join-Path $TestDrive 'profile'
            $settingsPath = Join-Path $configDirectory 'settings.json'
            $configPath = Join-Path $TestDrive 'safe.json'
            $workingDirectory = Join-Path $TestDrive 'work'
            New-Item -ItemType Directory -Path $configDirectory | Out-Null
            New-Item -ItemType Directory -Path $workingDirectory | Out-Null
            Copy-Item `
                -LiteralPath (Join-Path $PSScriptRoot '..\Fixtures\settings\official-safe.json') `
                -Destination $settingsPath
            @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($configDirectory.Replace('\', '\\'))",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": []
}
"@ | Set-Content -LiteralPath $configPath

            $environment = @{
                CLAUDE_GUARD_PROXY = "http://127.0.0.1:$port"
                USERPROFILE = $TestDrive
            }
            $status = Get-ClaudeGuardStatus `
                -ConfigPath $configPath `
                -Environment $environment `
                -WorkingDirectory $workingDirectory

            $status.code | Should -BeExactly 'CG_STATUS_LOCAL_ONLY'
            $status.exit_code | Should -Be 0
            $status.status | Should -BeExactly 'unknown'
            $status.evidence.network_readiness | Should -BeExactly 'not_checked'
            $status.evidence.watchdog | Should -BeExactly 'not_available_in_windows_milestone_1'
            $status.evidence.notifications | Should -BeExactly 'unavailable'
            $status.evidence.client_identity.status | Should -BeExactly 'pass'
            $status.evidence.client_identity.version | Should -BeExactly 'unpinned'
            $status.evidence.settings_policy.status | Should -BeExactly 'pass'
            $status.evidence.project_settings.status | Should -BeExactly 'pass'
            $status.evidence.fingerprint.status | Should -BeExactly 'pass'
            $status.evidence.legacy_profile.status | Should -BeExactly 'pass'
            $status.evidence.active_processes.status | Should -BeIn @('observed', 'unavailable')
            $listener.Pending() | Should -BeFalse
        }
        finally {
            $listener.Stop()
        }
    }

    It 'returns a local policy failure when settings do not enforce the lifecycle contract' {
        $configDirectory = Join-Path $TestDrive 'unsafe-profile'
        $workingDirectory = Join-Path $TestDrive 'unsafe-work'
        $settingsPath = Join-Path $configDirectory 'settings.json'
        $configPath = Join-Path $TestDrive 'unsafe-safe.json'
        New-Item -ItemType Directory -Path $configDirectory | Out-Null
        New-Item -ItemType Directory -Path $workingDirectory | Out-Null
        '{}' | Set-Content -LiteralPath $settingsPath
        @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($configDirectory.Replace('\', '\\'))",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": []
}
"@ | Set-Content -LiteralPath $configPath

        $status = Get-ClaudeGuardStatus `
            -ConfigPath $configPath `
            -Environment @{ USERPROFILE = $TestDrive } `
            -WorkingDirectory $workingDirectory

        $status.code | Should -BeExactly 'CG_STATUS_LOCAL_POLICY_FAILED'
        $status.exit_code | Should -Be 13
        $status.status | Should -BeExactly 'fail'
        $status.evidence.settings_policy.code | Should -BeExactly 'CG_LIFECYCLE_POLICY_REQUIRED'
        $status.evidence.network_readiness | Should -BeExactly 'not_checked'
    }
}
