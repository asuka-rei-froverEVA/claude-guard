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
            New-Item -ItemType Directory -Path $configDirectory | Out-Null
            '{}' | Set-Content -LiteralPath $settingsPath
            @"
{
  "command": "$((Get-Command pwsh).Source.Replace('\', '\\'))",
  "config_dir": "$($configDirectory.Replace('\', '\\'))",
  "allowed_ips": ["203.0.113.10"],
  "allowed_cidrs": []
}
"@ | Set-Content -LiteralPath $configPath

            $environment = @{ CLAUDE_GUARD_PROXY = "http://127.0.0.1:$port" }
            $status = Get-ClaudeGuardStatus -ConfigPath $configPath -Environment $environment

            $status.code | Should -BeExactly 'CG_STATUS_LOCAL_ONLY'
            $status.exit_code | Should -Be 0
            $status.status | Should -BeExactly 'unknown'
            $status.evidence.network_readiness | Should -BeExactly 'not_checked'
            $status.evidence.watchdog | Should -BeExactly 'not_available_in_windows_milestone_1'
            $status.evidence.notifications | Should -BeExactly 'unavailable'
            $listener.Pending() | Should -BeFalse
        }
        finally {
            $listener.Stop()
        }
    }
}
