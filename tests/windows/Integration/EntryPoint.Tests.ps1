Describe 'Windows entry point' {
    It 'reports its Windows module version without loading a config or using the network' {
        $entryPoint = Join-Path $PSScriptRoot '..\..\..\bin\claude-guard.ps1'
        (Test-Path -LiteralPath $entryPoint -PathType Leaf) | Should -BeTrue

        $output = & pwsh -NoLogo -NoProfile -File $entryPoint --version 2>&1
        $LASTEXITCODE | Should -Be 0
        @($output) | Should -Be @('claude-guard windows 0.1.0')
    }

    It 'dispatches status JSON and returns the structured local-only result' {
        $entryPoint = Join-Path $PSScriptRoot '..\..\..\bin\claude-guard.ps1'
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

        $previousConfig = $env:CLAUDE_GUARD_CONFIG
        try {
            $env:CLAUDE_GUARD_CONFIG = $configPath
            $output = & pwsh -NoLogo -NoProfile -File $entryPoint status --json 2>&1

            $LASTEXITCODE | Should -Be 0
            $parsed = (@($output) -join "`n") | ConvertFrom-Json
            $parsed.code | Should -BeExactly 'CG_STATUS_LOCAL_ONLY'
            $parsed.evidence.network_readiness | Should -BeExactly 'not_checked'
        }
        finally {
            $env:CLAUDE_GUARD_CONFIG = $previousConfig
        }
    }
}
