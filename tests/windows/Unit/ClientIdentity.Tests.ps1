BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows Claude client identity' {
    It 'accepts an exact executable version and SHA-256 pin' {
        $commandPath = (Get-Command pwsh).Source
        $expectedVersion = $PSVersionTable.PSVersion.ToString()
        $expectedHash = (Get-FileHash -LiteralPath $commandPath -Algorithm SHA256).Hash
        $guardPath = Join-Path $TestDrive 'claude-guard.ps1'
        '' | Set-Content -LiteralPath $guardPath

        InModuleScope ClaudeGuard -Parameters @{
            CommandPath = $commandPath
            ExpectedVersion = $expectedVersion
            ExpectedHash = $expectedHash
            GuardPath = $guardPath
        } {
            $result = Test-GuardClientIdentity `
                -CommandPath $CommandPath `
                -ExpectedVersion $ExpectedVersion `
                -ExpectedSha256 $ExpectedHash `
                -Environment ([Environment]::GetEnvironmentVariables()) `
                -GuardEntryPath $GuardPath

            $result.status | Should -BeExactly 'pass'
            $result.evidence.version | Should -BeExactly $ExpectedVersion
            $result.evidence.sha256_prefix | Should -BeExactly $ExpectedHash.Substring(0, 12).ToLowerInvariant()
        }
    }

    It 'rejects recursion into the Guard entry point before invoking a process' {
        $guardPath = Join-Path $TestDrive 'claude-guard.exe'
        'not executable' | Set-Content -LiteralPath $guardPath

        InModuleScope ClaudeGuard -Parameters @{ GuardPath = $guardPath } {
            $result = Test-GuardClientIdentity `
                -CommandPath $GuardPath.ToUpperInvariant() `
                -ExpectedVersion '' `
                -ExpectedSha256 '' `
                -Environment @{} `
                -GuardEntryPath $GuardPath

            $result.code | Should -BeExactly 'CG_CLIENT_RECURSION'
            $result.exit_code | Should -Be 12
        }
    }

    It 'rejects a version mismatch without exposing process output' {
        $commandPath = (Get-Command pwsh).Source
        $guardPath = Join-Path $TestDrive 'claude-guard.ps1'
        '' | Set-Content -LiteralPath $guardPath

        InModuleScope ClaudeGuard -Parameters @{
            CommandPath = $commandPath
            GuardPath = $guardPath
        } {
            $result = Test-GuardClientIdentity `
                -CommandPath $CommandPath `
                -ExpectedVersion '0.0.0-impossible' `
                -ExpectedSha256 '' `
                -Environment ([Environment]::GetEnvironmentVariables()) `
                -GuardEntryPath $GuardPath

            $result.code | Should -BeExactly 'CG_CLIENT_VERSION_MISMATCH'
            $result.exit_code | Should -Be 12
            ($result | ConvertTo-GuardJson) | Should -Not -Match 'PowerShell'
        }
    }

    It 'rejects a SHA-256 mismatch with only a bounded prefix as evidence' {
        $commandPath = (Get-Command pwsh).Source
        $guardPath = Join-Path $TestDrive 'claude-guard.ps1'
        '' | Set-Content -LiteralPath $guardPath
        $wrongHash = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

        InModuleScope ClaudeGuard -Parameters @{
            CommandPath = $commandPath
            GuardPath = $guardPath
            WrongHash = $wrongHash
        } {
            $result = Test-GuardClientIdentity `
                -CommandPath $CommandPath `
                -ExpectedVersion '' `
                -ExpectedSha256 $WrongHash `
                -Environment ([Environment]::GetEnvironmentVariables()) `
                -GuardEntryPath $GuardPath

            $result.code | Should -BeExactly 'CG_CLIENT_HASH_MISMATCH'
            $result.exit_code | Should -Be 12
            $result.evidence.actual_sha256_prefix.Length | Should -Be 12
            ($result | ConvertTo-GuardJson) | Should -Not -Match $WrongHash
        }
    }

    It 'fails closed when a pinned version cannot be captured from the configured file' {
        $commandPath = Join-Path $TestDrive 'not-an-executable.exe'
        $guardPath = Join-Path $TestDrive 'claude-guard.ps1'
        'fixture' | Set-Content -LiteralPath $commandPath
        '' | Set-Content -LiteralPath $guardPath

        InModuleScope ClaudeGuard -Parameters @{
            CommandPath = $commandPath
            GuardPath = $guardPath
        } {
            $result = Test-GuardClientIdentity `
                -CommandPath $CommandPath `
                -ExpectedVersion '1.2.3' `
                -ExpectedSha256 '' `
                -Environment ([Environment]::GetEnvironmentVariables()) `
                -GuardEntryPath $GuardPath

            $result.code | Should -BeExactly 'CG_CLIENT_VERSION_UNAVAILABLE'
            $result.exit_code | Should -Be 12
        }
    }
}
