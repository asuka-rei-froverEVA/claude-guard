BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows client fingerprint policy' {
    BeforeEach {
        $script:markerText = 'Asia/Shanghai filler Today date is watermark'
    }

    It 'passes a readable client without the paired watermark markers' {
        $clientPath = Join-Path $TestDrive 'clean.exe'
        'ordinary client bytes' | Set-Content -LiteralPath $clientPath

        InModuleScope ClaudeGuard -Parameters @{ ClientPath = $clientPath } {
            $result = Test-GuardClientFingerprint `
                -CommandPath $ClientPath `
                -Mode 'strict' `
                -Environment @{} `
                -TimeZoneId 'UTC'

            $result.status | Should -BeExactly 'pass'
        }
    }

    It 'rejects a watermark-capable client unconditionally in strict mode' {
        $clientPath = Join-Path $TestDrive 'strict.exe'
        $script:markerText | Set-Content -LiteralPath $clientPath

        InModuleScope ClaudeGuard -Parameters @{ ClientPath = $clientPath } {
            $result = Test-GuardClientFingerprint `
                -CommandPath $ClientPath `
                -Mode 'strict' `
                -Environment @{} `
                -TimeZoneId 'UTC'

            $result.code | Should -BeExactly 'CG_FINGERPRINT_BLOCKED'
            $result.exit_code | Should -Be 10
        }
    }

    It 'rejects fail-active mode when a base URL activation condition is present and redacts its value' {
        $clientPath = Join-Path $TestDrive 'active-url.exe'
        $script:markerText | Set-Content -LiteralPath $clientPath
        $secretUrl = 'https://credential-bearing-secret.invalid/path'

        InModuleScope ClaudeGuard -Parameters @{
            ClientPath = $clientPath
            SecretUrl = $secretUrl
        } {
            $result = Test-GuardClientFingerprint `
                -CommandPath $ClientPath `
                -Mode 'fail-active' `
                -Environment @{ ANTHROPIC_BASE_URL = $SecretUrl } `
                -TimeZoneId 'UTC'

            $result.code | Should -BeExactly 'CG_FINGERPRINT_ACTIVE'
            $result.exit_code | Should -Be 10
            ($result | ConvertTo-GuardJson) | Should -Not -Match ([regex]::Escape($SecretUrl))
        }
    }

    It 'treats the two upstream Asia time zones as activation conditions' -ForEach @(
        @{ TimeZoneId = 'Asia/Shanghai' }
        @{ TimeZoneId = 'Asia/Urumqi' }
    ) {
        $clientPath = Join-Path $TestDrive ("active-{0}.exe" -f $TimeZoneId.Replace('/', '-'))
        $script:markerText | Set-Content -LiteralPath $clientPath

        InModuleScope ClaudeGuard -Parameters @{
            ClientPath = $clientPath
            Zone = $TimeZoneId
        } {
            $result = Test-GuardClientFingerprint `
                -CommandPath $ClientPath `
                -Mode 'fail-active' `
                -Environment @{} `
                -TimeZoneId $Zone

            $result.code | Should -BeExactly 'CG_FINGERPRINT_ACTIVE'
        }
    }

    It 'warns but does not block when the marker is inactive in fail-active mode' {
        $clientPath = Join-Path $TestDrive 'inactive.exe'
        $script:markerText | Set-Content -LiteralPath $clientPath

        InModuleScope ClaudeGuard -Parameters @{ ClientPath = $clientPath } {
            $result = Test-GuardClientFingerprint `
                -CommandPath $ClientPath `
                -Mode 'fail-active' `
                -Environment @{} `
                -TimeZoneId 'UTC'

            $result.status | Should -BeExactly 'warn'
            $result.exit_code | Should -Be 0
        }
    }

    It 'fails closed when a blocking mode cannot scan the configured client' {
        $missingPath = Join-Path $TestDrive 'missing.exe'

        InModuleScope ClaudeGuard -Parameters @{ MissingPath = $missingPath } {
            $result = Test-GuardClientFingerprint `
                -CommandPath $MissingPath `
                -Mode 'strict' `
                -Environment @{} `
                -TimeZoneId 'UTC'

            $result.code | Should -BeExactly 'CG_FINGERPRINT_SCAN_FAILED'
            $result.exit_code | Should -Be 10
        }
    }
}

Describe 'Windows legacy profile policy' {
    It 'warns without exposing contaminated values in warn mode' {
        $profilePath = Join-Path $TestDrive 'legacy-settings.json'
        $secret = 'https://legacy-secret.invalid'
        @{ env = @{ ANTHROPIC_BASE_URL = $secret } } |
            ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $profilePath

        InModuleScope ClaudeGuard -Parameters @{
            ProfilePath = $profilePath
            Secret = $secret
        } {
            $result = Test-GuardLegacyProfile -ProfilePath $ProfilePath -Mode 'warn'

            $result.status | Should -BeExactly 'warn'
            $result.exit_code | Should -Be 0
            ($result | ConvertTo-GuardJson) | Should -Not -Match ([regex]::Escape($Secret))
        }
    }

    It 'blocks contaminated legacy settings in strict mode' {
        $profilePath = Join-Path $TestDrive 'legacy-strict.json'
        '{"apiKeyHelper":"helper.exe"}' | Set-Content -LiteralPath $profilePath

        InModuleScope ClaudeGuard -Parameters @{ ProfilePath = $profilePath } {
            $result = Test-GuardLegacyProfile -ProfilePath $ProfilePath -Mode 'strict'

            $result.code | Should -BeExactly 'CG_LEGACY_PROFILE_CONTAMINATED'
            $result.exit_code | Should -Be 11
        }
    }

    It 'does not inspect the legacy path when policy is off' {
        $missingPath = Join-Path $TestDrive 'missing\settings.json'

        InModuleScope ClaudeGuard -Parameters @{ MissingPath = $missingPath } {
            $result = Test-GuardLegacyProfile -ProfilePath $MissingPath -Mode 'off'

            $result.status | Should -BeExactly 'pass'
        }
    }
}
