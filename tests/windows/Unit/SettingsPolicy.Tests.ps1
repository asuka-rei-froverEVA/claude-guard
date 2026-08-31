BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    $script:SafeSettingsFixturePath = Join-Path $PSScriptRoot '..\Fixtures\settings\official-safe.json'
}

Describe 'Windows settings policy' {
    It 'accepts the complete official foreground lifecycle policy' {
        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $script:SafeSettingsFixturePath } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @('blocked@example') `
                -BlockedModels @('blocked-model') `
                -RequireUnpinnedModel $true

            $result.status | Should -BeExactly 'pass'
        }
    }

    It 'rejects route credential certificate and retry overrides without exposing values' -ForEach @(
        @{ Key = 'ANTHROPIC_BASE_URL'; Secret = 'https://secret.invalid' }
        @{ Key = 'ANTHROPIC_AUTH_TOKEN'; Secret = 'token-secret-value' }
        @{ Key = 'apiKeyHelper'; Secret = 'credential-helper-secret' }
        @{ Key = 'HTTP_PROXY'; Secret = 'http://user:password@proxy.invalid:8080' }
        @{ Key = 'NODE_EXTRA_CA_CERTS'; Secret = 'C:\secret\root.pem' }
        @{ Key = 'CLAUDE_CODE_RETRY_WATCHDOG'; Secret = '1' }
    ) {
        $settingsPath = Join-Path $TestDrive ("risk-{0}.json" -f $Key)
        $settings = Get-Content -LiteralPath $script:SafeSettingsFixturePath -Raw | ConvertFrom-Json -AsHashtable
        if ($Key -eq 'apiKeyHelper') {
            $settings[$Key] = $Secret
        }
        else {
            $settings.env[$Key] = $Secret
        }
        $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $settingsPath

        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $settingsPath; Secret = $Secret } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @() `
                -BlockedModels @() `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_SETTINGS_RISK_OVERRIDE'
            $result.exit_code | Should -Be 5
            ($result | ConvertTo-GuardJson) | Should -Not -Match ([regex]::Escape($Secret))
        }
    }

    It 'rejects a CC Switch route marker even when its JSON key looks harmless' {
        $settingsPath = Join-Path $TestDrive 'cc-route.json'
        $settings = Get-Content -LiteralPath $script:SafeSettingsFixturePath -Raw | ConvertFrom-Json -AsHashtable
        $settings['harmless'] = 'http://127.0.0.1:15721'
        $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $settingsPath

        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $settingsPath } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @() `
                -BlockedModels @() `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_SETTINGS_RISK_OVERRIDE'
        }
    }

    It 'fails when a required lifecycle protection is missing' {
        $settingsPath = Join-Path $TestDrive 'missing-lifecycle.json'
        $settings = Get-Content -LiteralPath $script:SafeSettingsFixturePath -Raw | ConvertFrom-Json -AsHashtable
        $settings.Remove('disableRemoteControl')
        $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $settingsPath

        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $settingsPath } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @() `
                -BlockedModels @() `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_LIFECYCLE_POLICY_REQUIRED'
            $result.exit_code | Should -Be 13
            $result.evidence.paths | Should -Contain 'disableRemoteControl'
        }
    }

    It 'rejects a locally blocked enabled plugin' {
        $settingsPath = Join-Path $TestDrive 'blocked-plugin.json'
        $settings = Get-Content -LiteralPath $script:SafeSettingsFixturePath -Raw | ConvertFrom-Json -AsHashtable
        $settings.enabledPlugins = @{ 'blocked@example' = $true }
        $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $settingsPath

        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $settingsPath } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @('blocked@example') `
                -BlockedModels @() `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_PLUGIN_BLOCKED'
            $result.exit_code | Should -Be 13
        }
    }

    It 'rejects a settings-pinned model when unpinned selection is required' {
        $settingsPath = Join-Path $TestDrive 'pinned-model.json'
        $settings = Get-Content -LiteralPath $script:SafeSettingsFixturePath -Raw | ConvertFrom-Json -AsHashtable
        $settings.model = 'sonnet'
        $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $settingsPath

        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $settingsPath } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @() `
                -BlockedModels @() `
                -RequireUnpinnedModel $true

            $result.code | Should -BeExactly 'CG_MODEL_PINNED_IN_SETTINGS'
            $result.exit_code | Should -Be 6
        }
    }

    It 'rejects an explicitly blocked settings model' {
        $settingsPath = Join-Path $TestDrive 'blocked-model.json'
        $settings = Get-Content -LiteralPath $script:SafeSettingsFixturePath -Raw | ConvertFrom-Json -AsHashtable
        $settings.model = 'blocked-model'
        $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $settingsPath

        InModuleScope ClaudeGuard -Parameters @{ SettingsPath = $settingsPath } {
            $result = Test-GuardSettings `
                -SettingsPath $SettingsPath `
                -BlockedPlugins @() `
                -BlockedModels @('blocked-model') `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_MODEL_BLOCKED'
            $result.exit_code | Should -Be 6
        }
    }

    It 'allows an empty project settings object but rejects a lifecycle downgrade' {
        $safeProjectPath = Join-Path $TestDrive 'project-safe.json'
        $unsafeProjectPath = Join-Path $TestDrive 'project-unsafe.json'
        '{}' | Set-Content -LiteralPath $safeProjectPath
        '{"disableRemoteControl":false}' | Set-Content -LiteralPath $unsafeProjectPath

        InModuleScope ClaudeGuard -Parameters @{
            SafeProjectPath = $safeProjectPath
            UnsafeProjectPath = $unsafeProjectPath
        } {
            $safe = Test-GuardSettings `
                -SettingsPath $SafeProjectPath `
                -BlockedPlugins @() `
                -BlockedModels @() `
                -RequireUnpinnedModel $false `
                -Project
            $unsafe = Test-GuardSettings `
                -SettingsPath $UnsafeProjectPath `
                -BlockedPlugins @() `
                -BlockedModels @() `
                -RequireUnpinnedModel $false `
                -Project

            $safe.status | Should -BeExactly 'pass'
            $unsafe.code | Should -BeExactly 'CG_PROJECT_LIFECYCLE_DOWNGRADE'
            $unsafe.exit_code | Should -Be 13
        }
    }

    It 'discovers project settings from the current directory up to but not including the profile boundary' {
        $projectRoot = Join-Path $TestDrive 'project'
        $nestedPath = Join-Path $projectRoot 'src\nested'
        $claudeDirectory = Join-Path $projectRoot '.claude'
        New-Item -ItemType Directory -Path $nestedPath -Force | Out-Null
        New-Item -ItemType Directory -Path $claudeDirectory | Out-Null
        '{}' | Set-Content -LiteralPath (Join-Path $claudeDirectory 'settings.json')
        '{}' | Set-Content -LiteralPath (Join-Path $claudeDirectory 'settings.local.json')
        New-Item -ItemType Directory -Path (Join-Path $TestDrive '.claude') | Out-Null
        '{}' | Set-Content -LiteralPath (Join-Path $TestDrive '.claude\settings.json')

        InModuleScope ClaudeGuard -Parameters @{
            NestedPath = $nestedPath
            Boundary = $TestDrive
            ClaudeDirectory = $claudeDirectory
        } {
            $found = @(Find-GuardProjectSettings -StartPath $NestedPath -ProfileBoundary $Boundary)

            $found | Should -Be @(
                (Join-Path $ClaudeDirectory 'settings.json')
                (Join-Path $ClaudeDirectory 'settings.local.json')
            )
        }
    }
}
