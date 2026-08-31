BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows child environment policy' {
    It 'keeps the Windows runtime baseline and replaces untrusted routing and lifecycle values' {
        $source = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $source['SystemRoot'] = 'C:\Windows'
        $source['WINDIR'] = 'C:\Windows'
        $source['ComSpec'] = 'C:\Windows\System32\cmd.exe'
        $source['PATH'] = 'C:\Windows\System32'
        $source['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
        $source['TEMP'] = 'C:\Temp'
        $source['TMP'] = 'C:\Temp'
        $source['USERPROFILE'] = 'C:\Users\example'
        $source['APPDATA'] = 'C:\Users\example\AppData\Roaming'
        $source['LOCALAPPDATA'] = 'C:\Users\example\AppData\Local'
        $source['ProgramData'] = 'C:\ProgramData'
        $source['ProgramFiles'] = 'C:\Program Files'
        $source['ProgramFiles(x86)'] = 'C:\Program Files (x86)'
        $source['ANTHROPIC_BASE_URL'] = 'https://route-secret.invalid'
        $source['anthropic_auth_token'] = 'token-secret'
        $source['ANTHROPIC_API_KEY'] = 'api-secret'
        $source['HTTP_PROXY'] = 'http://attacker.invalid:8080'
        $source['node_extra_ca_certs'] = 'C:\attacker\root.pem'
        $source['CLAUDE_CODE_USE_BEDROCK'] = '1'
        $source['CLAUDE_CODE_DISABLE_BACKGROUND_TASKS'] = '1'
        $source['CLAUDE_AUTO_BACKGROUND_TASKS'] = '1'
        $source['CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS'] = '1'
        $source['CLAUDE_CODE_RETRY_WATCHDOG'] = '1'
        $source['CLAUDE_GUARD_CONFIG'] = 'C:\secret\guard.json'
        $source['ARBITRARY_SECRET'] = 'must-not-pass'

        InModuleScope ClaudeGuard -Parameters @{ Source = $source } {
            $child = New-GuardChildEnvironment `
                -Source $Source `
                -ConfigDir 'C:\Users\example\.claude-official' `
                -ProxyUri ([uri]'http://127.0.0.1:7897') `
                -CaCertPath 'C:\Guard\roots.pem'

            $child.Comparer | Should -Be ([StringComparer]::OrdinalIgnoreCase)
            $child['SystemRoot'] | Should -BeExactly 'C:\Windows'
            $child['ProgramFiles(x86)'] | Should -BeExactly 'C:\Program Files (x86)'
            $child['CLAUDE_CONFIG_DIR'] | Should -BeExactly 'C:\Users\example\.claude-official'
            $child['HTTP_PROXY'] | Should -BeExactly 'http://127.0.0.1:7897/'
            $child['HTTPS_PROXY'] | Should -BeExactly 'http://127.0.0.1:7897/'
            $child['ALL_PROXY'] | Should -BeExactly 'http://127.0.0.1:7897/'
            $child['NO_PROXY'] | Should -BeExactly '127.0.0.1,localhost,::1,.local'
            $child['DISABLE_UPDATES'] | Should -BeExactly '1'
            $child['CLAUDE_CODE_DISABLE_CRON'] | Should -BeExactly '1'
            $child['CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS'] | Should -BeExactly '0'
            $child['CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH'] | Should -BeExactly '1'
            $child['CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS'] | Should -BeExactly '3'
            $child['CLAUDE_CODE_CERT_STORE'] | Should -BeExactly 'system'
            $child['SSL_CERT_FILE'] | Should -BeExactly 'C:\Guard\roots.pem'
            $child['NODE_EXTRA_CA_CERTS'] | Should -BeExactly 'C:\Guard\roots.pem'

            foreach ($name in @(
                'ANTHROPIC_BASE_URL',
                'ANTHROPIC_AUTH_TOKEN',
                'ANTHROPIC_API_KEY',
                'CLAUDE_CODE_USE_BEDROCK',
                'CLAUDE_CODE_DISABLE_BACKGROUND_TASKS',
                'CLAUDE_AUTO_BACKGROUND_TASKS',
                'CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS',
                'CLAUDE_CODE_RETRY_WATCHDOG',
                'CLAUDE_GUARD_CONFIG',
                'ARBITRARY_SECRET'
            )) {
                $child.ContainsKey($name) | Should -BeFalse
            }
        }
    }

    It 'uses the Windows certificate store without injecting a PEM path by default' {
        $source = @{ SystemRoot = 'C:\Windows'; PATH = 'C:\Windows\System32' }

        InModuleScope ClaudeGuard -Parameters @{ Source = $source } {
            $child = New-GuardChildEnvironment `
                -Source $Source `
                -ConfigDir 'C:\Profile' `
                -ProxyUri ([uri]'http://127.0.0.1:7897')

            $child['CLAUDE_CODE_CERT_STORE'] | Should -BeExactly 'system'
            $child.ContainsKey('SSL_CERT_FILE') | Should -BeFalse
            $child.ContainsKey('NODE_EXTRA_CA_CERTS') | Should -BeFalse
        }
    }
}
