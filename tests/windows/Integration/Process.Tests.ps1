BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows foreground Claude process' {
    It 'preserves exact argument boundaries uses only the supplied environment and returns the child exit code' {
        $fixturePath = Join-Path $PSScriptRoot '..\Fixtures\fake-claude.ps1'
        $outputPath = Join-Path $TestDrive 'captured.json'
        $unicodeValue = '{0}{1}' -f [char]0x4F60, [char]0x597D
        $arguments = @(
            '-NoLogo',
            '-NoProfile',
            '-File',
            $fixturePath,
            'space value',
            '"quoted"',
            $unicodeValue,
            '',
            '-literal'
        )
        $childEnvironment = [Collections.Generic.Dictionary[string, string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($name in @('SystemRoot', 'WINDIR', 'ComSpec', 'PATH', 'PATHEXT', 'TEMP', 'TMP')) {
            $value = [Environment]::GetEnvironmentVariable($name)
            if ($null -ne $value) { $childEnvironment[$name] = $value }
        }
        $childEnvironment['CG_TEST_OUTPUT'] = $outputPath
        $childEnvironment['CG_TEST_EXIT'] = '23'
        $childEnvironment['CG_TEST_SENTINEL'] = 'present'
        $childEnvironment['CLAUDE_CONFIG_DIR'] = 'C:\OfficialProfile'
        $childEnvironment['HTTP_PROXY'] = 'http://127.0.0.1:7897/'

        InModuleScope ClaudeGuard -Parameters @{
            Arguments = $arguments
            ChildEnvironment = $childEnvironment
        } {
            $exitCode = Start-GuardClaudeProcess `
                -CommandPath (Get-Command pwsh).Source `
                -Arguments $Arguments `
                -Environment $ChildEnvironment

            $exitCode | Should -Be 23
        }

        $captured = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        @($captured.arguments) | Should -Be @(
            'space value',
            '"quoted"',
            $unicodeValue,
            '',
            '-literal'
        )
        $captured.environment.CG_TEST_SENTINEL | Should -BeExactly 'present'
        $captured.environment.CLAUDE_CONFIG_DIR | Should -BeExactly 'C:\OfficialProfile'
        $captured.environment.HTTP_PROXY | Should -BeExactly 'http://127.0.0.1:7897/'
        $captured.environment.ANTHROPIC_BASE_URL | Should -BeNullOrEmpty
        $captured.environment.ANTHROPIC_AUTH_TOKEN | Should -BeNullOrEmpty
    }
}
