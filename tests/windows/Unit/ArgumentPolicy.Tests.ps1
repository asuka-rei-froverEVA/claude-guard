BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Windows CLI argument policy' {
    It 'rejects settings and detached lifecycle bypass arguments' -ForEach @(
        @{ Argument = '--settings'; Extra = 'alternate.json' }
        @{ Argument = '--settings=alternate.json'; Extra = $null }
        @{ Argument = '--setting-sources'; Extra = 'project' }
        @{ Argument = '--setting-sources=project'; Extra = $null }
        @{ Argument = '--bg'; Extra = $null }
        @{ Argument = '--background=true'; Extra = $null }
        @{ Argument = 'agents'; Extra = $null }
        @{ Argument = 'attach'; Extra = $null }
        @{ Argument = 'respawn'; Extra = $null }
        @{ Argument = '--tmux'; Extra = $null }
        @{ Argument = '--remote-control'; Extra = $null }
        @{ Argument = 'remote-control'; Extra = $null }
    ) {
        $arguments = @($Argument)
        if ($null -ne $Extra) { $arguments += $Extra }

        InModuleScope ClaudeGuard -Parameters @{ Arguments = $arguments } {
            $result = Test-GuardArguments `
                -Arguments $Arguments `
                -BlockedModels @() `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_ARGUMENT_LIFECYCLE_BYPASS'
            $result.exit_code | Should -Be 13
        }
    }

    It 'rejects blocked models in split and equals forms' -ForEach @(
        @{ Arguments = @('--model', 'blocked-model') }
        @{ Arguments = @('--model=blocked-model') }
    ) {
        InModuleScope ClaudeGuard -Parameters @{ Arguments = $Arguments } {
            $result = Test-GuardArguments `
                -Arguments $Arguments `
                -BlockedModels @('blocked-model') `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_MODEL_BLOCKED'
            $result.exit_code | Should -Be 6
        }
    }

    It 'rejects a model option whose value is missing' -ForEach @(
        @{ Arguments = @('--model') }
        @{ Arguments = @('--model', '') }
        @{ Arguments = @('--model=') }
    ) {
        InModuleScope ClaudeGuard -Parameters @{ Arguments = $Arguments } {
            $result = Test-GuardArguments `
                -Arguments $Arguments `
                -BlockedModels @() `
                -RequireUnpinnedModel $false

            $result.code | Should -BeExactly 'CG_ARGUMENT_VALUE_MISSING'
            $result.exit_code | Should -Be 2
        }
    }

    It 'accepts allowed arguments without changing order spelling Unicode or empty values' {
        $unicodePrompt = '{0}{1} world' -f [char]0x4F60, [char]0x597D
        $arguments = @('--model', 'sonnet', '--append-system-prompt', $unicodePrompt, '--', '', '-literal')
        $snapshot = @($arguments)

        InModuleScope ClaudeGuard -Parameters @{ Arguments = $arguments } {
            $result = Test-GuardArguments `
                -Arguments $Arguments `
                -BlockedModels @('blocked-model') `
                -RequireUnpinnedModel $true

            $result.status | Should -BeExactly 'pass'
        }
        $arguments | Should -Be $snapshot
    }
}
