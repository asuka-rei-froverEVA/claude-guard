Describe 'Guard result contract' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..\..\..\src\ClaudeGuard\ClaudeGuard.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    }

    It 'returns the stable fields and preserves nested evidence in JSON' {
        (Test-Path -LiteralPath $modulePath -PathType Leaf) | Should -BeTrue

        InModuleScope ClaudeGuard {
            $result = New-GuardResult `
                -Code 'CG_TEST' `
                -ExitCode 7 `
                -Status 'fail' `
                -Reason 'test failure' `
                -Remediation 'fix it' `
                -Evidence @{ tls = @{ chain_valid = $false } }

            @($result.PSObject.Properties.Name) | Should -Be @(
                'code'
                'exit_code'
                'status'
                'reason'
                'remediation'
                'evidence'
            )

            $json = ConvertTo-GuardJson -InputObject $result
            $json | Should -Match '"chain_valid":false'
            $json | Should -Not -Match ([char]27)
        }
    }

    It 'renders machine JSON without presentation bytes' {
        InModuleScope ClaudeGuard {
            $result = New-GuardResult `
                -Code 'CG_TEST' `
                -ExitCode 7 `
                -Status 'fail' `
                -Reason 'test failure' `
                -Remediation 'fix it' `
                -Evidence @{ value = 'bounded' }

            $rendered = Write-GuardResult -Result $result -Json

            $rendered | Should -BeExactly '{"code":"CG_TEST","exit_code":7,"status":"fail","reason":"test failure","remediation":"fix it","evidence":{"value":"bounded"}}'
            $rendered | Should -Not -Match ([char]27)
        }
    }

    It 'renders the symbolic code reason and remediation for a person' {
        InModuleScope ClaudeGuard {
            $result = New-GuardResult `
                -Code 'CG_TEST' `
                -ExitCode 7 `
                -Status 'fail' `
                -Reason 'test failure' `
                -Remediation 'fix it' `
                -Evidence @{}

            $rendered = @(Write-GuardResult -Result $result)

            $rendered | Should -Be @(
                '[fail] CG_TEST: test failure'
                'Remediation: fix it'
            )
        }
    }
}
