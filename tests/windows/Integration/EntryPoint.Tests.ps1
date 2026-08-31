Describe 'Windows entry point' {
    It 'reports its Windows module version without loading a config or using the network' {
        $entryPoint = Join-Path $PSScriptRoot '..\..\..\bin\claude-guard.ps1'
        (Test-Path -LiteralPath $entryPoint -PathType Leaf) | Should -BeTrue

        $output = & pwsh -NoLogo -NoProfile -File $entryPoint --version 2>&1
        $LASTEXITCODE | Should -Be 0
        @($output) | Should -Be @('claude-guard windows 0.1.0')
    }
}
