Describe 'Windows verification harness' {
    It 'stays offline and explains the explicit bootstrap when pinned tools are missing' {
        $checkScript = Join-Path $PSScriptRoot '..\..\..\scripts\check-windows.ps1'
        $missingToolRoot = Join-Path $TestDrive 'missing-tools'

        $output = & pwsh -NoLogo -NoProfile -File $checkScript `
            -ToolRoot $missingToolRoot 2>&1

        $LASTEXITCODE | Should -Not -Be 0
        (@($output) -join "`n") | Should -Match `
            'Run: pwsh -NoProfile -File scripts/bootstrap-windows-tests\.ps1'
        (Test-Path -LiteralPath $missingToolRoot) | Should -BeFalse
    }
}
