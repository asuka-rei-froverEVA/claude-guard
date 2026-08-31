[CmdletBinding()]
param(
    [switch]$SkipBootstrap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'PowerShell 7.4 or newer is required to run Windows checks.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $repositoryRoot '.tools\powershell'

if (-not $SkipBootstrap) {
    & (Join-Path $PSScriptRoot 'bootstrap-windows-tests.ps1')
}

$env:PSModulePath = '{0}{1}{2}' -f $toolRoot, [IO.Path]::PathSeparator, $env:PSModulePath

$moduleManifest = Join-Path $repositoryRoot 'src\ClaudeGuard\ClaudeGuard.psd1'
Import-Module $moduleManifest -Force -ErrorAction Stop

Import-Module Pester -RequiredVersion 6.0.1 -Force -ErrorAction Stop
$pesterConfiguration = New-PesterConfiguration
$pesterConfiguration.Run.Path = Join-Path $repositoryRoot 'tests\windows'
$pesterConfiguration.Run.PassThru = $true
$pesterConfiguration.Output.Verbosity = 'Detailed'
$pesterResult = Invoke-Pester -Configuration $pesterConfiguration
if ($pesterResult.FailedCount -gt 0 -or $pesterResult.FailedContainersCount -gt 0) {
    throw ('Pester failed: {0} failed tests and {1} failed containers.' -f `
        $pesterResult.FailedCount, $pesterResult.FailedContainersCount)
}

Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force -ErrorAction Stop
$analysisTargets = @(
    (Join-Path $repositoryRoot 'bin\claude-guard.ps1')
    (Join-Path $repositoryRoot 'scripts\bootstrap-windows-tests.ps1')
    (Join-Path $repositoryRoot 'scripts\check-windows.ps1')
    (Join-Path $repositoryRoot 'src\ClaudeGuard')
    (Join-Path $repositoryRoot 'tests\windows')
)
$analysisResults = @(
    foreach ($target in $analysisTargets) {
        Invoke-ScriptAnalyzer -Path $target -Recurse -Severity Warning, Error
    }
)

if ($analysisResults.Count -gt 0) {
    $analysisResults | Format-Table -AutoSize | Out-String | Write-Error
    throw ('PSScriptAnalyzer reported {0} finding(s).' -f $analysisResults.Count)
}

Write-Information -MessageData 'Windows checks passed.' -InformationAction Continue
