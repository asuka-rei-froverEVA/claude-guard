[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments)]
    [AllowEmptyCollection()]
    [string[]]$GuardArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    [Console]::Error.WriteLine(
        'CG_POWERSHELL_UNSUPPORTED: PowerShell 7.4 or newer is required. Install the current PowerShell 7 release and retry.'
    )
    exit 2
}

$modulePath = Join-Path $PSScriptRoot '..\src\ClaudeGuard\ClaudeGuard.psd1'
$module = Import-Module $modulePath -Force -PassThru

if ($GuardArguments.Count -eq 1 -and $GuardArguments[0] -eq '--version') {
    Write-Output ('claude-guard windows {0}' -f $module.Version)
    exit 0
}

[Console]::Error.WriteLine(
    'CG_WINDOWS_NOT_IMPLEMENTED: native Windows preflight commands are still being assembled on this branch.'
)
exit 2
