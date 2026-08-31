[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'PowerShell 7.4 or newer is required to bootstrap Windows tests.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $repositoryRoot '.tools\powershell'
$requiredModules = [ordered]@{
    Pester           = '6.0.1'
    PSScriptAnalyzer = '1.25.0'
}

New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null

foreach ($entry in $requiredModules.GetEnumerator()) {
    $manifestPath = Join-Path $toolRoot ('{0}\{1}\{0}.psd1' -f $entry.Key, $entry.Value)
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        continue
    }

    Write-Information `
        -MessageData ('Installing {0} {1} into {2}' -f $entry.Key, $entry.Value, $toolRoot) `
        -InformationAction Continue
    Save-PSResource `
        -Name $entry.Key `
        -Version $entry.Value `
        -Path $toolRoot `
        -Repository PSGallery `
        -TrustRepository `
        -ErrorAction Stop
}

Write-Information -MessageData 'Windows test dependencies are ready.' -InformationAction Continue
