Set-StrictMode -Version Latest

$script:ClaudeGuardModuleVersion = '0.1.0'

$sourceDirectories = @('Private', 'Public')
foreach ($sourceDirectory in $sourceDirectories) {
    $directoryPath = Join-Path $PSScriptRoot $sourceDirectory
    if (-not (Test-Path -LiteralPath $directoryPath -PathType Container)) {
        continue
    }

    Get-ChildItem -LiteralPath $directoryPath -Filter '*.ps1' -File |
        Sort-Object -Property Name |
        ForEach-Object { . $_.FullName }
}
