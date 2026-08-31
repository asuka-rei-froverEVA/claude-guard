function Write-GuardResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [switch]$Json
    )

    if ($Json) {
        return ConvertTo-GuardJson -InputObject $Result
    }

    Write-Output ('[{0}] {1}: {2}' -f $Result.status, $Result.code, $Result.reason)
    if (-not [string]::IsNullOrWhiteSpace([string]$Result.remediation)) {
        Write-Output ('Remediation: {0}' -f $Result.remediation)
    }
}
