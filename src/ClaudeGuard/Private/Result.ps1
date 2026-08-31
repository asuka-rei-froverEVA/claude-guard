function New-GuardResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This pure factory creates an in-memory result object and changes no system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Code,

        [Parameter(Mandatory)]
        [ValidateRange(0, 255)]
        [int]$ExitCode,

        [Parameter(Mandatory)]
        [ValidateSet('pass', 'warn', 'fail', 'unknown')]
        [string]$Status,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Reason,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Remediation,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Evidence
    )

    [pscustomobject][ordered]@{
        code        = $Code
        exit_code   = $ExitCode
        status      = $Status
        reason      = $Reason
        remediation = $Remediation
        evidence    = $Evidence
    }
}

function ConvertTo-GuardJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject
    )

    process {
        $InputObject | ConvertTo-Json -Depth 12 -Compress
    }
}
