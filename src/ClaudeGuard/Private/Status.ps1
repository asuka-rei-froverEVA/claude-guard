function ConvertTo-GuardStatusCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result
    )

    $check = [ordered]@{
        status = $Result.status
        code   = $Result.code
    }
    if ($Result.evidence -is [System.Collections.IDictionary]) {
        foreach ($key in $Result.evidence.Keys) {
            $check[[string]$key] = $Result.evidence[$key]
        }
    }
    [pscustomobject]$check
}

function Get-GuardMatchingProcessState {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$CommandPath
    )

    if ([string]::IsNullOrWhiteSpace($CommandPath)) {
        return [pscustomobject][ordered]@{
            status = 'unavailable'
            count  = $null
        }
    }

    try {
        $count = 0
        foreach ($process in @(Get-Process -ErrorAction Stop)) {
            try {
                if (-not [string]::IsNullOrWhiteSpace($process.Path) -and
                    (Test-GuardPathIdentity -Left $process.Path -Right $CommandPath)) {
                    $count++
                }
            }
            catch {
                continue
            }
        }
        [pscustomobject][ordered]@{
            status = 'observed'
            count  = $count
        }
    }
    catch {
        [pscustomobject][ordered]@{
            status = 'unavailable'
            count  = $null
        }
    }
}
