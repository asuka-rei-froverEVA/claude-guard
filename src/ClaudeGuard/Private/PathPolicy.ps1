function ConvertTo-GuardPathOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [AllowNull()]
        [string]$Path,

        [bool]$IsReparsePoint = $false
    )

    [pscustomobject][ordered]@{
        Result         = $Result
        Path           = $Path
        IsReparsePoint = $IsReparsePoint
    }
}

function Resolve-GuardPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('File', 'Directory')]
        [string]$Kind,

        [switch]$RejectReparsePoint
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
        $result = New-GuardResult `
            -Code 'CG_PATH_NOT_ABSOLUTE' -ExitCode 2 -Status 'fail' `
            -Reason 'A configured path is not absolute.' `
            -Remediation 'Use an absolute native Windows path.' `
            -Evidence @{ kind = $Kind }
        return ConvertTo-GuardPathOutcome -Result $result -Path $null
    }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    catch {
        $result = New-GuardResult `
            -Code 'CG_PATH_NOT_FOUND' -ExitCode 2 -Status 'fail' `
            -Reason 'A configured path does not exist or cannot be inspected.' `
            -Remediation 'Correct the path and verify the current user can read it.' `
            -Evidence @{ kind = $Kind }
        return ConvertTo-GuardPathOutcome -Result $result -Path $null
    }

    $isExpectedKind = if ($Kind -eq 'File') {
        $item -is [IO.FileInfo]
    }
    else {
        $item -is [IO.DirectoryInfo]
    }
    if (-not $isExpectedKind) {
        $result = New-GuardResult `
            -Code 'CG_PATH_KIND_INVALID' -ExitCode 2 -Status 'fail' `
            -Reason ('The configured path is not a regular {0}.' -f $Kind.ToLowerInvariant()) `
            -Remediation ('Select an existing regular {0}.' -f $Kind.ToLowerInvariant()) `
            -Evidence @{ kind = $Kind }
        return ConvertTo-GuardPathOutcome -Result $result -Path $null
    }

    $isReparsePoint = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    if ($RejectReparsePoint -and $isReparsePoint) {
        $result = New-GuardResult `
            -Code 'CG_PATH_REPARSE_POINT' -ExitCode 2 -Status 'fail' `
            -Reason 'A security-sensitive path is a filesystem reparse point.' `
            -Remediation 'Use the real regular file or directory instead of a link or junction.' `
            -Evidence @{ kind = $Kind }
        return ConvertTo-GuardPathOutcome `
            -Result $result `
            -Path $item.FullName `
            -IsReparsePoint $true
    }

    $result = New-GuardResult `
        -Code 'CG_PATH_VALID' -ExitCode 0 -Status 'pass' `
        -Reason ('The configured {0} path is valid.' -f $Kind.ToLowerInvariant()) `
        -Remediation '' `
        -Evidence @{ kind = $Kind }
    ConvertTo-GuardPathOutcome `
        -Result $result `
        -Path $item.FullName `
        -IsReparsePoint $isReparsePoint
}

function Test-GuardPathIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Left,

        [Parameter(Mandatory)]
        [string]$Right
    )

    try {
        $leftFullPath = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Left))
        $rightFullPath = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Right))
    }
    catch {
        return $false
    }

    [StringComparer]::OrdinalIgnoreCase.Equals($leftFullPath, $rightFullPath)
}

function Protect-GuardPath {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Path,

        [AllowNull()]
        [string]$UserProfile
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return '<not-set>'
    }
    if (-not [string]::IsNullOrWhiteSpace($UserProfile)) {
        $profileRoot = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($UserProfile))
        $fullPath = [IO.Path]::GetFullPath($Path)
        if ($fullPath.Equals($profileRoot, [StringComparison]::OrdinalIgnoreCase)) {
            return '<user-profile>'
        }
        $prefix = $profileRoot + [IO.Path]::DirectorySeparatorChar
        if ($fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return '<user-profile>' + $fullPath.Substring($profileRoot.Length)
        }
    }
    [IO.Path]::GetFullPath($Path)
}
