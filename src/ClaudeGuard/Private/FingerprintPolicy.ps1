$script:GuardLegacyMarkerPattern = [regex]::new(
    'ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|apiKeyHelper|127\.0\.0\.1:15721|PROXY_MANAGED|CLAUDE_CODE_USE_GATEWAY',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$script:GuardFingerprintTimeZonePattern = [regex]::new('Asia/Shanghai|Asia/Urumqi')
$script:GuardFingerprintWatermarkPattern = [regex]::new(
    '\\u02BC|\\u02B9|Today.{0,512}date is|date is.{0,512}replaceAll|date is.{0,512}replace\(',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase
)

function Find-GuardClientFingerprintMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $buffer = [byte[]]::new(65536)
        $tail = ''
        $timeZoneFound = $false
        $watermarkFound = $false
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $text = $tail + [Text.Encoding]::Latin1.GetString($buffer, 0, $read)
            if ($script:GuardFingerprintTimeZonePattern.IsMatch($text)) {
                $timeZoneFound = $true
            }
            if ($script:GuardFingerprintWatermarkPattern.IsMatch($text)) {
                $watermarkFound = $true
            }
            if ($timeZoneFound -and $watermarkFound) {
                break
            }
            $tailLength = [Math]::Min(1024, $text.Length)
            $tail = $text.Substring($text.Length - $tailLength, $tailLength)
        }

        [pscustomobject][ordered]@{
            Success     = $true
            MarkerFound = $timeZoneFound -and $watermarkFound
        }
    }
    catch {
        [pscustomobject][ordered]@{
            Success     = $false
            MarkerFound = $false
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Test-GuardClientFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandPath,

        [Parameter(Mandatory)]
        [ValidateSet('off', 'warn', 'fail-active', 'strict')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Environment,

        [string]$TimeZoneId = [TimeZoneInfo]::Local.Id
    )

    if ($Mode -eq 'off') {
        return New-GuardResult `
            -Code 'CG_FINGERPRINT_DISABLED' -ExitCode 0 -Status 'pass' `
            -Reason 'The client fingerprint tripwire is disabled by explicit policy.' `
            -Remediation '' `
            -Evidence @{ mode = 'off' }
    }

    $resolved = Resolve-GuardPath -Path $CommandPath -Kind File -RejectReparsePoint
    $scan = if ($resolved.Result.status -eq 'pass') {
        Find-GuardClientFingerprintMarker -Path $resolved.Path
    }
    else {
        [pscustomobject]@{ Success = $false; MarkerFound = $false }
    }
    if (-not $scan.Success) {
        if ($Mode -in @('strict', 'fail-active')) {
            return New-GuardResult `
                -Code 'CG_FINGERPRINT_SCAN_FAILED' -ExitCode 10 -Status 'fail' `
                -Reason 'The configured client could not be scanned for known fingerprint markers.' `
                -Remediation 'Use a readable regular native Claude executable.' `
                -Evidence @{ mode = $Mode }
        }
        return New-GuardResult `
            -Code 'CG_FINGERPRINT_SCAN_WARNING' -ExitCode 0 -Status 'warn' `
            -Reason 'The configured client could not be scanned in warning mode.' `
            -Remediation 'Inspect the native Claude executable before using a blocking mode.' `
            -Evidence @{ mode = $Mode }
    }

    if (-not $scan.MarkerFound) {
        return New-GuardResult `
            -Code 'CG_FINGERPRINT_CLEAR' -ExitCode 0 -Status 'pass' `
            -Reason 'The configured client does not contain the paired known watermark markers.' `
            -Remediation '' `
            -Evidence @{ mode = $Mode }
    }

    $environmentValues = ConvertTo-GuardEnvironmentDictionary -Environment $Environment
    $activationReasons = @()
    if ($environmentValues.ContainsKey('ANTHROPIC_BASE_URL') -and
        -not [string]::IsNullOrWhiteSpace([string]$environmentValues['ANTHROPIC_BASE_URL'])) {
        $activationReasons += 'base_url_present'
    }
    if ($TimeZoneId -in @('Asia/Shanghai', 'Asia/Urumqi')) {
        $activationReasons += 'timezone'
    }

    if ($Mode -eq 'strict') {
        return New-GuardResult `
            -Code 'CG_FINGERPRINT_BLOCKED' -ExitCode 10 -Status 'fail' `
            -Reason 'The configured client contains the paired known watermark markers.' `
            -Remediation 'Replace the client with a reviewed clean native Claude executable.' `
            -Evidence @{ mode = $Mode; activation = $activationReasons }
    }
    if ($Mode -eq 'fail-active' -and $activationReasons.Count -gt 0) {
        return New-GuardResult `
            -Code 'CG_FINGERPRINT_ACTIVE' -ExitCode 10 -Status 'fail' `
            -Reason 'Known watermark markers and an upstream activation condition are both present.' `
            -Remediation 'Remove the route override or use a clean timezone/profile and reviewed client.' `
            -Evidence @{ mode = $Mode; activation = $activationReasons }
    }

    New-GuardResult `
        -Code 'CG_FINGERPRINT_WARNING' -ExitCode 0 -Status 'warn' `
        -Reason 'Known watermark markers were found, but the selected mode does not block this state.' `
        -Remediation 'Review and replace the client before enabling strict enforcement.' `
        -Evidence @{ mode = $Mode; activation = $activationReasons }
}

function Test-GuardLegacyProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProfilePath,

        [Parameter(Mandatory)]
        [ValidateSet('off', 'warn', 'strict')]
        [string]$Mode
    )

    if ($Mode -eq 'off') {
        return New-GuardResult `
            -Code 'CG_LEGACY_PROFILE_DISABLED' -ExitCode 0 -Status 'pass' `
            -Reason 'Legacy profile inspection is disabled by explicit policy.' `
            -Remediation '' `
            -Evidence @{ mode = $Mode }
    }
    if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
        return New-GuardResult `
            -Code 'CG_LEGACY_PROFILE_ABSENT' -ExitCode 0 -Status 'pass' `
            -Reason 'No legacy default settings file is present.' `
            -Remediation '' `
            -Evidence @{ mode = $Mode }
    }

    try {
        $item = Get-Item -LiteralPath $ProfilePath -Force -ErrorAction Stop
        if ($item.Length -gt 1048576) {
            throw 'The legacy settings file exceeds the bounded scan size.'
        }
        $content = Get-Content -LiteralPath $ProfilePath -Raw -ErrorAction Stop
    }
    catch {
        if ($Mode -eq 'strict') {
            return New-GuardResult `
                -Code 'CG_LEGACY_PROFILE_SCAN_FAILED' -ExitCode 11 -Status 'fail' `
                -Reason 'The legacy default profile could not be scanned in strict mode.' `
                -Remediation 'Inspect or remove the legacy settings file.' `
                -Evidence @{ mode = $Mode }
        }
        return New-GuardResult `
            -Code 'CG_LEGACY_PROFILE_SCAN_WARNING' -ExitCode 0 -Status 'warn' `
            -Reason 'The legacy default profile could not be scanned in warning mode.' `
            -Remediation 'Inspect or remove the legacy settings file.' `
            -Evidence @{ mode = $Mode }
    }

    $markerNames = @(
        $script:GuardLegacyMarkerPattern.Matches($content) |
            ForEach-Object Value |
            Sort-Object -Unique
    )
    if ($markerNames.Count -eq 0) {
        return New-GuardResult `
            -Code 'CG_LEGACY_PROFILE_CLEAR' -ExitCode 0 -Status 'pass' `
            -Reason 'The legacy default profile contains no known route or credential markers.' `
            -Remediation '' `
            -Evidence @{ mode = $Mode }
    }
    if ($Mode -eq 'strict') {
        return New-GuardResult `
            -Code 'CG_LEGACY_PROFILE_CONTAMINATED' -ExitCode 11 -Status 'fail' `
            -Reason 'The legacy default profile contains route or credential injection markers.' `
            -Remediation 'Remove the legacy contamination or keep it isolated outside the guarded profile.' `
            -Evidence @{ markers = $markerNames }
    }

    New-GuardResult `
        -Code 'CG_LEGACY_PROFILE_WARNING' -ExitCode 0 -Status 'warn' `
        -Reason 'The legacy default profile contains route or credential markers but is not active.' `
        -Remediation 'Remove the legacy contamination when practical.' `
        -Evidence @{ markers = $markerNames }
}
