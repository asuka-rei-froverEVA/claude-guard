function Invoke-GuardCapturedProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Environment,

        [ValidateRange(100, 30000)]
        [int]$TimeoutMs = 5000,

        [ValidateRange(256, 65536)]
        [int]$MaxOutputCharacters = 4096
    )

    $process = $null
    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $CommandPath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in $Arguments) {
            $startInfo.ArgumentList.Add($argument)
        }
        $startInfo.Environment.Clear()
        foreach ($key in $Environment.Keys) {
            if ($null -ne $Environment[$key]) {
                $startInfo.Environment[[string]$key] = [string]$Environment[$key]
            }
        }

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'The configured process did not start.'
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            $process.Kill($true)
            $process.WaitForExit()
            return [pscustomobject][ordered]@{
                Success  = $false
                TimedOut = $true
                ExitCode = $null
                StdOut   = ''
                StdErr   = ''
            }
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt $MaxOutputCharacters) {
            $stdout = $stdout.Substring(0, $MaxOutputCharacters)
        }
        if ($stderr.Length -gt $MaxOutputCharacters) {
            $stderr = $stderr.Substring(0, $MaxOutputCharacters)
        }

        [pscustomobject][ordered]@{
            Success  = $true
            TimedOut = $false
            ExitCode = $process.ExitCode
            StdOut   = $stdout
            StdErr   = $stderr
        }
    }
    catch {
        [pscustomobject][ordered]@{
            Success  = $false
            TimedOut = $false
            ExitCode = $null
            StdOut   = ''
            StdErr   = ''
        }
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Test-GuardClientIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandPath,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ExpectedVersion,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ExpectedSha256,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Environment,

        [Parameter(Mandatory)]
        [string]$GuardEntryPath
    )

    $resolved = Resolve-GuardPath -Path $CommandPath -Kind File -RejectReparsePoint
    if ($resolved.Result.status -ne 'pass') {
        return New-GuardResult `
            -Code 'CG_CLIENT_PATH_INVALID' -ExitCode 12 -Status 'fail' `
            -Reason 'The configured Claude client is missing, unreadable, or a reparse point.' `
            -Remediation 'Select the regular native claude.exe file.' `
            -Evidence @{ client = '<invalid>' }
    }

    if (Test-GuardPathIdentity -Left $resolved.Path -Right $GuardEntryPath) {
        return New-GuardResult `
            -Code 'CG_CLIENT_RECURSION' -ExitCode 12 -Status 'fail' `
            -Reason 'The configured client resolves back to Claude Guard.' `
            -Remediation 'Set command to the original native claude.exe file.' `
            -Evidence @{ client = [IO.Path]::GetFileName($resolved.Path) }
    }

    $actualVersion = 'unpinned'
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        $captured = Invoke-GuardCapturedProcess `
            -CommandPath $resolved.Path `
            -Arguments @('--version') `
            -Environment $Environment
        $versionMatch = if ($captured.Success -and $captured.ExitCode -eq 0) {
            [regex]::Match(
                $captured.StdOut,
                '(?m)(?<!\d)(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)'
            )
        }
        else {
            [Text.RegularExpressions.Match]::Empty
        }
        if (-not $versionMatch.Success) {
            return New-GuardResult `
                -Code 'CG_CLIENT_VERSION_UNAVAILABLE' -ExitCode 12 -Status 'fail' `
                -Reason 'The configured client did not return a bounded parseable version.' `
                -Remediation 'Verify the native Claude executable and its local dependencies.' `
                -Evidence @{ client = [IO.Path]::GetFileName($resolved.Path) }
        }
        $actualVersion = $versionMatch.Groups[1].Value
        if ($actualVersion -cne $ExpectedVersion) {
            return New-GuardResult `
                -Code 'CG_CLIENT_VERSION_MISMATCH' -ExitCode 12 -Status 'fail' `
                -Reason 'The configured client version does not match the local pin.' `
                -Remediation 'Review the update, then update both version and SHA-256 pins together.' `
                -Evidence @{ expected = $ExpectedVersion; actual = $actualVersion }
        }
    }

    $actualHashPrefix = 'unpinned'
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        if ($ExpectedSha256 -cnotmatch '^[0-9A-Fa-f]{64}$') {
            return New-GuardResult `
                -Code 'CG_CLIENT_HASH_PIN_INVALID' -ExitCode 12 -Status 'fail' `
                -Reason 'The configured SHA-256 pin is not 64 hexadecimal characters.' `
                -Remediation 'Replace client_sha256 with the full reviewed SHA-256 hash.' `
                -Evidence @{ field = 'client_sha256' }
        }
        try {
            $actualHash = (Get-FileHash -LiteralPath $resolved.Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        }
        catch {
            return New-GuardResult `
                -Code 'CG_CLIENT_HASH_UNAVAILABLE' -ExitCode 12 -Status 'fail' `
                -Reason 'The configured client could not be hashed.' `
                -Remediation 'Verify read access to the native Claude executable.' `
                -Evidence @{ client = [IO.Path]::GetFileName($resolved.Path) }
        }
        $actualHashPrefix = $actualHash.Substring(0, 12)
        if ($actualHash -cne $ExpectedSha256.ToLowerInvariant()) {
            return New-GuardResult `
                -Code 'CG_CLIENT_HASH_MISMATCH' -ExitCode 12 -Status 'fail' `
                -Reason 'The configured client SHA-256 does not match the local pin.' `
                -Remediation 'Do not launch; review the client update and refresh both identity pins.' `
                -Evidence @{ actual_sha256_prefix = $actualHashPrefix }
        }
    }

    New-GuardResult `
        -Code 'CG_CLIENT_IDENTITY_VALID' -ExitCode 0 -Status 'pass' `
        -Reason 'The configured Windows Claude client matches its local identity policy.' `
        -Remediation '' `
        -Evidence ([ordered]@{
            client        = [IO.Path]::GetFileName($resolved.Path)
            version       = $actualVersion
            sha256_prefix = $actualHashPrefix
        })
}
