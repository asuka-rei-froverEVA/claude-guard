if (-not ('ClaudeGuard.Runtime.BoundedProcessRunner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace ClaudeGuard.Runtime
{
    public sealed class BoundedProcessResult
    {
        public bool Success { get; set; }
        public bool TimedOut { get; set; }
        public bool OutputLimitExceeded { get; set; }
        public int? ExitCode { get; set; }
        public string StdOut { get; set; } = string.Empty;
        public string StdErr { get; set; } = string.Empty;
    }

    public static class BoundedProcessRunner
    {
        private sealed class BoundedText
        {
            public string Text { get; set; } = string.Empty;
            public bool Exceeded { get; set; }
        }

        private static async Task<BoundedText> DrainAsync(StreamReader reader, int maximumCharacters)
        {
            var buffer = new char[1024];
            var text = new StringBuilder(Math.Min(maximumCharacters, 4096));
            var exceeded = false;
            int read;
            while ((read = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                var remaining = maximumCharacters - text.Length;
                if (remaining > 0)
                {
                    text.Append(buffer, 0, Math.Min(remaining, read));
                }
                if (read > remaining)
                {
                    exceeded = true;
                }
            }
            return new BoundedText { Text = text.ToString(), Exceeded = exceeded };
        }

        public static BoundedProcessResult Run(
            ProcessStartInfo startInfo,
            int timeoutMilliseconds,
            int maximumCharacters)
        {
            using (var process = new Process { StartInfo = startInfo })
            {
                if (!process.Start())
                {
                    return new BoundedProcessResult { Success = false };
                }

                var stdoutTask = DrainAsync(process.StandardOutput, maximumCharacters);
                var stderrTask = DrainAsync(process.StandardError, maximumCharacters);
                var timedOut = !process.WaitForExit(timeoutMilliseconds);
                if (timedOut)
                {
                    try { process.Kill(true); } catch { }
                    process.WaitForExit();
                }

                Task.WaitAll(stdoutTask, stderrTask);
                var stdout = stdoutTask.GetAwaiter().GetResult();
                var stderr = stderrTask.GetAwaiter().GetResult();
                return new BoundedProcessResult
                {
                    Success = !timedOut,
                    TimedOut = timedOut,
                    OutputLimitExceeded = stdout.Exceeded || stderr.Exceeded,
                    ExitCode = timedOut ? (int?)null : process.ExitCode,
                    StdOut = stdout.Text,
                    StdErr = stderr.Text
                };
            }
        }
    }
}
'@
}

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

        $captured = [ClaudeGuard.Runtime.BoundedProcessRunner]::Run(
            $startInfo,
            $TimeoutMs,
            $MaxOutputCharacters
        )
        [pscustomobject][ordered]@{
            Success             = $captured.Success
            TimedOut            = $captured.TimedOut
            OutputLimitExceeded = $captured.OutputLimitExceeded
            ExitCode            = $captured.ExitCode
            StdOut              = $captured.StdOut
            StdErr              = $captured.StdErr
        }
    }
    catch {
        [pscustomobject][ordered]@{
            Success             = $false
            TimedOut            = $false
            OutputLimitExceeded = $false
            ExitCode            = $null
            StdOut              = ''
            StdErr              = ''
        }
    }
}

function ConvertFrom-GuardClientVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Output
    )

    $versionMatch = [regex]::Match(
        $Output,
        '\A(?<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?: \(Claude Code\))?\r?\n?\z'
    )
    if ($versionMatch.Success) {
        $versionMatch.Groups['version'].Value
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
        [string]$GuardEntryPath,

        [AllowNull()]
        [scriptblock]$ProcessInvoker
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
        $captured = if ($null -ne $ProcessInvoker) {
            & $ProcessInvoker $resolved.Path @('--version') $Environment
        }
        else {
            Invoke-GuardCapturedProcess `
                -CommandPath $resolved.Path `
                -Arguments @('--version') `
                -Environment $Environment
        }
        $outputLimitExceeded = $null -ne $captured.PSObject.Properties['OutputLimitExceeded'] -and
            [bool]$captured.OutputLimitExceeded
        $actualVersion = if ($captured.Success -and
            $captured.ExitCode -eq 0 -and
            -not $outputLimitExceeded) {
            ConvertFrom-GuardClientVersion -Output ([string]$captured.StdOut)
        }
        else { $null }
        if ([string]::IsNullOrEmpty($actualVersion)) {
            return New-GuardResult `
                -Code 'CG_CLIENT_VERSION_UNAVAILABLE' -ExitCode 12 -Status 'fail' `
                -Reason 'The configured client did not return a bounded parseable version.' `
                -Remediation 'Verify the native Claude executable and its local dependencies.' `
                -Evidence @{ client = [IO.Path]::GetFileName($resolved.Path) }
        }
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
