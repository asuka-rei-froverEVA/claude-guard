function Start-GuardClaudeProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This private final-stage foreground launcher must preserve console semantics and has no public WhatIf surface.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Environment
    )

    $resolved = Resolve-GuardPath -Path $CommandPath -Kind File -RejectReparsePoint
    if ($resolved.Result.status -ne 'pass') {
        return 127
    }

    $process = $null
    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $resolved.Path
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $false
        $startInfo.RedirectStandardInput = $false
        $startInfo.RedirectStandardOutput = $false
        $startInfo.RedirectStandardError = $false
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
            return 127
        }
        $process.WaitForExit()
        $process.ExitCode
    }
    catch {
        127
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}
