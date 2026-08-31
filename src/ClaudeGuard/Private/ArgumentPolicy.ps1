function Test-GuardArguments {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The function evaluates one immutable argument collection as a single policy boundary.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$BlockedModels,

        [Parameter(Mandatory)]
        [bool]$RequireUnpinnedModel
    )

    $null = $RequireUnpinnedModel
    foreach ($argument in $Arguments) {
        $isSettingsOverride = $argument -ceq '--settings' -or
            $argument.StartsWith('--settings=', [StringComparison]::Ordinal)
        $isSourceOverride = $argument -ceq '--setting-sources' -or
            $argument.StartsWith('--setting-sources=', [StringComparison]::Ordinal)
        $isDetachedMode = $argument -cin @(
            '--bg', '--background', 'agents', '--agents', 'attach', 'respawn',
            '--tmux', '--remote-control', 'remote-control'
        ) -or
            $argument.StartsWith('--bg=', [StringComparison]::Ordinal) -or
            $argument.StartsWith('--background=', [StringComparison]::Ordinal) -or
            $argument.StartsWith('--tmux=', [StringComparison]::Ordinal) -or
            $argument.StartsWith('--remote-control=', [StringComparison]::Ordinal)

        if ($isSettingsOverride -or $isSourceOverride -or $isDetachedMode) {
            return New-GuardResult `
                -Code 'CG_ARGUMENT_LIFECYCLE_BYPASS' -ExitCode 13 -Status 'fail' `
                -Reason 'A command-line argument can bypass guarded settings or foreground lifecycle policy.' `
                -Remediation 'Remove settings overrides and detached/background lifecycle arguments.' `
                -Evidence @{ argument = $argument.Split('=', 2)[0] }
        }
    }

    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $argument = $Arguments[$index]
        $model = $null
        if ($argument -ceq '--model') {
            if ($index + 1 -ge $Arguments.Count -or
                [string]::IsNullOrEmpty($Arguments[$index + 1]) -or
                $Arguments[$index + 1].StartsWith('--', [StringComparison]::Ordinal)) {
                return New-GuardResult `
                    -Code 'CG_ARGUMENT_VALUE_MISSING' -ExitCode 2 -Status 'fail' `
                    -Reason 'The --model option is missing its value.' `
                    -Remediation 'Provide one allowed model value or remove --model.' `
                    -Evidence @{ argument = '--model' }
            }
            $index++
            $model = $Arguments[$index]
        }
        elseif ($argument.StartsWith('--model=', [StringComparison]::Ordinal)) {
            $model = $argument.Substring('--model='.Length)
            if ([string]::IsNullOrEmpty($model)) {
                return New-GuardResult `
                    -Code 'CG_ARGUMENT_VALUE_MISSING' -ExitCode 2 -Status 'fail' `
                    -Reason 'The --model option is missing its value.' `
                    -Remediation 'Provide one allowed model value or remove --model.' `
                    -Evidence @{ argument = '--model' }
            }
        }

        if ($null -ne $model -and $BlockedModels -ccontains $model) {
            return New-GuardResult `
                -Code 'CG_MODEL_BLOCKED' -ExitCode 6 -Status 'fail' `
                -Reason 'The command-line model is locally blocked.' `
                -Remediation 'Choose an allowed model or remove --model.' `
                -Evidence @{ source = 'arguments' }
        }
    }

    New-GuardResult `
        -Code 'CG_ARGUMENTS_VALID' -ExitCode 0 -Status 'pass' `
        -Reason 'Command-line arguments preserve the guarded lifecycle and model policy.' `
        -Remediation '' `
        -Evidence @{ argument_count = $Arguments.Count }
}
