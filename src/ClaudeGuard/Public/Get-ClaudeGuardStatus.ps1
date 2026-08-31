function Get-ClaudeGuardStatus {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,

        [System.Collections.IDictionary]$Environment = [Environment]::GetEnvironmentVariables(),

        [string]$WorkingDirectory = (Get-Location).Path
    )

    $environmentValues = ConvertTo-GuardEnvironmentDictionary -Environment $Environment
    $userProfile = if ($environmentValues.ContainsKey('USERPROFILE')) {
        [string]$environmentValues['USERPROFILE']
    }
    else {
        [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    }

    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        if ($environmentValues.ContainsKey('CLAUDE_GUARD_CONFIG') -and
            -not [string]::IsNullOrWhiteSpace([string]$environmentValues['CLAUDE_GUARD_CONFIG'])) {
            $ConfigPath = [string]$environmentValues['CLAUDE_GUARD_CONFIG']
        }
        else {
            $ConfigPath = Join-Path $userProfile '.safe-claude-official.json'
        }
    }

    $parsed = Read-GuardConfiguration -Path $ConfigPath -Environment $Environment
    if ($parsed.Result.status -ne 'pass') {
        return New-GuardResult `
            -Code $parsed.Result.code `
            -ExitCode $parsed.Result.exit_code `
            -Status 'fail' `
            -Reason $parsed.Result.reason `
            -Remediation $parsed.Result.remediation `
            -Evidence ([ordered]@{
                config_path      = Protect-GuardPath -Path $ConfigPath -UserProfile $userProfile
                network_readiness = 'not_checked'
                watchdog          = 'not_available_in_windows_milestone_1'
                notifications     = 'unavailable'
            })
    }

    $configuration = $parsed.Configuration
    $clientPath = Resolve-GuardPath -Path $configuration.command -Kind File
    $configDirectory = Resolve-GuardPath -Path $configuration.config_dir -Kind Directory
    $settingsPath = Resolve-GuardPath -Path $configuration.settings_path -Kind File
    $guardEntryPath = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\..\bin\claude-guard.ps1')
    )
    $clientIdentity = Test-GuardClientIdentity `
        -CommandPath $configuration.command `
        -ExpectedVersion $configuration.client_version `
        -ExpectedSha256 $configuration.client_sha256 `
        -Environment $Environment `
        -GuardEntryPath $guardEntryPath
    $settingsPolicy = Test-GuardSettings `
        -SettingsPath $configuration.settings_path `
        -BlockedPlugins $configuration.blocked_plugins `
        -BlockedModels $configuration.blocked_models `
        -RequireUnpinnedModel $configuration.require_unpinned_model

    $projectResults = @(
        foreach ($projectSettingsPath in @(Find-GuardProjectSettings `
            -StartPath $WorkingDirectory `
            -ProfileBoundary $userProfile)) {
            Test-GuardSettings `
                -SettingsPath $projectSettingsPath `
                -BlockedPlugins $configuration.blocked_plugins `
                -BlockedModels $configuration.blocked_models `
                -RequireUnpinnedModel $configuration.require_unpinned_model `
                -Project
        }
    )
    $projectFailure = @($projectResults | Where-Object status -eq 'fail' | Select-Object -First 1)
    $projectPolicy = if ($projectFailure.Count -gt 0) {
        $projectFailure[0]
    }
    else {
        New-GuardResult `
            -Code 'CG_PROJECT_SETTINGS_VALID' -ExitCode 0 -Status 'pass' `
            -Reason 'Discovered project settings comply with local policy.' `
            -Remediation '' `
            -Evidence @{ files_checked = $projectResults.Count }
    }

    $fingerprint = Test-GuardClientFingerprint `
        -CommandPath $configuration.command `
        -Mode $configuration.fingerprint_mode `
        -Environment $Environment
    $legacyProfile = Test-GuardLegacyProfile `
        -ProfilePath (Join-Path $userProfile '.claude\settings.json') `
        -Mode $configuration.legacy_profile_mode
    $activeProcesses = Get-GuardMatchingProcessState -CommandPath $clientPath.Path

    $evidence = [ordered]@{
        module_version     = $script:ClaudeGuardModuleVersion
        powershell_version = $PSVersionTable.PSVersion.ToString()
        config             = [ordered]@{
            status = 'valid'
            path   = Protect-GuardPath -Path $configuration.config_path -UserProfile $userProfile
        }
        client             = [ordered]@{
            status = $clientPath.Result.status
            path   = Protect-GuardPath -Path $clientPath.Path -UserProfile $userProfile
        }
        config_directory   = [ordered]@{
            status = $configDirectory.Result.status
            path   = Protect-GuardPath -Path $configDirectory.Path -UserProfile $userProfile
        }
        settings           = [ordered]@{
            status = $settingsPath.Result.status
            path   = Protect-GuardPath -Path $settingsPath.Path -UserProfile $userProfile
        }
        client_identity    = ConvertTo-GuardStatusCheck -Result $clientIdentity
        settings_policy    = ConvertTo-GuardStatusCheck -Result $settingsPolicy
        project_settings   = ConvertTo-GuardStatusCheck -Result $projectPolicy
        fingerprint        = ConvertTo-GuardStatusCheck -Result $fingerprint
        legacy_profile     = ConvertTo-GuardStatusCheck -Result $legacyProfile
        active_processes   = $activeProcesses
        network_readiness  = 'not_checked'
        watchdog           = 'not_available_in_windows_milestone_1'
        notifications      = 'unavailable'
    }

    $localResults = @(
        $clientPath.Result
        $configDirectory.Result
        $settingsPath.Result
        $clientIdentity
        $settingsPolicy
        $projectPolicy
        $fingerprint
        $legacyProfile
    )
    $localFailure = @($localResults | Where-Object status -eq 'fail' | Select-Object -First 1)
    if ($localFailure.Count -gt 0) {
        return New-GuardResult `
            -Code 'CG_STATUS_LOCAL_POLICY_FAILED' `
            -ExitCode $localFailure[0].exit_code `
            -Status 'fail' `
            -Reason 'One or more local Windows policy checks failed; network readiness was not checked.' `
            -Remediation $localFailure[0].remediation `
            -Evidence $evidence
    }

    $localWarning = @($localResults | Where-Object status -eq 'warn' | Select-Object -First 1)
    if ($localWarning.Count -gt 0) {
        return New-GuardResult `
            -Code 'CG_STATUS_LOCAL_WARNING' `
            -ExitCode 0 `
            -Status 'warn' `
            -Reason 'Local Windows policy checks completed with warnings; network readiness was not checked.' `
            -Remediation $localWarning[0].remediation `
            -Evidence $evidence
    }

    New-GuardResult `
        -Code 'CG_STATUS_LOCAL_ONLY' `
        -ExitCode 0 `
        -Status 'unknown' `
        -Reason 'Local policy state was inspected; network readiness was not checked.' `
        -Remediation 'Run doctor or --precheck-only before launching Claude.' `
        -Evidence $evidence
}
