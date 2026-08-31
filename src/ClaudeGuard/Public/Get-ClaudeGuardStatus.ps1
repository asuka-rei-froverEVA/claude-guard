function Get-ClaudeGuardStatus {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,

        [System.Collections.IDictionary]$Environment = [Environment]::GetEnvironmentVariables()
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
        network_readiness  = 'not_checked'
        watchdog           = 'not_available_in_windows_milestone_1'
        notifications      = 'unavailable'
    }

    New-GuardResult `
        -Code 'CG_STATUS_LOCAL_ONLY' `
        -ExitCode 0 `
        -Status 'unknown' `
        -Reason 'Local policy state was inspected; network readiness was not checked.' `
        -Remediation 'Run doctor or --precheck-only before launching Claude.' `
        -Evidence $evidence
}
