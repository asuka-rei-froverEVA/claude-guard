function ConvertTo-GuardConfigurationOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [AllowNull()]
        [object]$Configuration
    )

    [pscustomobject][ordered]@{
        Result        = $Result
        Configuration = $Configuration
    }
}

function ConvertTo-GuardConfigurationFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Code,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [string]$Remediation,

        [System.Collections.IDictionary]$Evidence = @{}
    )

    $result = New-GuardResult `
        -Code $Code `
        -ExitCode 2 `
        -Status 'fail' `
        -Reason $Reason `
        -Remediation $Remediation `
        -Evidence $Evidence
    ConvertTo-GuardConfigurationOutcome -Result $result -Configuration $null
}

function ConvertTo-GuardEnvironmentDictionary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Environment
    )

    $normalized = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($key in $Environment.Keys) {
        $normalized[[string]$key] = $Environment[$key]
    }
    $normalized
}

function Test-GuardJsonStringArray {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or $Value -is [string] -or $Value -isnot [System.Collections.IList]) {
        return $false
    }

    foreach ($entry in $Value) {
        if ($entry -isnot [string]) {
            return $false
        }
    }
    $true
}

function Get-GuardJsonProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Object,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $Object.PSObject.Properties[$Name]
}

function Read-GuardConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Environment
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ConvertTo-GuardConfigurationFailure `
            -Code 'CG_CONFIG_NOT_FOUND' `
            -Reason 'The safe configuration file does not exist.' `
            -Remediation 'Create the Windows safe configuration from the repository example.' `
            -Evidence @{ field = 'config_path' }
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $json = $raw | ConvertFrom-Json -Depth 32 -ErrorAction Stop
    }
    catch {
        return ConvertTo-GuardConfigurationFailure `
            -Code 'CG_CONFIG_JSON_INVALID' `
            -Reason 'The safe configuration is not valid JSON.' `
            -Remediation 'Fix the JSON syntax and retry.' `
            -Evidence @{ field = 'config' }
    }

    if ($null -eq $json -or $json -is [System.Collections.IList] -or $json -isnot [psobject]) {
        return ConvertTo-GuardConfigurationFailure `
            -Code 'CG_CONFIG_SCHEMA_INVALID' `
            -Reason 'The safe configuration root must be a JSON object.' `
            -Remediation 'Use the documented Windows configuration object.' `
            -Evidence @{ field = 'root' }
    }

    $requiredStrings = @('command', 'config_dir')
    foreach ($name in $requiredStrings) {
        $property = Get-GuardJsonProperty -Object $json -Name $name
        if ($null -eq $property -or
            $property.Value -isnot [string] -or
            [string]::IsNullOrWhiteSpace($property.Value)) {
            return ConvertTo-GuardConfigurationFailure `
                -Code 'CG_CONFIG_SCHEMA_INVALID' `
                -Reason ('Configuration field "{0}" must be a non-empty string.' -f $name) `
                -Remediation 'Correct the field type using the Windows example.' `
                -Evidence @{ field = $name }
        }
    }

    $requiredArrays = @('allowed_ips', 'allowed_cidrs')
    $optionalArrays = @('blocked_plugins', 'blocked_models')
    foreach ($name in $requiredArrays) {
        $property = Get-GuardJsonProperty -Object $json -Name $name
        if ($null -eq $property -or
            -not (Test-GuardJsonStringArray -Value $property.Value)) {
            return ConvertTo-GuardConfigurationFailure `
                -Code 'CG_CONFIG_SCHEMA_INVALID' `
                -Reason ('Configuration field "{0}" must be an array of strings.' -f $name) `
                -Remediation 'Correct the field type using the Windows example.' `
                -Evidence @{ field = $name }
        }
    }

    foreach ($name in $optionalArrays) {
        $property = $json.PSObject.Properties[$name]
        if ($null -ne $property -and -not (Test-GuardJsonStringArray -Value $property.Value)) {
            return ConvertTo-GuardConfigurationFailure `
                -Code 'CG_CONFIG_SCHEMA_INVALID' `
                -Reason ('Configuration field "{0}" must be an array of strings.' -f $name) `
                -Remediation 'Correct the field type using the Windows example.' `
                -Evidence @{ field = $name }
        }
    }

    foreach ($name in @('require_unpinned_model', 'notify')) {
        $property = $json.PSObject.Properties[$name]
        if ($null -ne $property -and $property.Value -isnot [bool]) {
            return ConvertTo-GuardConfigurationFailure `
                -Code 'CG_CONFIG_SCHEMA_INVALID' `
                -Reason ('Configuration field "{0}" must be true or false.' -f $name) `
                -Remediation 'Correct the field type using the Windows example.' `
                -Evidence @{ field = $name }
        }
    }

    foreach ($name in @('client_version', 'client_sha256', 'client_macos_team_id')) {
        $property = $json.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value -and $property.Value -isnot [string]) {
            return ConvertTo-GuardConfigurationFailure `
                -Code 'CG_CONFIG_SCHEMA_INVALID' `
                -Reason ('Configuration field "{0}" must be a string.' -f $name) `
                -Remediation 'Correct the field type using the Windows example.' `
                -Evidence @{ field = $name }
        }
    }

    $teamIdProperty = Get-GuardJsonProperty -Object $json -Name 'client_macos_team_id'
    $teamId = if ($null -eq $teamIdProperty) { '' } else { [string]$teamIdProperty.Value }
    if (-not [string]::IsNullOrWhiteSpace($teamId)) {
        return ConvertTo-GuardConfigurationFailure `
            -Code 'CG_WINDOWS_TEAM_ID_UNSUPPORTED' `
            -Reason 'A macOS Team ID cannot be verified by the native Windows lane.' `
            -Remediation 'Remove client_macos_team_id and pin the Windows client version and SHA-256 instead.' `
            -Evidence @{ field = 'client_macos_team_id' }
    }

    $environmentValues = ConvertTo-GuardEnvironmentDictionary -Environment $Environment
    $overrideNames = @(
        'CLAUDE_GUARD_SETTINGS'
        'CLAUDE_GUARD_PROXY'
        'CLAUDE_GUARD_CA_CERT'
        'CLAUDE_GUARD_UI'
        'CLAUDE_GUARD_FINGERPRINT_MODE'
        'CLAUDE_GUARD_LEGACY_PROFILE_MODE'
    )
    foreach ($name in $overrideNames) {
        if ($environmentValues.ContainsKey($name) -and
            [string]::IsNullOrWhiteSpace([string]$environmentValues[$name])) {
            return ConvertTo-GuardConfigurationFailure `
                -Code 'CG_CONFIG_OVERRIDE_EMPTY' `
                -Reason ('Environment override "{0}" is explicitly empty.' -f $name) `
                -Remediation 'Unset the override or provide a non-empty supported value.' `
                -Evidence @{ field = $name }
        }
    }

    $configDirectory = [string](
        (Get-GuardJsonProperty -Object $json -Name 'config_dir').Value
    )
    $settingsPath = Join-Path $configDirectory 'settings.json'
    if ($environmentValues.ContainsKey('CLAUDE_GUARD_SETTINGS')) {
        $settingsPath = [string]$environmentValues['CLAUDE_GUARD_SETTINGS']
    }

    $proxyText = 'http://127.0.0.1:7897'
    if ($environmentValues.ContainsKey('CLAUDE_GUARD_PROXY')) {
        $proxyText = [string]$environmentValues['CLAUDE_GUARD_PROXY']
    }
    $proxyUri = $null
    if (-not [uri]::TryCreate($proxyText, [UriKind]::Absolute, [ref]$proxyUri)) {
        return ConvertTo-GuardConfigurationFailure `
            -Code 'CG_CONFIG_PROXY_INVALID' `
            -Reason 'CLAUDE_GUARD_PROXY is not an absolute URI.' `
            -Remediation 'Set an explicit HTTP proxy URI with a host and port.' `
            -Evidence @{ field = 'CLAUDE_GUARD_PROXY' }
    }

    $uiMode = if ($environmentValues.ContainsKey('CLAUDE_GUARD_UI')) {
        [string]$environmentValues['CLAUDE_GUARD_UI']
    }
    else { 'auto' }
    $fingerprintMode = if ($environmentValues.ContainsKey('CLAUDE_GUARD_FINGERPRINT_MODE')) {
        [string]$environmentValues['CLAUDE_GUARD_FINGERPRINT_MODE']
    }
    else { 'fail-active' }
    $legacyMode = if ($environmentValues.ContainsKey('CLAUDE_GUARD_LEGACY_PROFILE_MODE')) {
        [string]$environmentValues['CLAUDE_GUARD_LEGACY_PROFILE_MODE']
    }
    else { 'warn' }

    if ($uiMode -notin @('auto', 'always', 'never') -or
        $fingerprintMode -notin @('off', 'warn', 'fail-active', 'strict') -or
        $legacyMode -notin @('off', 'warn', 'strict')) {
        return ConvertTo-GuardConfigurationFailure `
            -Code 'CG_CONFIG_OVERRIDE_INVALID' `
            -Reason 'A Windows Guard mode override has an unsupported value.' `
            -Remediation 'Use a documented UI, fingerprint, or legacy-profile mode.' `
            -Evidence @{ field = 'mode_override' }
    }

    $caCertPath = $null
    if ($environmentValues.ContainsKey('CLAUDE_GUARD_CA_CERT')) {
        $caCertPath = [string]$environmentValues['CLAUDE_GUARD_CA_CERT']
    }

    $blockedPluginsProperty = Get-GuardJsonProperty -Object $json -Name 'blocked_plugins'
    $blockedPlugins = if ($null -eq $blockedPluginsProperty) { @() } else { $blockedPluginsProperty.Value }
    $blockedModelsProperty = Get-GuardJsonProperty -Object $json -Name 'blocked_models'
    $blockedModels = if ($null -eq $blockedModelsProperty) { @() } else { $blockedModelsProperty.Value }
    $requireUnpinnedProperty = Get-GuardJsonProperty -Object $json -Name 'require_unpinned_model'
    $requireUnpinnedModel = if ($null -eq $requireUnpinnedProperty) { $false } else { $requireUnpinnedProperty.Value }
    $notifyProperty = Get-GuardJsonProperty -Object $json -Name 'notify'
    $notify = if ($null -eq $notifyProperty) { $false } else { $notifyProperty.Value }
    $commandProperty = Get-GuardJsonProperty -Object $json -Name 'command'
    $allowedIpsProperty = Get-GuardJsonProperty -Object $json -Name 'allowed_ips'
    $allowedCidrsProperty = Get-GuardJsonProperty -Object $json -Name 'allowed_cidrs'
    $clientVersionProperty = Get-GuardJsonProperty -Object $json -Name 'client_version'
    $clientShaProperty = Get-GuardJsonProperty -Object $json -Name 'client_sha256'

    $configuration = [pscustomobject][ordered]@{
        config_path             = [IO.Path]::GetFullPath($Path)
        command                 = [string]$commandProperty.Value
        config_dir              = $configDirectory
        settings_path           = $settingsPath
        allowed_ips             = @($allowedIpsProperty.Value)
        allowed_cidrs           = @($allowedCidrsProperty.Value)
        client_version          = if ($null -eq $clientVersionProperty) { '' } else { [string]$clientVersionProperty.Value }
        client_sha256           = if ($null -eq $clientShaProperty) { '' } else { [string]$clientShaProperty.Value }
        client_macos_team_id    = ''
        blocked_plugins         = @($blockedPlugins)
        blocked_models          = @($blockedModels)
        require_unpinned_model  = [bool]$requireUnpinnedModel
        notify                  = [bool]$notify
        proxy_uri               = $proxyUri
        ca_cert_path            = $caCertPath
        ui_mode                 = $uiMode
        fingerprint_mode        = $fingerprintMode
        legacy_profile_mode     = $legacyMode
    }

    $result = New-GuardResult `
        -Code 'CG_CONFIG_VALID' `
        -ExitCode 0 `
        -Status 'pass' `
        -Reason 'The Windows safe configuration schema is valid.' `
        -Remediation '' `
        -Evidence @{ schema = 'windows-milestone-1' }
    ConvertTo-GuardConfigurationOutcome -Result $result -Configuration $configuration
}
