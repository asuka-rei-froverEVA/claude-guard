$script:GuardSettingsRiskPattern = [regex]::new(
    'ANTHROPIC_(BASE_URL|AUTH_TOKEN|API_KEY|CUSTOM_HEADERS|AWS_BASE_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL|FOUNDRY_BASE_URL)|apiKeyHelper|PROXY_MANAGED|CLAUDE_CODE_USE_(GATEWAY|BEDROCK|VERTEX|FOUNDRY|ANTHROPIC_AWS|MANTLE)|CLAUDE_CODE_PROCESS_WRAPPER|processWrapper|CLAUDE_CODE_RETRY_WATCHDOG|CLAUDE_CODE_ATTRIBUTION_HEADER|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|CLAUDE_CODE_CERT_STORE|CLAUDE_CONFIG_DIR',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$script:GuardSettingsRiskValuePattern = [regex]::new(
    '127\.0\.0\.1:15721|PROXY_MANAGED',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase
)

function Get-GuardJsonScalarEntry {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [string]$Path = ''
    )

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $childPath = if ([string]::IsNullOrEmpty($Path)) {
                [string]$key
            }
            else {
                '{0}.{1}' -f $Path, $key
            }
            Get-GuardJsonScalarEntry -Value $Value[$key] -Path $childPath
        }
        return
    }

    if ($Value -is [System.Collections.IList] -and $Value -isnot [string]) {
        for ($index = 0; $index -lt $Value.Count; $index++) {
            $childPath = if ([string]::IsNullOrEmpty($Path)) {
                [string]$index
            }
            else {
                '{0}.{1}' -f $Path, $index
            }
            Get-GuardJsonScalarEntry -Value $Value[$index] -Path $childPath
        }
        return
    }

    [pscustomobject][ordered]@{
        Path  = $Path
        Value = $Value
    }
}

function Get-GuardSettingsRiskPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Settings
    )

    @(
        foreach ($entry in @(Get-GuardJsonScalarEntry -Value $Settings)) {
            $valueText = if ($null -eq $entry.Value) { '' } else { [string]$entry.Value }
            if ($script:GuardSettingsRiskPattern.IsMatch($entry.Path) -or
                $script:GuardSettingsRiskValuePattern.IsMatch($valueText)) {
                $entry.Path
            }
        }
    ) | Sort-Object -Unique
}

function Test-GuardSettingsValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Settings,

        [Parameter(Mandatory)]
        [string[]]$Path,

        [AllowNull()]
        [object]$Expected,

        [switch]$OnlyWhenPresent
    )

    $current = $Settings
    foreach ($segment in $Path) {
        if ($current -isnot [System.Collections.IDictionary] -or -not $current.Contains($segment)) {
            return $OnlyWhenPresent.IsPresent
        }
        $current = $current[$segment]
    }
    $current -ceq $Expected
}

function Test-GuardSettingsKeyPresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Settings,

        [Parameter(Mandatory)]
        [string[]]$Path
    )

    $current = $Settings
    foreach ($segment in $Path) {
        if ($current -isnot [System.Collections.IDictionary] -or -not $current.Contains($segment)) {
            return $false
        }
        $current = $current[$segment]
    }
    $true
}

function Test-GuardSettings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'Settings is the official Claude product term and the function evaluates one settings file.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SettingsPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$BlockedPlugins,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$BlockedModels,

        [Parameter(Mandatory)]
        [bool]$RequireUnpinnedModel,

        [switch]$Project
    )

    $pathResult = Resolve-GuardPath `
        -Path $SettingsPath `
        -Kind File `
        -RejectReparsePoint
    if ($pathResult.Result.status -ne 'pass') {
        $exitCode = if ($Project) { 13 } else { 5 }
        return New-GuardResult `
            -Code 'CG_SETTINGS_PATH_INVALID' -ExitCode $exitCode -Status 'fail' `
            -Reason 'The settings file is missing, unreadable, or a reparse point.' `
            -Remediation 'Use a readable regular settings.json file.' `
            -Evidence @{ kind = if ($Project) { 'project' } else { 'official' } }
    }

    try {
        $settings = Get-Content -LiteralPath $pathResult.Path -Raw -ErrorAction Stop |
            ConvertFrom-Json -AsHashtable -Depth 64 -ErrorAction Stop
    }
    catch {
        return New-GuardResult `
            -Code 'CG_SETTINGS_JSON_INVALID' -ExitCode 5 -Status 'fail' `
            -Reason 'A settings file is not valid JSON.' `
            -Remediation 'Fix the settings JSON syntax and retry.' `
            -Evidence @{ kind = if ($Project) { 'project' } else { 'official' } }
    }

    if ($settings -isnot [System.Collections.IDictionary]) {
        return New-GuardResult `
            -Code 'CG_SETTINGS_SCHEMA_INVALID' -ExitCode 5 -Status 'fail' `
            -Reason 'A settings file must contain a JSON object.' `
            -Remediation 'Replace the settings root with a JSON object.' `
            -Evidence @{ kind = if ($Project) { 'project' } else { 'official' } }
    }

    $riskPaths = @(Get-GuardSettingsRiskPath -Settings $settings)
    if ($riskPaths.Count -gt 0) {
        return New-GuardResult `
            -Code $(if ($Project) { 'CG_PROJECT_RISK_OVERRIDE' } else { 'CG_SETTINGS_RISK_OVERRIDE' }) `
            -ExitCode $(if ($Project) { 13 } else { 5 }) `
            -Status 'fail' `
            -Reason 'Settings attempt to override routing, credentials, certificates, or retry policy.' `
            -Remediation 'Remove the reported policy paths from settings.' `
            -Evidence @{ paths = $riskPaths }
    }

    $enabledPlugins = if ($settings.Contains('enabledPlugins') -and
        $settings.enabledPlugins -is [System.Collections.IDictionary]) {
        $settings.enabledPlugins
    }
    else { @{} }
    foreach ($plugin in $BlockedPlugins) {
        if ($enabledPlugins.Contains($plugin) -and $enabledPlugins[$plugin] -ceq $true) {
            return New-GuardResult `
                -Code 'CG_PLUGIN_BLOCKED' -ExitCode 13 -Status 'fail' `
                -Reason 'A locally blocked plugin is enabled in settings.' `
                -Remediation 'Disable the blocked plugin before using the guarded lane.' `
                -Evidence @{ plugin = $plugin }
        }
    }

    if ($settings.Contains('model') -and
        $settings.model -is [string] -and
        -not [string]::IsNullOrWhiteSpace($settings.model)) {
        if ($BlockedModels -ccontains [string]$settings.model) {
            return New-GuardResult `
                -Code 'CG_MODEL_BLOCKED' -ExitCode 6 -Status 'fail' `
                -Reason 'The settings-selected model is locally blocked.' `
                -Remediation 'Remove or change the settings model.' `
                -Evidence @{ source = 'settings' }
        }
        if ($RequireUnpinnedModel) {
            return New-GuardResult `
                -Code 'CG_MODEL_PINNED_IN_SETTINGS' -ExitCode 6 -Status 'fail' `
                -Reason 'The safe configuration requires settings to leave model selection unpinned.' `
                -Remediation 'Remove model from settings; use a one-time allowed --model argument if needed.' `
                -Evidence @{ source = 'settings' }
        }
    }

    $requiredValues = [ordered]@{
        'disableAgentView'                              = $true
        'disableRemoteControl'                         = $true
        'disableDeepLinkRegistration'                  = 'disable'
        'disableAllHooks'                              = $true
        'disableWorkflows'                             = $true
        'env.DISABLE_UPDATES'                          = '1'
        'env.CLAUDE_CODE_DISABLE_AGENT_VIEW'           = '1'
        'env.CLAUDE_CODE_DISABLE_CRON'                 = '1'
        'env.CLAUDE_CODE_DISABLE_BG_EXIT_HANDOFF'      = '1'
        'env.CLAUDE_DISABLE_ADOPT'                     = '1'
        'env.CLAUDE_CODE_DISABLE_WORKFLOWS'            = '1'
        'env.CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS'       = '0'
        'env.CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH'     = '1'
        'env.CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS'     = '3'
    }
    $missingOrUnsafe = @(
        foreach ($entry in $requiredValues.GetEnumerator()) {
            $segments = @($entry.Key -split '\.')
            $valueMatches = Test-GuardSettingsValue `
                -Settings $settings `
                -Path $segments `
                -Expected $entry.Value `
                -OnlyWhenPresent:$Project
            if (-not $valueMatches) { $entry.Key }
        }
    )

    $forbiddenPresence = @(
        'env.CLAUDE_CODE_DISABLE_BACKGROUND_TASKS'
    )
    foreach ($path in $forbiddenPresence) {
        if (Test-GuardSettingsKeyPresent -Settings $settings -Path @($path -split '\.')) {
            $missingOrUnsafe += $path
        }
    }

    $forbiddenValues = [ordered]@{
        'env.CLAUDE_AUTO_BACKGROUND_TASKS'            = '1'
        'env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS'    = '1'
    }
    foreach ($entry in $forbiddenValues.GetEnumerator()) {
        if (Test-GuardSettingsValue `
            -Settings $settings `
            -Path @($entry.Key -split '\.') `
            -Expected $entry.Value) {
            $missingOrUnsafe += $entry.Key
        }
    }

    if (Test-GuardSettingsKeyPresent `
        -Settings $settings `
        -Path @('env', 'CLAUDE_CODE_RETRY_WATCHDOG')) {
        $retryValue = [string]$settings.env.CLAUDE_CODE_RETRY_WATCHDOG
        if (-not [string]::IsNullOrEmpty($retryValue)) {
            $missingOrUnsafe += 'env.CLAUDE_CODE_RETRY_WATCHDOG'
        }
    }

    if ($missingOrUnsafe.Count -gt 0) {
        return New-GuardResult `
            -Code $(if ($Project) { 'CG_PROJECT_LIFECYCLE_DOWNGRADE' } else { 'CG_LIFECYCLE_POLICY_REQUIRED' }) `
            -ExitCode 13 `
            -Status 'fail' `
            -Reason $(if ($Project) {
                'Project settings attempt to lower the foreground lifecycle policy.'
            } else {
                'Official settings do not enforce every required foreground lifecycle protection.'
            }) `
            -Remediation 'Apply the documented official lifecycle settings and remove project downgrades.' `
            -Evidence @{ paths = @($missingOrUnsafe | Sort-Object -Unique) }
    }

    New-GuardResult `
        -Code $(if ($Project) { 'CG_PROJECT_SETTINGS_VALID' } else { 'CG_SETTINGS_VALID' }) `
        -ExitCode 0 `
        -Status 'pass' `
        -Reason 'Settings comply with the guarded official foreground lifecycle.' `
        -Remediation '' `
        -Evidence @{ kind = if ($Project) { 'project' } else { 'official' } }
}

function Find-GuardProjectSettings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The function intentionally discovers both Claude settings.json variants along the path.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StartPath,

        [Parameter(Mandatory)]
        [string]$ProfileBoundary
    )

    $start = Resolve-GuardPath -Path $StartPath -Kind Directory
    $boundary = Resolve-GuardPath -Path $ProfileBoundary -Kind Directory
    if ($start.Result.status -ne 'pass' -or $boundary.Result.status -ne 'pass') {
        return
    }

    $directory = Get-Item -LiteralPath $start.Path -Force
    while ($null -ne $directory -and
        -not (Test-GuardPathIdentity -Left $directory.FullName -Right $boundary.Path)) {
        foreach ($relativePath in @('.claude\settings.json', '.claude\settings.local.json')) {
            $candidate = Join-Path $directory.FullName $relativePath
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                (Get-Item -LiteralPath $candidate -Force).FullName
            }
        }
        $directory = $directory.Parent
    }
}
