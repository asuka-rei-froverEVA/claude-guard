function New-GuardChildEnvironment {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This pure factory builds an in-memory environment dictionary and changes no process state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Source,

        [Parameter(Mandatory)]
        [string]$ConfigDir,

        [Parameter(Mandatory)]
        [uri]$ProxyUri,

        [AllowNull()]
        [string]$CaCertPath
    )

    $sourceValues = ConvertTo-GuardEnvironmentDictionary -Environment $Source
    $child = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    $baselineNames = @(
        'SystemRoot'
        'WINDIR'
        'ComSpec'
        'PATH'
        'PATHEXT'
        'TEMP'
        'TMP'
        'USERPROFILE'
        'APPDATA'
        'LOCALAPPDATA'
        'ProgramData'
        'ProgramFiles'
        'ProgramFiles(x86)'
        'ProgramW6432'
        'CommonProgramFiles'
        'CommonProgramFiles(x86)'
        'CommonProgramW6432'
        'PROCESSOR_ARCHITECTURE'
        'PROCESSOR_ARCHITEW6432'
        'HOMEDRIVE'
        'HOMEPATH'
        'HOME'
        'USERNAME'
        'USERDOMAIN'
        'TERM'
        'COLORTERM'
        'LANG'
        'NO_COLOR'
    )
    foreach ($name in $baselineNames) {
        if ($sourceValues.ContainsKey($name) -and $null -ne $sourceValues[$name]) {
            $child[$name] = [string]$sourceValues[$name]
        }
    }

    $proxyText = $ProxyUri.AbsoluteUri
    $child['HTTP_PROXY'] = $proxyText
    $child['HTTPS_PROXY'] = $proxyText
    $child['ALL_PROXY'] = $proxyText
    $child['NO_PROXY'] = '127.0.0.1,localhost,::1,.local'
    $child['CLAUDE_CONFIG_DIR'] = $ConfigDir

    $fixedPolicy = [ordered]@{
        DISABLE_AUTOUPDATER                       = '1'
        DISABLE_ERROR_REPORTING                   = '1'
        DISABLE_FEEDBACK_COMMAND                  = '1'
        CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY       = '1'
        DISABLE_UPDATES                           = '1'
        CLAUDE_CODE_DISABLE_AGENT_VIEW            = '1'
        CLAUDE_CODE_DISABLE_CRON                  = '1'
        CLAUDE_CODE_DISABLE_BG_EXIT_HANDOFF       = '1'
        CLAUDE_DISABLE_ADOPT                      = '1'
        CLAUDE_CODE_DISABLE_WORKFLOWS             = '1'
        CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS        = '0'
        CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH      = '1'
        CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS      = '3'
        CLAUDE_CODE_CERT_STORE                    = 'system'
    }
    foreach ($entry in $fixedPolicy.GetEnumerator()) {
        $child[$entry.Key] = $entry.Value
    }

    if (-not [string]::IsNullOrWhiteSpace($CaCertPath)) {
        $child['SSL_CERT_FILE'] = $CaCertPath
        $child['NODE_EXTRA_CA_CERTS'] = $CaCertPath
    }

    $child
}
