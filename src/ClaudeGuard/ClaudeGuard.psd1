@{
    RootModule        = 'ClaudeGuard.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'f0d178b1-20f9-4b72-8891-6b64cff9d361'
    Author            = 'Claude Guard contributors'
    CompanyName       = 'Community'
    Copyright         = '(c) Claude Guard contributors. MIT licensed.'
    Description       = 'Native Windows security preflight for the official Claude Code CLI.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @('Get-ClaudeGuardStatus')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Windows', 'Claude', 'Security')
            ProjectUri = 'https://github.com/wetlink/claude-guard'
            LicenseUri = 'https://github.com/wetlink/claude-guard/blob/main/LICENSE'
        }
    }
}
