[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments)]
    [AllowEmptyCollection()]
    [AllowEmptyString()]
    [string[]]$CapturedArguments = @()
)

$capturedEnvironment = [ordered]@{}
foreach ($name in @(
    'SystemRoot',
    'CLAUDE_CONFIG_DIR',
    'HTTP_PROXY',
    'ANTHROPIC_BASE_URL',
    'ANTHROPIC_AUTH_TOKEN',
    'CG_TEST_SENTINEL'
)) {
    $capturedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
}

$envelope = [ordered]@{
    arguments   = @($CapturedArguments)
    environment = $capturedEnvironment
}
$envelope | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $env:CG_TEST_OUTPUT
exit [int]$env:CG_TEST_EXIT
