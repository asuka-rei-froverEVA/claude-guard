# Windows Native PowerShell Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fail-closed native Windows PowerShell guard for the official Claude Code CLI/TUI while leaving the existing Bash lanes unchanged.

**Architecture:** Add a thin PowerShell entry point backed by a testable `ClaudeGuard` module. Local policy checks, child-process construction, HTTP CONNECT, TLS validation, exit-IP validation, and IPv6 exposure checks return structured `GuardResult` values; only the entry point renders output and exits. Offline Pester fixtures provide all network evidence, and CI runs Pester and PSScriptAnalyzer as independent Windows gates.

**Tech Stack:** PowerShell 7.4+, .NET 8 networking and X.509 APIs, Pester 6.0.1, PSScriptAnalyzer 1.25.0, GitHub Actions Windows runners.

**Spec:** `docs/superpowers/specs/2026-08-31-windows-native-powershell-design.md`

## Global Constraints

- Preserve `bin/claude-guard`, `bin/claude-cc`, and their Bash behavior.
- Keep all automated tests credential-free, deterministic, and offline.
- Never accept missing CONNECT, TLS, hostname, chain, leaf, issuer, or complete HTTP-response evidence.
- Never reconnect directly after proxy failure. The direct IPv6 reachability probe is the only direct socket operation and sends no application data.
- Keep certificate evidence separate from CONNECT response bytes.
- Never log proxy credentials, tokens, complete hashes, complete allowlists, or user-profile paths.
- Put `exit` only in `bin/claude-guard.ps1`; module functions return results or process exit codes.
- Make one focused commit after every task whose checks pass.

---

### Task 1: Pinned Windows Test Harness And Module Skeleton

**Files:**
- Create: `scripts/bootstrap-windows-tests.ps1`
- Create: `scripts/check-windows.ps1`
- Create: `src/ClaudeGuard/ClaudeGuard.psd1`
- Create: `src/ClaudeGuard/ClaudeGuard.psm1`
- Create: `src/ClaudeGuard/Private/Result.ps1`
- Create: `src/ClaudeGuard/Private/Ui.ps1`
- Create: `tests/windows/Unit/Result.Tests.ps1`
- Create: `bin/claude-guard.ps1`
- Modify: `.gitignore`

**Interfaces:**

```powershell
New-GuardResult -Code <string> -ExitCode <int> -Status <pass|warn|fail|unknown> `
  -Reason <string> -Remediation <string> -Evidence <hashtable>
ConvertTo-GuardJson -InputObject <object>
Write-GuardResult -Result <object> [-Json]
```

- [ ] **Step 1: Add a failing result-contract test**

Assert that a result has exactly the stable fields `code`, `exit_code`, `status`, `reason`, `remediation`, and `evidence`; assert JSON depth preserves nested evidence and contains no ANSI escape bytes.

```powershell
It 'creates the stable result contract' {
    $result = New-GuardResult -Code 'CG_TEST' -ExitCode 7 -Status fail `
        -Reason 'test' -Remediation 'fix it' -Evidence @{ tls = @{ chain_valid = $false } }
    @($result.PSObject.Properties.Name) | Should -Be @(
        'code', 'exit_code', 'status', 'reason', 'remediation', 'evidence'
    )
    (ConvertTo-GuardJson $result) | Should -Match '"chain_valid":false'
}
```

- [ ] **Step 2: Prove the test fails**

Run:

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/windows/Unit/Result.Tests.ps1 -Output Detailed"
```

Expected: failure because the module and `New-GuardResult` do not exist.

- [ ] **Step 3: Add the module and result implementation**

The module loader dot-sources `Private/*.ps1` then `Public/*.ps1` in ordinal name order. Export only:

```powershell
Export-ModuleMember -Function Invoke-ClaudeGuard, Invoke-ClaudeGuardDoctor, Get-ClaudeGuardStatus
```

Use ordered `PSCustomObject` values for results so field order is deterministic. `ConvertTo-GuardJson` must call `ConvertTo-Json -Depth 12 -Compress` and never colorize JSON.

- [ ] **Step 4: Add pinned local test dependencies and checks**

`bootstrap-windows-tests.ps1` installs exact versions into `.tools/powershell`:

```powershell
$Required = [ordered]@{ Pester = '6.0.1'; PSScriptAnalyzer = '1.25.0' }
Save-PSResource -Name $name -Version $Required[$name] -Path $ToolRoot -TrustRepository
```

`check-windows.ps1` must validate PowerShell 7.4+, import the module, run Pester, and run PSScriptAnalyzer with failures treated as errors. Add `.tools/` and `TestResults/` to `.gitignore`.

- [ ] **Step 5: Add the runtime floor and thin entry point**

The entry point checks `$PSVersionTable.PSVersion -ge [version]'7.4'`, imports the manifest by an absolute path, manually dispatches `status`, `doctor`, and `--precheck-only`, and otherwise forwards the original argument array to `Invoke-ClaudeGuard`.

- [ ] **Step 6: Run checks and commit**

```powershell
pwsh -NoProfile -File scripts/bootstrap-windows-tests.ps1
pwsh -NoProfile -File scripts/check-windows.ps1
git add .gitignore bin/claude-guard.ps1 scripts src/ClaudeGuard tests/windows/Unit/Result.Tests.ps1
git commit -m "test: add Windows PowerShell guard harness"
```

Expected: Pester and PSScriptAnalyzer pass and the entry point reports a structured unsupported-command failure until public functions are added.

### Task 2: Configuration, Paths, And Offline Status

**Files:**
- Create: `src/ClaudeGuard/Private/Configuration.ps1`
- Create: `src/ClaudeGuard/Private/PathPolicy.ps1`
- Create: `src/ClaudeGuard/Public/Get-ClaudeGuardStatus.ps1`
- Create: `tests/windows/Unit/Configuration.Tests.ps1`
- Create: `tests/windows/Unit/PathPolicy.Tests.ps1`
- Create: `tests/windows/Unit/Status.Tests.ps1`
- Create: `config/safe-claude.windows.example.json`

**Interfaces:**

```powershell
Read-GuardConfiguration -Path <string> -Environment <IDictionary>
Resolve-GuardPath -Path <string> -Kind <File|Directory> [-RejectReparsePoint]
Test-GuardPathIdentity -Left <string> -Right <string>
Get-ClaudeGuardStatus [-ConfigPath <string>] [-Json]
```

- [ ] **Step 1: Write failing configuration and path tests**

Cover invalid JSON, missing required fields, wrong array/boolean types, environment-over-JSON precedence, empty environment overrides, non-empty `client_macos_team_id`, relative/missing paths, case-insensitive identity, slash variants, command recursion, file-vs-directory mismatches, and reparse points.

- [ ] **Step 2: Write a failing offline-status test**

Mock every network primitive (`TcpClient`, DNS, `Invoke-WebRequest`) to throw. `Get-ClaudeGuardStatus -Json` must still return local bounded JSON and report:

```json
{"network_readiness":"not_checked","watchdog":"not_available_in_windows_milestone_1","notifications":"unavailable"}
```

- [ ] **Step 3: Implement strict configuration parsing**

Return a normalized object containing all existing official-lane fields. Reject a non-empty macOS team ID with `CG_WINDOWS_TEAM_ID_UNSUPPORTED`/exit 2. Ignore unknown keys, but never let them modify a known policy. Treat an explicitly empty required override as invalid instead of falling back.

- [ ] **Step 4: Implement filesystem identity**

Use `[IO.Path]::GetFullPath()`, `Get-Item -LiteralPath`, `FileInfo.FullName`, and `FileAttributes.ReparsePoint`. Compare normalized identities with `[StringComparer]::OrdinalIgnoreCase`; do not infer links from differing strings.

- [ ] **Step 5: Implement offline status and example config**

Status may read files and inspect local processes but must not make sockets, DNS calls, HTTP calls, or invoke a model. Use documentation-only IP ranges and placeholder hashes in the example.

- [ ] **Step 6: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add config/safe-claude.windows.example.json src/ClaudeGuard tests/windows/Unit
git commit -m "feat: add Windows config and offline status"
```

### Task 3: Settings, Project, Model, And Argument Policy

**Files:**
- Create: `src/ClaudeGuard/Private/SettingsPolicy.ps1`
- Create: `src/ClaudeGuard/Private/ArgumentPolicy.ps1`
- Create: `tests/windows/Unit/SettingsPolicy.Tests.ps1`
- Create: `tests/windows/Unit/ArgumentPolicy.Tests.ps1`
- Create: `tests/windows/Fixtures/settings/`

**Interfaces:**

```powershell
Test-GuardSettings -SettingsPath <string> -BlockedPlugins <string[]> `
  -BlockedModels <string[]> -RequireUnpinnedModel <bool>
Find-GuardProjectSettings -StartPath <string> -ProfileBoundary <string>
Test-GuardArguments -Arguments <string[]> -BlockedModels <string[]> `
  -RequireUnpinnedModel <bool>
```

- [ ] **Step 1: Add failing table-driven policy tests**

Port the official Bash risk categories: route/provider/base URL, token and auth helpers, proxy and CA overrides, retry/update/telemetry/background/watchdog values, CC Switch routes, lifecycle bypasses, blocked plugins, pinned model policy, project-local settings, and reparse-point settings paths.

CLI cases must include both split and equals forms (`--model sonnet`, `--model=sonnet`, `--settings`, `--settings=...`) plus `--setting-sources`, background/detached/attach/respawn/tmux/remote-control/agents modes. Confirm benign prompt arguments retain exact ordering.

- [ ] **Step 2: Prove the owning tests fail**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/windows/Unit/SettingsPolicy.Tests.ps1,tests/windows/Unit/ArgumentPolicy.Tests.ps1 -Output Detailed"
```

- [ ] **Step 3: Implement path-aware JSON traversal**

Walk nested objects and arrays while recording a normalized dotted path. Match both risky key names and risky string values; never serialize secrets into the failure evidence. Return only the category and JSON path.

- [ ] **Step 4: Implement argument scanning without reparsing**

Inspect the original string array but return it unchanged. Match option names case-sensitively as Claude does; reject ambiguous incomplete options. Return exit 5 for settings/model policy and exit 13 for lifecycle modes.

- [ ] **Step 5: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private tests/windows/Unit tests/windows/Fixtures/settings
git commit -m "feat: port official Windows policy gates"
```

### Task 4: Client Identity, Legacy Profile, And Fingerprint Tripwire

**Files:**
- Create: `src/ClaudeGuard/Private/ClientIdentity.ps1`
- Create: `src/ClaudeGuard/Private/FingerprintPolicy.ps1`
- Create: `tests/windows/Unit/ClientIdentity.Tests.ps1`
- Create: `tests/windows/Unit/FingerprintPolicy.Tests.ps1`
- Create: `tests/windows/Fixtures/fake-claude.cmd`

**Interfaces:**

```powershell
Test-GuardClientIdentity -CommandPath <string> -ExpectedVersion <string> `
  -ExpectedSha256 <string> -Environment <IDictionary> -GuardEntryPath <string>
Test-GuardClientFingerprint -CommandPath <string> -Mode <off|warn|fail-active|strict> `
  -Environment <IDictionary>
Test-GuardLegacyProfile -ProfilePath <string> -Mode <off|warn|strict>
```

- [ ] **Step 1: Add failing identity tests**

Test recursion, missing command, version capture failure, exact version match/mismatch, SHA-256 match/mismatch, hash read failure, and proof that only the configured command receives `--version`.

- [ ] **Step 2: Add failing fingerprint and legacy tests**

Port the upstream marker set and modes. For `fail-active`, activate only when the upstream activation conditions are present (`ANTHROPIC_BASE_URL` or the specified Asia time zones). A scan failure must fail closed in blocking modes. Legacy profile findings stay separate from the selected official `config_dir`.

- [ ] **Step 3: Implement captured process invocation**

Use `System.Diagnostics.ProcessStartInfo` with `UseShellExecute = $false`, redirected output for `--version`, an explicit environment dictionary, and `ArgumentList.Add('--version')`. Bound captured stdout/stderr and time out deterministically.

- [ ] **Step 4: Implement hash and marker scans**

Hash the resolved regular file via `Get-FileHash -Algorithm SHA256`. Read bounded binary chunks for ASCII/UTF-8 marker matching; do not load an unbounded executable into memory.

- [ ] **Step 5: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private tests/windows
git commit -m "feat: verify Windows Claude client identity"
```

### Task 5: Sanitized Foreground Child Process

**Files:**
- Create: `src/ClaudeGuard/Private/EnvironmentPolicy.ps1`
- Create: `src/ClaudeGuard/Private/Process.ps1`
- Create: `tests/windows/Unit/EnvironmentPolicy.Tests.ps1`
- Create: `tests/windows/Integration/Process.Tests.ps1`
- Create: `tests/windows/Fixtures/fake-claude.ps1`

**Interfaces:**

```powershell
New-GuardChildEnvironment -Source <IDictionary> -ConfigDir <string> `
  -SettingsPath <string> -ProxyUri <uri>
Start-GuardClaudeProcess -CommandPath <string> -Arguments <string[]> `
  -Environment <IDictionary>
```

- [ ] **Step 1: Add failing environment tests**

Assert the allowlist preserves required Windows variables and architecture-specific program directories. Assert all upstream routing/provider/token/credential/retry/update/background/remote/telemetry variables are absent or forced to official-lane values. Include mixed-case variable names because Windows environment keys are case-insensitive.

- [ ] **Step 2: Add a failing fake-client integration test**

The fake client records a JSON envelope into a test-selected temporary file. Assert arguments containing spaces, quotes, Unicode, leading dashes, and empty strings arrive in order; prohibited environment values do not arrive; stdin/stdout/stderr are not redirected for the foreground run; Guard returns the fake client's nonzero exit code.

- [ ] **Step 3: Implement the child environment as data**

Construct a new `[Collections.Generic.Dictionary[string,string]]` using `OrdinalIgnoreCase`. Never mutate the Guard process environment. Explicitly set the official settings/config/proxy variables after the denylist is applied.

- [ ] **Step 4: Implement foreground execution**

Use `ProcessStartInfo.ArgumentList`, `UseShellExecute = $false`, and the constructed `Environment`. Leave standard handles unredirected and synchronously return `ExitCode`. No shell command string, detached window, job, or watchdog is allowed.

- [ ] **Step 5: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private tests/windows
git commit -m "feat: launch sanitized Windows Claude process"
```

### Task 6: Bounded HTTP CONNECT Transport

**Files:**
- Create: `src/ClaudeGuard/Private/ProxyConnect.ps1`
- Create: `tests/windows/Fixtures/LoopbackProxy.ps1`
- Create: `tests/windows/Integration/ProxyConnect.Tests.ps1`

**Interfaces:**

```powershell
Open-GuardProxyTunnel -ProxyUri <uri> -TargetHost <string> -TargetPort <int> `
  [-TimeoutMs <int>] [-MaxHeaderBytes <int>]
Close-GuardTunnel -Tunnel <object>
```

- [ ] **Step 1: Add failing loopback CONNECT tests**

Test 200, 407, 502, malformed status, missing header terminator, oversized headers, timeout, proxy refusal, unsupported `https`/SOCKS schemes, missing port, and credential-bearing URIs. The fixture counts target-side accepts so a failed proxy case can prove no direct target connection occurred.

- [ ] **Step 2: Implement exact-target CONNECT**

Connect only to `ProxyUri.Host:ProxyUri.Port`, then write:

```text
CONNECT api.anthropic.com:443 HTTP/1.1\r\n
Host: api.anthropic.com:443\r\n
Proxy-Connection: Keep-Alive\r\n
\r\n
```

Read one byte buffer at a time until `\r\n\r\n`, timeout, EOF, or the maximum size. Parse only the first response line and require status 200.

- [ ] **Step 3: Keep evidence physically separate**

The returned object contains `Client`, `Stream`, and a new immutable evidence object with only `proxy_connected`, `connect_status`, `proxy_host_redacted`, and `target_host`. It must not expose or later append TLS bytes.

- [ ] **Step 4: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private/ProxyConnect.ps1 tests/windows
git commit -m "feat: add fail-closed Windows CONNECT transport"
```

### Task 7: TLS, Hostname, Chain, Leaf, And Custom Root Policy

**Files:**
- Create: `src/ClaudeGuard/Private/TlsPolicy.ps1`
- Create: `tests/windows/Fixtures/TestCertificates.ps1`
- Create: `tests/windows/Fixtures/LoopbackTlsEndpoint.ps1`
- Create: `tests/windows/Integration/TlsPolicy.Tests.ps1`

**Interfaces:**

```powershell
Open-GuardTlsStream -Tunnel <object> -TargetHost <string> [-CaCertPath <string>] `
  [-TimeoutMs <int>]
Import-GuardCustomRoots -Path <string>
Test-GuardLeafIssuer -LeafCertificate <X509Certificate2>
```

- [ ] **Step 1: Add failing generated-certificate tests**

Cover valid custom-root trust, system-store default behavior, hostname mismatch, untrusted root, expired leaf, absent certificate, unreadable/empty/malformed PEM, multiple PEM roots, TLS protocol failure, and authentication timeout.

Add the two regression-critical cases:

- TLS validation fails even when CONNECT is 200 and the issuer text is benign.
- A multi-level chain has a benign root but the leaf issuer contains a blocked MITM keyword; the leaf issuer must fail.

- [ ] **Step 2: Add the evidence-injection regression test**

Place text resembling `HTTP/1.1 200 Connection established` in a certificate field and prove it cannot satisfy a missing CONNECT response. Test CONNECT and TLS independently before composing them.

- [ ] **Step 3: Implement default and custom trust**

For default trust, the callback succeeds only when `SslPolicyErrors.None`. For custom roots, create `X509ChainPolicy` with `TrustMode = CustomRootTrust`, add every parsed root to `CustomTrustStore`, build the leaf, and independently reject `RemoteCertificateNameMismatch`/`RemoteCertificateNotAvailable`. Never fall back to the Windows store after a custom bundle was selected.

- [ ] **Step 4: Return separate TLS facts**

Record only bounded/redacted fields:

```powershell
@{
  tls_authenticated = $true
  hostname_valid    = $true
  chain_valid       = $true
  leaf_thumbprint   = $leaf.Thumbprint.Substring(0, 12)
  leaf_issuer       = Protect-GuardEvidence $leaf.Issuer
}
```

Leaf existence, issuer extraction, and issuer blacklist are independent pass conditions.

- [ ] **Step 5: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private/TlsPolicy.ps1 tests/windows
git commit -m "feat: validate Windows TLS identity"
```

### Task 8: Complete HTTPS Response And Exit-IP Policy

**Files:**
- Create: `src/ClaudeGuard/Private/EgressPolicy.ps1`
- Create: `tests/windows/Unit/EgressPolicy.Tests.ps1`
- Create: `tests/windows/Integration/EgressPolicy.Tests.ps1`
- Modify: `tests/windows/Fixtures/LoopbackTlsEndpoint.ps1`

**Interfaces:**

```powershell
Invoke-GuardHttpsRequest -TlsStream <SslStream> -Host <string> -Path <string> `
  [-TimeoutMs <int>] [-MaxHeaderBytes <int>] [-MaxBodyBytes <int>]
Get-GuardTraceIp -Response <object>
Test-GuardIpAllowed -Ip <IPAddress> -AllowedIps <string[]> -AllowedCidrs <string[]>
```

- [ ] **Step 1: Add failing IPv4/CIDR unit tests**

Cover exact IPs, `/0`, `/32`, first/last subnet addresses, invalid IPs, invalid prefix lengths, IPv6-in-IPv4 fields, overlapping CIDRs, and empty allowlists.

- [ ] **Step 2: Add failing complete-response tests**

Require host `api.anthropic.com` and path `/cdn-cgi/trace`. Test content-length, chunked encoding, connection-close bodies, non-200 status, malformed/multiple `ip=` lines, header/body limits, timeout after partial body, truncated chunk, and server reset. A partial body containing a valid allowed `ip=` must still be discarded.

- [ ] **Step 3: Implement a bounded HTTP/1.1 reader**

Accept the body only after framing proves completion. Reject ambiguous framing, unsupported content encodings, and response-size overflow. Return raw body only inside the function; public evidence contains a redacted classification, never the real public IP.

- [ ] **Step 4: Implement CIDR membership without text-prefix shortcuts**

Parse to four bytes, apply a 32-bit network mask, and compare network values. Invalid configured allowlist entries are configuration failures, not unauthorized-IP results.

- [ ] **Step 5: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private/EgressPolicy.ps1 tests/windows
git commit -m "feat: validate Anthropic-aligned Windows egress"
```

### Task 9: Direct IPv6 Exposure Gate

**Files:**
- Create: `src/ClaudeGuard/Private/Ipv6Policy.ps1`
- Create: `tests/windows/Unit/Ipv6Policy.Tests.ps1`
- Create: `tests/windows/Integration/Ipv6Policy.Tests.ps1`

**Interfaces:**

```powershell
Get-GuardIpv6Class -Address <IPAddress>
Test-GuardDirectIpv6 -Host <string> [-Resolver <scriptblock>] `
  [-Connector <scriptblock>] [-TimeoutMs <int>]
```

- [ ] **Step 1: Add failing classification tests**

Classify loopback, link-local, unique-local `fc00::/7`, documentation `2001:db8::/32`, multicast, unspecified, IPv4-mapped addresses, and globally routable IPv6. Cover fake-IP mapped `198.18.0.0/15` separately.

- [ ] **Step 2: Add failing reachability tests**

Use injected offline resolver/connector functions. No AAAA is pass; only non-global addresses is pass; a reachable global IPv6 is exit 8; an unreachable global address is pass; DNS ambiguity, timeout ambiguity, or partial resolver failure is fail-closed. Assert the connector writes zero bytes.

- [ ] **Step 3: Implement DNS and TCP-only probing**

Resolve only `api.anthropic.com`; attempt direct IPv6 TCP port 443 with bounded timeouts and no TLS/HTTP data. Never alter the proxy route based on the result.

- [ ] **Step 4: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add src/ClaudeGuard/Private/Ipv6Policy.ps1 tests/windows
git commit -m "feat: block direct Windows IPv6 exposure"
```

### Task 10: Preflight Orchestration, Doctor, And Launch

**Files:**
- Create: `src/ClaudeGuard/Public/Invoke-ClaudeGuard.ps1`
- Create: `src/ClaudeGuard/Public/Invoke-ClaudeGuardDoctor.ps1`
- Create: `src/ClaudeGuard/Private/Preflight.ps1`
- Create: `tests/windows/Unit/Preflight.Tests.ps1`
- Create: `tests/windows/Integration/Commands.Tests.ps1`
- Modify: `bin/claude-guard.ps1`

**Interfaces:**

```powershell
Invoke-GuardPreflight -ConfigPath <string> -Arguments <string[]> [-OfflineNetwork <object>]
Invoke-ClaudeGuard -ConfigPath <string> -Arguments <string[]>
Invoke-ClaudeGuardDoctor -ConfigPath <string> [-Json]
```

- [ ] **Step 1: Add failing call-order and short-circuit tests**

Assert the exact order from the design spec. Each injected failure must prevent every later check and prevent client launch. Deterministic policy errors must not retry; transient proxy/TLS failures may retry only the same proxy, target, CA source, and policy.

- [ ] **Step 2: Add failing command-surface integration tests**

Cover default launch, arbitrary args, `--precheck-only`, `doctor`, `status`, `status --json`, invalid commands, config override, and child exit-code propagation. `doctor`, status, and precheck must prove the fake client launch marker is absent; status must prove the loopback network fixture received no connection.

- [ ] **Step 3: Implement orchestration and structured rendering**

Compose `GuardResult` values without changing their semantics in the UI layer. Plain output provides code/reason/remediation and bounded evidence. JSON output contains stable fields and no progress lines.

- [ ] **Step 4: Implement launch only after all gates pass**

The final action is `Start-GuardClaudeProcess`. Dispose tunnels and TLS streams on all success/failure paths. Return Claude's exit code unchanged.

- [ ] **Step 5: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add bin/claude-guard.ps1 src/ClaudeGuard tests/windows
git commit -m "feat: orchestrate native Windows Claude Guard"
```

### Task 11: Targeted Security Mutation Checks

**Files:**
- Create: `scripts/test-windows-mutations.ps1`
- Create: `tests/windows/Mutation/Mutation.Tests.ps1`
- Modify: `scripts/check-windows.ps1`

- [ ] **Step 1: Add a failing mutation-runner self-test**

The runner copies only tracked Windows source/tests into a unique temporary directory, applies one exact mutation, runs its owning Pester test, requires a nonzero test result, and removes the directory. It must reject zero or multiple mutation matches.

- [ ] **Step 2: Implement the six required mutations**

Mutate one at a time:

- accept TLS policy errors;
- select chain root instead of leaf;
- accept missing CONNECT evidence;
- append certificate bytes to CONNECT evidence;
- accept an `ip=` body before response completion;
- keep a prohibited routing/token environment variable.

- [ ] **Step 3: Wire mutations into the default Windows check**

Run ordinary Pester first, then mutations, then PSScriptAnalyzer. Print one line per killed mutation and fail if any mutation survives.

- [ ] **Step 4: Run and commit**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git add scripts tests/windows/Mutation
git commit -m "test: add Windows guard mutation checks"
```

### Task 12: Independent Windows CI Gates

**Files:**
- Modify: `.github/workflows/check.yml`

- [ ] **Step 1: Add separate Windows test and analyzer jobs**

Use `windows-2025`, `pwsh`, and exact tool versions. The Pester job runs module import, Pester, and mutations. The analyzer job independently installs PSScriptAnalyzer 1.25.0 and invokes it directly; it must not merely reuse a label from the Pester job.

- [ ] **Step 2: Preserve Bash jobs unchanged**

Keep Ubuntu and macOS `/bin/bash` checks. Do not allow Windows job setup to alter their dependency installation or shell.

- [ ] **Step 3: Run local equivalents and inspect workflow syntax**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
git diff --check
git add .github/workflows/check.yml
git commit -m "ci: test native Windows PowerShell guard"
```

Expected: local checks pass and the diff has no whitespace errors.

### Task 13: Windows Documentation And Release Evidence

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Create: `docs/windows-native-powershell.md`
- Create: `docs/windows-validation-template.md`
- Modify: `VERSION` only if maintainers choose a release version after review

- [ ] **Step 1: Document experimental native Windows support**

Add prerequisites, manual invocation, configuration, `doctor`, offline `status`, exit-code behavior, default Windows trust vs custom PEM roots, and exact unsupported features: CC lane, installer/shim, watchdog, notifications, SOCKS/HTTPS proxies, and Desktop Code tab.

- [ ] **Step 2: Document security and privacy boundaries**

State that Guard never handles or forwards model traffic, never stores account tokens, does not provide ban-evasion, and blocks ambiguous/missing proxy/TLS/IP/IPv6 evidence.

- [ ] **Step 3: Add a redacted real-machine validation template**

Include Windows build/architecture, PowerShell version, commit, Claude version, shortened hash, credential-free proxy type, precheck result, no-launch proof, closed-port negative test, and documentation-IP negative test. Explicitly prohibit real IPs, tokens, full paths, complete hashes, or settings contents.

- [ ] **Step 4: Run all verification**

```powershell
pwsh -NoProfile -File scripts/check-windows.ps1
bash ./scripts/check.sh
git diff --check
```

Expected: Windows Pester, mutation, and analyzer checks pass; all existing Bash tests pass; no whitespace errors.

- [ ] **Step 5: Commit and push**

```powershell
git add README.md CHANGELOG.md docs
git commit -m "docs: add native Windows guard guide"
git push origin codex/windows-native-powershell
```

Do not call the Windows lane stable, publish a release, merge, or tag until GitHub CI and a redacted real-machine precheck both pass.

