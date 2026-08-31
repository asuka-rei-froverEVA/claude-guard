# Windows Native PowerShell Guard Design

## Status

- Date: 2026-08-31
- Target: native Windows Claude Code CLI/TUI
- Phase: approved design for the first Windows milestone
- Runtime baseline: Windows 10 1809+ or Windows Server 2019+, PowerShell 7.4+

## Summary

Claude Guard currently implements its security boundary in Bash and explicitly rejects native Windows when curl uses Schannel. The first Windows milestone adds a native PowerShell implementation for the official Claude channel without changing the existing macOS/Linux Bash path.

The Windows implementation preserves the project's fail-closed semantics. It validates configuration, the pinned Claude client, lifecycle policy, project overrides, command-line arguments, the configured HTTP CONNECT proxy, TLS identity, the Anthropic-aligned exit IP, and IPv6 exposure before starting Claude Code. It uses .NET networking and certificate APIs rather than parsing curl's backend-specific verbose output.

The implementation is intentionally parallel rather than a cross-platform rewrite. Existing Bash behavior remains the reference contract while the Windows code is split into testable PowerShell modules.

## Evidence And Prior Art

The design incorporates the following upstream findings:

- Issue #6 and PR #8 establish that missing Schannel certificate metadata must not silently downgrade the TLS gate or be misreported as a MITM event.
- PR #11 demonstrates three load-bearing invariants: inspect the leaf certificate issuer, preserve TLS validation failure even when other evidence exists, and keep CONNECT evidence physically separate from certificate-controlled bytes.
- PR #4 requires the exit-IP probe to target `api.anthropic.com/cdn-cgi/trace`, with no default fallback to a differently routed hostname and no acceptance of a partial body from a failed request.
- PR #10 shows that user curl configuration can alter security behavior. The Windows path therefore does not invoke curl.
- Issue #14 requires static analysis to be an actual independent CI gate rather than an implied or manually run check.
- Issue #15 shows that the current shim backup model is unsafe across upgrades and symlinks. Installer work is excluded from this milestone.

## Goals

- Let a Windows user run the official Claude Code CLI/TUI through Claude Guard without WSL, Git Bash, curl, jq, or OpenSSL.
- Preserve fail-closed behavior for every required security check.
- Preserve the existing safe-config fields, environment-variable names, command intent, and stable exit-code categories where applicable.
- Keep `status` offline and make `doctor` run the full preflight without starting Claude or invoking a model.
- Keep the default test suite deterministic, credential-free, and network-free.
- Add Windows CI with pinned Pester and PSScriptAnalyzer versions while keeping existing Linux/macOS checks green.
- Provide actionable errors for unsupported PowerShell versions, invalid configuration, proxy failures, certificate failures, and policy violations.

## Non-Goals

- Do not port the CC Switch lane in this milestone.
- Do not implement the runtime watchdog, pause/resume, notifications, scheduled tasks, or detached process supervision.
- Do not build an installer, replace `claude`, or create command shims yet.
- Do not support Windows PowerShell 5.1.
- Do not support SOCKS or HTTPS proxy transports in this milestone.
- Do not add request forwarding, request rewriting, token handling, TLS interception, fingerprint spoofing, or ban-evasion behavior.
- Do not claim support for Claude Desktop's Code tab. The target is the separately installed `claude` CLI.

## Repository Layout

The Bash entry points remain unchanged. New Windows files are isolated:

```text
bin/
  claude-guard.ps1
src/ClaudeGuard/
  ClaudeGuard.psd1
  ClaudeGuard.psm1
  Public/
    Invoke-ClaudeGuard.ps1
    Invoke-ClaudeGuardDoctor.ps1
    Get-ClaudeGuardStatus.ps1
  Private/
    Configuration.ps1
    ClientIdentity.ps1
    FingerprintPolicy.ps1
    SettingsPolicy.ps1
    ArgumentPolicy.ps1
    EnvironmentPolicy.ps1
    PathPolicy.ps1
    ProxyConnect.ps1
    TlsPolicy.ps1
    EgressPolicy.ps1
    Ipv6Policy.ps1
    Result.ps1
    Ui.ps1
tests/windows/
  Unit/
  Integration/
  Fixtures/
scripts/
  check-windows.ps1
config/
  safe-claude.windows.example.json
```

`bin/claude-guard.ps1` is a thin argument-forwarding entry point. Policy and networking logic live in module functions with explicit inputs and structured results so they can be tested without launching processes or accessing the public network.

## Command Surface

The first milestone supports:

```powershell
pwsh -File .\bin\claude-guard.ps1
pwsh -File .\bin\claude-guard.ps1 --precheck-only
pwsh -File .\bin\claude-guard.ps1 doctor
pwsh -File .\bin\claude-guard.ps1 status
pwsh -File .\bin\claude-guard.ps1 status --json
pwsh -File .\bin\claude-guard.ps1 --model sonnet
```

All unconsumed arguments are forwarded to the pinned Claude client only after preflight succeeds. `--precheck-only` and `doctor` never start Claude. `status` never performs network access.

An installer may later expose the extensionless `claude-guard` command. This milestone does not modify an existing `claude` command or PATH entry.

## Configuration Contract

The Windows example uses the existing JSON fields:

- `command`
- `config_dir`
- `allowed_ips`
- `allowed_cidrs`
- `client_version`
- `client_sha256`
- `client_macos_team_id`
- `blocked_plugins`
- `blocked_models`
- `require_unpinned_model`
- `notify`

Windows-specific rules:

- `command` must resolve to an absolute regular file and must not resolve back to the Guard entry point.
- `config_dir` must resolve to an absolute directory path.
- A non-empty `client_macos_team_id` is rejected because Windows cannot satisfy that policy.
- `notify` is accepted for schema compatibility but has no effect in this milestone; status output reports that notifications are unavailable.
- Unknown fields may be parsed for forward compatibility but are ignored and cannot alter policy unless explicitly implemented.

Environment-variable compatibility is preserved for `CLAUDE_GUARD_CONFIG`, `CLAUDE_GUARD_SETTINGS`, `CLAUDE_GUARD_PROXY`, `CLAUDE_GUARD_CA_CERT`, `CLAUDE_GUARD_UI`, `CLAUDE_GUARD_FINGERPRINT_MODE`, `CLAUDE_GUARD_LEGACY_PROFILE_MODE`, and existing policy overrides used by the official lane.

Configuration precedence is explicit: process environment override, then JSON field where one exists, then the documented default. Empty strings never silently enable a feature.

## Preflight Data Flow

```text
PowerShell/runtime check
  -> parse and validate safe config
  -> normalize configured paths
  -> validate Claude client identity
  -> validate legacy-profile and client-fingerprint policy
  -> validate official settings and project overrides
  -> reject command-line policy bypasses
  -> create a sanitized child environment
  -> connect to the configured HTTP proxy
  -> verify HTTP CONNECT for each required host
  -> authenticate TLS and inspect the leaf certificate
  -> verify Anthropic-aligned exit IP
  -> verify IPv6 policy
  -> render a structured summary
  -> exit for precheck/doctor, otherwise start Claude in the foreground
```

Every step returns a `GuardResult` object containing a stable code, status, short reason, remediation, and redacted evidence. Rendering is separate from policy decisions so plain text, interactive progress, and JSON output cannot change whether a check passes.

## Security Invariants

1. A required check with missing evidence fails closed.
2. A configured proxy is mandatory and direct fallback is forbidden. The dedicated direct IPv6 leak probe is the only exception; it never sends application data and can only make the gate fail.
3. A successful TCP connection is not proof of CONNECT, and successful CONNECT is not proof of TLS identity.
4. TLS validation, hostname validation, leaf certificate selection, and issuer policy are independent gates.
5. Certificate-controlled bytes cannot be used as proxy CONNECT evidence.
6. The exit-IP response is accepted only when the request itself completed successfully.
7. Deterministic configuration or capability failures are not retried; transient transport failures may be retried.
8. `status` is offline; `doctor` never launches Claude; neither command invokes a model or uses an account token.
9. Sensitive configuration values, proxy credentials, real allowlists, absolute home paths, and live diagnostics are never written to the repository or unredacted JSON output.
10. The Windows implementation never silently falls back to the Bash implementation or a different network transport.

## HTTP CONNECT Design

The network module uses `System.Net.Sockets.TcpClient` to connect to the configured HTTP proxy. It writes a bounded HTTP/1.1 CONNECT request for the exact target host and reads only a bounded response-header block.

The CONNECT gate requires:

- proxy URI scheme `http`;
- an explicit proxy host and port;
- response status code 200;
- completion of the header terminator within the configured timeout and size limit;
- no attempt to reconnect directly to the target after proxy failure.

The implementation records CONNECT evidence in a dedicated structure produced before TLS begins. TLS certificate data never enters this structure.

Proxy credentials, if later supported, must be redacted at construction time and must not appear in logs or exceptions. This milestone may reject credential-bearing proxy URIs with a clear unsupported-capability error rather than risk accidental disclosure.

## TLS And Certificate Design

After CONNECT succeeds, the same network stream is wrapped in `System.Net.Security.SslStream`. Authentication uses the exact target hostname and TLS 1.2 or later. The callback captures certificate evidence but returns success only when .NET reports no certificate or hostname policy errors.

The TLS gate independently requires:

- `SslStream` authentication completed;
- hostname validation succeeded;
- certificate chain validation succeeded;
- a leaf certificate was present;
- the leaf certificate issuer was extracted from the leaf, not from an intermediate or root;
- the normalized leaf issuer does not match the existing MITM keyword policy.

The default trust source is the Windows certificate store. When `CLAUDE_GUARD_CA_CERT` is set, the module loads that PEM bundle into a custom root trust policy. An unreadable, empty, or unparsable bundle fails closed. The custom-bundle path requires PowerShell 7.4+ and a compatible .NET runtime; no fallback to the Windows store occurs after the user explicitly selects a bundle.

The structured result keeps these fields separate:

```text
proxy_connected
connect_status
tls_authenticated
hostname_valid
chain_valid
leaf_thumbprint
leaf_issuer
```

No exception message or raw certificate dump is treated as positive security evidence.

## Exit-IP And IPv6 Policy

The exit-IP probe uses the already verified proxy path and targets only:

```text
https://api.anthropic.com/cdn-cgi/trace
```

The response is accepted only after CONNECT and TLS pass and the HTTP request completes successfully. The parser extracts one valid IPv4 value from the `ip=` line and compares it with `allowed_ips` and `allowed_cidrs`. A partial body from a timed-out or failed request is discarded. There is no default fallback hostname.

The IPv6 check preserves the existing intent: the official API must not be publicly reachable over an unauthorized direct IPv6 path. Loopback, link-local, private, documentation, and known fake-IP-mapped ranges are classified separately from globally routable IPv6. An ambiguous result fails closed rather than assuming that IPv6 is safe.

## Client, Settings, And Argument Policy

Client identity checks preserve the upstream order:

- normalize and resolve the configured command path;
- reject recursion into Guard;
- run only the configured binary for `--version` in a sanitized environment;
- compare the expected version when pinned;
- hash the resolved file with SHA-256 and compare the expected value when pinned;
- reject `client_macos_team_id` on Windows.

The Windows fingerprint tripwire preserves the upstream modes `off`, `warn`, `fail-active`, and `strict`. It inspects only the configured client and the activation conditions already defined by the official lane. It does not rewrite the binary, spoof locale or timezone, or infer unsupported model policy. A scan failure in an enabled blocking mode fails closed.

Legacy default-profile inspection remains separate from the official `config_dir`. It reports likely route or credential contamination according to `CLAUDE_GUARD_LEGACY_PROFILE_MODE` without treating the legacy profile as the active official profile.

Settings checks reuse the existing risk categories for base URLs, authentication tokens, credential helpers, certificate and retry overrides, CC Switch routes, lifecycle escape hatches, blocked plugins, and optionally pinned models.

Project settings are discovered from the current directory toward the user profile boundary. Windows path comparisons use normalized paths with ordinal case-insensitive comparison. Drive-letter case, slash direction, and equivalent path spelling do not create distinct security identities. Reparse points are detected through filesystem metadata; they are not inferred from string differences alone.

CLI arguments that can replace settings, select alternate setting sources, start detached/background sessions, or enter unsupported lifecycle modes are rejected before any network request.

## Child Environment And Process Model

The child environment starts from an allowlisted Windows baseline rather than a literal empty environment. Required operating-system variables include `SystemRoot`, `WINDIR`, `ComSpec`, `PATH`, `PATHEXT`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `ProgramData`, and architecture-specific program directory variables when present.

High-risk routing, provider, token, update, detached-session, workflow, remote-control, telemetry, and retry-watchdog variables are removed or set to the official-lane policy values. The implementation constructs the environment as data and tests it before process creation.

Claude is started as a foreground child attached to the current console with stdin, stdout, and stderr preserved. The Guard process returns the Claude exit code. This milestone does not create a watchdog sidecar, background window, scheduled task, or hidden detached process.

## `doctor` And `status`

`doctor` runs the same configuration, client, settings, argument-neutral, CONNECT, TLS, exit-IP, and IPv6 checks used for launch. It then exits without starting Claude.

`status` performs only local inspection:

- PowerShell and module version;
- config path and schema status;
- client path, version, and hash status;
- settings-policy status;
- client-fingerprint and legacy-profile policy status;
- matching active Claude processes when they can be identified safely;
- watchdog support reported as `not_available_in_windows_milestone_1`;
- notification support reported as unavailable.

`status --json` emits the same bounded, redacted data with stable field names. It never reports `OK` for network readiness because it does not perform network checks.

## Error Model

The PowerShell path reuses upstream exit-code categories wherever the semantics match, including usage/configuration errors, IP lookup failure, unauthorized IP, settings/policy errors, TLS failure, IPv6 failure, fingerprint/client identity failure, and lifecycle-policy failure.

Every terminal failure includes:

- a stable symbolic code such as `CG_TLS_CHAIN_INVALID`;
- the compatible numeric process exit code;
- a one-line reason;
- a concrete remediation;
- bounded, redacted evidence suitable for `doctor` output.

Errors caused by unsupported PowerShell versions, proxy schemes, or explicitly selected CA features are deterministic and stop immediately. Timeouts and connection resets use bounded retries with no change of target, proxy, CA source, or security policy.

## Test Strategy

### Unit Tests

Pinned Pester tests cover:

- configuration parsing and precedence;
- required types and invalid JSON;
- IPv4 and CIDR membership;
- Windows path normalization and case-insensitive identity;
- recursion detection;
- SHA-256 and version mismatch;
- fingerprint modes, activation conditions, and scan failure;
- settings risk paths, blocked plugins, and model policy;
- prohibited CLI arguments;
- child-environment allowlist and denylist;
- error-code and JSON-result stability;
- redaction of home paths, proxy credentials, tokens, IP allowlists, and diagnostic evidence.

### Offline Integration Tests

Tests use a fake Claude executable, a loopback HTTP CONNECT fixture, and generated test certificates. No public endpoint or model is called.

Required scenarios include:

- valid CONNECT, TLS, hostname, leaf issuer, and allowed IP;
- missing or non-200 CONNECT response;
- proxy refusal with proof that no direct connection was attempted;
- invalid hostname;
- untrusted or expired certificate;
- CONNECT and benign issuer present while TLS validation fails;
- a multi-level chain whose leaf issuer is a blocked MITM issuer but whose root is benign;
- certificate-controlled content resembling a CONNECT response;
- missing leaf certificate or issuer;
- successful HTTP headers followed by a failed/partial exit-IP body;
- unauthorized IP and allowed CIDR boundaries;
- fake Claude argument and environment forwarding;
- `doctor`, `status`, and `--precheck-only` never launching fake Claude.

### Mutation Checks

The verification harness performs targeted mutations in an isolated copy and requires the matching test to fail:

- bypass TLS policy errors;
- select the chain root instead of the leaf;
- accept missing CONNECT evidence;
- merge certificate bytes into CONNECT evidence;
- accept an IP body from a failed request;
- retain a prohibited routing or credential environment variable.

Each mutation starts from a clean copy, runs only its owning test, and is discarded before the next mutation.

### Static Analysis And CI

`scripts/check-windows.ps1` runs syntax/import checks, Pester, targeted mutation checks, and PSScriptAnalyzer. Pester and PSScriptAnalyzer versions are pinned and installed into a repository-local tools directory in CI.

CI contains independently named required jobs:

- existing Linux Bash tests;
- existing macOS `/bin/bash` 3.2 tests;
- Windows PowerShell tests;
- Windows PSScriptAnalyzer.

Network-heavy or account-dependent checks remain outside the default suite.

## Manual Windows Validation

Before the README marks the milestone as verified, a maintainer records a redacted real-machine run containing:

- Windows version and architecture;
- PowerShell version;
- Guard commit SHA;
- Claude CLI version and redacted hash prefix;
- configured proxy type without credentials;
- `--precheck-only` result;
- proof that Claude did not start during precheck;
- negative tests for a closed proxy port and a deliberately unauthorized documentation IP.

Real tokens, full paths, real public IPs, complete hashes, settings files, and live diagnostic logs are not committed.

## Documentation And Rollout

The milestone updates:

- README platform support and Windows quickstart;
- `config/safe-claude.windows.example.json` using documentation-only values;
- command help for Windows-specific prerequisites and unsupported features;
- CHANGELOG with explicit statements of unchanged security boundaries;
- a Windows technical note describing the trust-store choice and validation evidence.

Initial wording is `experimental native Windows support` until both CI and a redacted real-machine precheck pass. The project must not describe the runtime watchdog, CC Switch lane, notifications, or installer as supported on Windows in this milestone.

## Deferred Milestones

1. Safe Windows installation and uninstall with an identity manifest, idempotent upgrades, and preservation of files, symlinks, junctions, and absent-entry state.
2. CC Switch lane parity.
3. Runtime watchdog and Windows job-object/process-tree design.
4. Optional Windows notifications.
5. Broader proxy transport support.
6. Evaluation of a shared cross-platform core only after behavioral parity is measured.

## Acceptance Criteria

- The existing Bash files and behavior remain unchanged unless a separately justified compatibility edit is required.
- All existing upstream checks pass on their supported platforms.
- Windows Pester and PSScriptAnalyzer jobs pass from a fresh checkout.
- The offline integration suite proves that every required network and certificate evidence item is load-bearing.
- `status` is network-free and `doctor` cannot start Claude.
- A sanitized fake Claude receives the original allowed arguments and no prohibited environment values.
- Unsupported or ambiguous security states fail closed with actionable errors.
- The Windows README describes only implemented and verified capabilities.
- A redacted native Windows precheck is recorded before stable-support language is used.

## Alternatives Rejected

### Cross-Platform Rewrite

A .NET or Rust rewrite could eventually unify behavior, but it would replace the already tested Bash security boundary and make parity difficult to prove in the first Windows milestone.

### Git Bash Compatibility Wrapper

Requiring Git Bash, jq, and a particular curl build is faster but does not provide native Windows support. PR #11 remains valuable prior art for Bash users and for security fixtures, not the runtime architecture selected here.

### Silent TLS Degradation

Allowing launch when issuer, chain, hostname, CONNECT, or exit-IP evidence is missing would contradict the project's purpose. Diagnostics may become more specific, but the pass criteria do not weaken.
