#!/usr/bin/env bash
set -euo pipefail

# curl 默认会读取 ~/.curlrc。official_net_env / clean_env 都用 env -i，但都把 HOME 传了
# 进去，所以用户的 .curlrc 一直对门禁生效——里面一行 insecure 就能关掉证书校验。
# -q 可以禁用配置文件，但**必须是 curl 后面的第一个参数**。
#
# 本用例断言的是运行时真实 argv，不是源码 grep。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/bin" "$TMP_DIR/home"

cp "$ROOT_DIR/config/official-settings-lifecycle.example.json" "$TMP_DIR/settings.json"
# CA 路径故意带空格：把参数拼成一行再匹配的断言会在这里失真。
mkdir -p "$TMP_DIR/ca dir"
CA_CERT_FILE="$TMP_DIR/ca dir/cert.pem"
printf 'fake ca\n' >"$CA_CERT_FILE"
printf '{"command":"/bin/echo","allowed_ips":["203.0.113.10"]}\n' >"$TMP_DIR/allowed.json"

# 记录型假 curl：正常放行，只负责把每次调用的 argv 记下来。
cat >"$TMP_DIR/bin/curl" <<'EOF'
#!/usr/bin/env bash
args="$*"
# TAB 分隔逐个参数写入："$*" 会抹掉参数边界，带空格的 CA 路径下断言会失真。
{ for a in "$@"; do printf '%s\t' "$a"; done; printf '\n'; } >>"$HOME/curl-argv.log"

if printf '%s' "$args" | grep -Eq '(^| )-6( |$)'; then
  exit 7
fi

if printf '%s' "$args" | grep -q '/cdn-cgi/trace'; then
  printf 'fl=1f2\n'
  printf 'h=api.anthropic.com\n'
  printf 'ip=203.0.113.10\n'
  exit 0
fi

if printf '%s' "$args" | grep -q 'https://api.anthropic.com/'; then
  {
    printf '* CONNECT api.anthropic.com:443 HTTP/1.1\n'
    printf '* CONNECT tunnel established\n'
    printf '* SSL certificate verify ok.\n'
    printf '*  issuer: C=US; O=Google Trust Services; CN=WE1\n'
  } >&2
  exit 0
fi

if printf '%s' "$args" | grep -q 'https://platform.claude.com/'; then
  {
    printf '* CONNECT platform.claude.com:443 HTTP/1.1\n'
    printf '* CONNECT tunnel established\n'
    printf '* SSL certificate verify ok.\n'
    printf '*  issuer: C=US; O=Let'\''s Encrypt; CN=YE1\n'
  } >&2
  exit 0
fi

exit 1
EOF
chmod +x "$TMP_DIR/bin/curl"

# .curlrc 敏感型假 curl：忠实模拟 curl 自身的行为——只有当 -q 不是首参时才读取
# ~/.curlrc；读到 insecure 就当证书校验已关闭，放行一条被中间人伪造的响应。
mkdir -p "$TMP_DIR/bin-curlrc"
cat >"$TMP_DIR/bin-curlrc/curl" <<'EOF'
#!/usr/bin/env bash
args="$*"
{ for a in "$@"; do printf '%s\t' "$a"; done; printf '\n'; } >>"$HOME/curlrc-argv.log"

if printf '%s' "$args" | grep -Eq '(^| )-6( |$)'; then
  exit 7
fi

insecure=0
if [ "${1:-}" != "-q" ] \
  && [ -f "$HOME/.curlrc" ] \
  && grep -qE '^[[:space:]]*(insecure|-k)[[:space:]]*$' "$HOME/.curlrc"; then
  insecure=1
fi

if [ "$insecure" -eq 0 ]; then
  # 证书校验生效：中间人的证书链不受信，curl 以 60 退出。
  exit 60
fi

# 证书校验被 .curlrc 关掉，中间人得以伪造响应。
if printf '%s' "$args" | grep -q '/cdn-cgi/trace'; then
  # 伪造一个白名单内的出口，直接绕过出口门禁。
  printf 'fl=1f2\n'
  printf 'h=api.anthropic.com\n'
  printf 'ip=203.0.113.10\n'
  exit 0
fi

# issuer 故意不命中 MITM 关键词黑名单——真实的拦截设备不会自报家门。
if printf '%s' "$args" | grep -qE 'https://(api\.anthropic\.com|platform\.claude\.com)/'; then
  {
    printf '* CONNECT tunnel established\n'
    printf '* SSL certificate verify ok.\n'
    printf '*  issuer: C=NL; O=Interception Appliance BV; CN=Corp Root\n'
  } >&2
  exit 0
fi

exit 1
EOF
chmod +x "$TMP_DIR/bin-curlrc/curl"

run_precheck() {
  (
    cd "$TMP_DIR"
    HOME="$TMP_DIR/home" \
      USER="guard-test" \
      PATH="$1:$PATH" \
      LANG="en_US.UTF-8" \
      CLAUDE_GUARD_CONFIG="$TMP_DIR/allowed.json" \
      CLAUDE_GUARD_SETTINGS="$TMP_DIR/settings.json" \
      CLAUDE_GUARD_CA_CERT="$CA_CERT_FILE" \
      CLAUDE_GUARD_IP_RETRIES=1 \
      CLAUDE_GUARD_TLS_RETRIES=1 \
      CLAUDE_GUARD_UI=never \
      "$ROOT_DIR/bin/claude-guard" --precheck-only
  )
}

# ---------------------------------------------------------------------------
# 1. 每次 curl 调用的第一个参数都必须是 -q。
# ---------------------------------------------------------------------------
: >"$TMP_DIR/home/curl-argv.log"
set +e
run_precheck "$TMP_DIR/bin" >"$TMP_DIR/ok.out" 2>&1
status=$?
set -e
if [ "$status" -ne 0 ]; then
  printf 'baseline precheck failed with %s\n' "$status" >&2
  cat "$TMP_DIR/ok.out" >&2
  exit 1
fi

argv_log="$TMP_DIR/home/curl-argv.log"
[ -s "$argv_log" ] || {
  printf 'no curl invocation was recorded\n' >&2
  exit 1
}
if ! awk -F'\t' '$1 != "-q" { print NR ": " $0; bad = 1 } END { exit bad }' "$argv_log"; then
  printf 'every curl invocation must pass -q as the first argument\n' >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. 每条 HTTPS 路径都必须显式固定 CA bundle。
#    Schannel 会忽略 SSL_CERT_FILE，仅靠环境变量不足以保证用的是配置里那份 CA。
# ---------------------------------------------------------------------------
# 按真实 argv 边界分类每次调用，并要求 --cacert 紧跟的下一个参数严格等于配置里那份 CA。
# 只断言 "--cacert" 出现过是不够的：把路径改成 /definitely/wrong-ca.pem 也照样通过。
if ! awk -F'\t' -v want="$CA_CERT_FILE" '
  function fail(label,   i) {
    printf "%s must pass --cacert \"%s\"\n", label, want
    print "  " $0
    bad = 1
  }
  {
    label = ""
    has6 = 0; has4 = 0; trace = 0; api = 0; login = 0
    for (i = 1; i <= NF; i++) {
      if ($i == "-6") { has6 = 1 }
      if ($i == "-4") { has4 = 1 }
      if ($i == "https://api.anthropic.com/cdn-cgi/trace") { trace = 1 }
      if ($i == "https://api.anthropic.com/") { api = 1 }
      if ($i == "https://platform.claude.com/") { login = 1 }
    }
    if (trace)             { label = "出口 IP 探测" }
    else if (has6 && api)  { label = "IPv6 泄漏检查" }
    else if (has4 && api)  { label = "Anthropic API TLS" }
    else if (login)        { label = "Claude 登录 TLS" }
    if (label == "") { next }
    seen[label] = 1

    ok = 0
    for (i = 1; i < NF; i++) {
      if ($i == "--cacert" && $(i + 1) == want) { ok = 1 }
    }
    if (!ok) { fail(label) }
  }
  END {
    split("出口 IP 探测,IPv6 泄漏检查,Anthropic API TLS,Claude 登录 TLS", want_labels, ",")
    for (i in want_labels) {
      if (!(want_labels[i] in seen)) {
        printf "no curl invocation matched %s\n", want_labels[i]
        bad = 1
      }
    }
    exit bad
  }
' "$argv_log" >"$TMP_DIR/cacert.err" 2>&1; then
  cat "$TMP_DIR/cacert.err" >&2
  cat "$argv_log" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. ~/.curlrc 里的 insecure 不得再绕过出口与 TLS 门禁。
#    白名单里正好有伪造响应中的那个 IP：一旦 .curlrc 生效就会 exit 0 放行，
#    因此这条断言是紧的。
# ---------------------------------------------------------------------------
printf 'insecure\n' >"$TMP_DIR/home/.curlrc"
: >"$TMP_DIR/home/curlrc-argv.log"
set +e
run_precheck "$TMP_DIR/bin-curlrc" >"$TMP_DIR/curlrc.out" 2>&1
status=$?
set -e
rm -f "$TMP_DIR/home/.curlrc"

if [ "$status" -eq 0 ]; then
  printf 'a ~/.curlrc containing "insecure" must not let the gate pass\n' >&2
  cat "$TMP_DIR/curlrc.out" >&2
  exit 1
fi
if [ "$status" -ne 3 ]; then
  printf 'expected exit 3 (egress probe fail-closed), got %s\n' "$status" >&2
  cat "$TMP_DIR/curlrc.out" >&2
  exit 1
fi
grep -q 'IP 检查失败：无法获取当前出口 IP' "$TMP_DIR/curlrc.out"

printf 'curl hardening ok\n'
