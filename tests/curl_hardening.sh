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
printf 'fake ca\n' >"$TMP_DIR/cert.pem"
printf '{"command":"/bin/echo","allowed_ips":["203.0.113.10"]}\n' >"$TMP_DIR/allowed.json"

# 记录型假 curl：正常放行，只负责把每次调用的 argv 记下来。
cat >"$TMP_DIR/bin/curl" <<'EOF'
#!/usr/bin/env bash
args="$*"
printf '%s\n' "$args" >>"$HOME/curl-argv.log"

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
printf '%s\n' "$args" >>"$HOME/curlrc-argv.log"

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
      CLAUDE_GUARD_CA_CERT="$TMP_DIR/cert.pem" \
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
if awk '$1 != "-q" {print; bad=1} END {exit bad}' "$argv_log"; then
  :
else
  printf 'every curl invocation must pass -q as the first argument\n' >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. 每条 HTTPS 路径都必须显式固定 CA bundle。
#    Schannel 会忽略 SSL_CERT_FILE，仅靠环境变量不足以保证用的是配置里那份 CA。
# ---------------------------------------------------------------------------
assert_cacert() {
  local label="$1" pattern="$2" line
  line="$(grep -E "$pattern" "$argv_log" | head -1 || true)"
  if [ -z "$line" ]; then
    printf 'no curl invocation matched %s (%s)\n' "$label" "$pattern" >&2
    cat "$argv_log" >&2
    exit 1
  fi
  case "$line" in
    *"--cacert $TMP_DIR/cert.pem"*) ;;
    *)
      printf '%s must pass --cacert "$CA_CERT_FILE"\n' "$label" >&2
      printf '%s\n' "$line" >&2
      exit 1
      ;;
  esac
}

assert_cacert '出口 IP 探测'          '/cdn-cgi/trace'
assert_cacert 'Anthropic API TLS'     '(^| )-vI .*https://api\.anthropic\.com/ *$'
assert_cacert 'Claude 登录 TLS'       'https://platform\.claude\.com/ *$'
assert_cacert 'IPv6 泄漏检查'         '(^| )-6( |$)'

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
