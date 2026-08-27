#!/usr/bin/env bash
set -euo pipefail

# Schannel（Windows 原生 TLS 后端）不打印证书验证结果和 issuer，TLS 预检无法执行。
# 本用例要求：报错文案明确指出是平台不兼容，退出码仍是 7，不做无意义的重试，也不谎报
# 尝试次数；curl 自身以非零码退出时同样要认出后端，而不是含糊地报「无法连接」。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/home"

# 直接复用仓库里的官方 settings 示例：生命周期策略升级时它会一起更新，fixture 不会过期。
cp "$ROOT_DIR/config/official-settings-lifecycle.example.json" "$TMP_DIR/settings.json"

printf 'fake ca\n' >"$TMP_DIR/cert.pem"
printf '{"command":"/bin/echo","allowed_ips":["203.0.113.10"]}\n' >"$TMP_DIR/allowed.json"

# $1 = 假 curl 在 TLS 探测上的退出码
make_curl() {
  local dir="$TMP_DIR/bin-$1"
  mkdir -p "$dir"
  cat >"$dir/curl" <<EOF
#!/usr/bin/env bash
args="\$*"
printf '%s\n' "\$args" >>"\$HOME/curl.log"

if printf '%s' "\$args" | grep -Eq '(^| )-6( |\$)'; then
  exit 7
fi

if printf '%s' "\$args" | grep -q '/cdn-cgi/trace'; then
  printf 'fl=1f2\n'
  printf 'h=api.anthropic.com\n'
  printf 'ip=203.0.113.10\n'
  exit 0
fi

# Schannel 后端的 verbose 输出：隧道建好了，但没有 "SSL certificate verify ok"，
# 也没有 issuer 行。
if printf '%s' "\$args" | grep -q 'https://api.anthropic.com/'; then
  {
    printf '* CONNECT api.anthropic.com:443 HTTP/1.1\n'
    printf '* CONNECT tunnel established, response 200\n'
    printf '* schannel: disabled automatic use of client certificate\n'
    printf '* Connection #0 to host 127.0.0.1:7897 left intact\n'
  } >&2
  exit $1
fi

exit 1
EOF
  chmod +x "$dir/curl"
  printf '%s\n' "$dir"
}

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
      CLAUDE_GUARD_TLS_RETRIES=3 \
      CLAUDE_GUARD_UI=never \
      "$ROOT_DIR/bin/claude-guard" --precheck-only
  )
}

# $1 = curl 退出码，$2 = 用例名
assert_schannel_case() {
  local code="$1" label="$2" bin out status attempts
  bin="$(make_curl "$code")"
  : >"$TMP_DIR/home/curl.log"
  out="$TMP_DIR/out-$code"

  set +e
  run_precheck "$bin" >"$out" 2>&1
  status=$?
  set -e

  if [ "$status" -ne 7 ]; then
    printf '%s: returned %s instead of 7\n' "$label" "$status" >&2
    cat "$out" >&2
    exit 1
  fi

  # 报错必须指名平台不兼容，而不是含糊的「未显示证书验证通过」/「无法连接」——两者
  # 读起来都像在指控用户被中间人劫持或代理坏了。
  if ! grep -q 'Schannel' "$out"; then
    printf '%s: failure must name the TLS backend\n' "$label" >&2
    cat "$out" >&2
    exit 1
  fi
  if grep -qE '未显示证书验证通过|无法连接或验证' "$out"; then
    printf '%s: must not fall through to a generic TLS message\n' "$label" >&2
    cat "$out" >&2
    exit 1
  fi

  # 只探测了一次，就不能声称尝试了三次。
  if grep -q '次尝试' "$out"; then
    printf '%s: must not claim a retry count it did not spend\n' "$label" >&2
    cat "$out" >&2
    exit 1
  fi

  # 平台不支持是确定性结果：即使 TLS_CHECK_RETRIES=3，也只应探测一次。
  attempts="$(grep -c 'https://api.anthropic.com/ *$' "$TMP_DIR/home/curl.log" || true)"
  if [ "$attempts" -ne 1 ]; then
    printf '%s: must not retry, got %s attempts\n' "$label" "$attempts" >&2
    cat "$TMP_DIR/home/curl.log" >&2
    exit 1
  fi
}

# 1. Schannel，curl 自身成功退出（用户实际报告的形态）。
assert_schannel_case 0 'schannel exit 0'

# 2. Schannel，curl 因证书校验失败以 60 退出。后端识别必须先于退出码判定，否则会把
#    平台限制说成网络或代理问题，并且白白重试三次。
assert_schannel_case 60 'schannel exit 60'

printf 'tls backend platform ok\n'
