#!/usr/bin/env bash
# test_ctxredact.sh: behavioral test suite for the ctxredact secret broker.
#
# Run it three ways:
#   ./tests/test_ctxredact.sh                            functional only (no root)
#   CTXREDACT_PWD_BIN=/path/to/setuid/ctxredact ./...    + privilege-drop tests
#   sudo -E crond  ...                                   (setuid binary runs as
#                                                       NON-root; see below)
#
# The privilege-drop tests need a *setuid-root* binary and a *non-root*
# invoker. Build+install one with install.sh --prefix <scratch> (as root),
# then run this script as a non-root user with CTXREDACT_PWD_BIN pointing at it.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="$REPO/src/ctxredact.c"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DEV_VAULT="$WORK/vault.env"
DEV_BIN="$WORK/ctxredact-dev"
CFLAGS="-O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now"

PASS=0; FAIL=0
ok(){  PASS=$((PASS+1)); echo "  ok   - $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  FAIL - $1"; }
check(){ [ "$2" = "$3" ] && ok "$1" || bad "$1 (expected [$2] got [$3])"; }

# seed a scratch vault with DUMMY values (never real secrets)
cat > "$DEV_VAULT" <<'EOF'
TEST_ALPHA=alpha12345
TEST_BETA=beta67890
TEST_GAMMA=gamma_abc
# a comment line
TEST_EQ=a=b=c
TEST_EMPTY=
EOF

# regression: the shipped vault.env.example must parse cleanly under the real
# parser rules (values are literal to EOL; inline '#' would corrupt a value).
if [ -f "$REPO/vault.env.example" ]; then
  EXAMPLE_VAULT="$WORK/example.env"
  grep -v '^#' "$REPO/vault.env.example" > "$EXAMPLE_VAULT" || true
  bad_inline=0
  while IFS= read -r line; do
    case "$line" in *"#"*) bad_inline=1 ;; esac
  done < <(grep -v '^#' "$REPO/vault.env.example")
  [ "$bad_inline" -eq 0 ] && ok "vault.env.example has no inline comments" \
                          || bad "vault.env.example contains inline comments (parser trap)"
  example_bin="$WORK/ctxredact-example"
  cc $CFLAGS -DSECRETS_PATH=\"$EXAMPLE_VAULT\" -o "$example_bin" "$SRC" 2>/dev/null
  if "$example_bin" --check LAB_PASS >/dev/null 2>&1; then
    ok "vault.env.example parses under real rules"
  else
    bad "vault.env.example fails to parse"
  fi
fi

echo "== build dev test binary =="
cc $CFLAGS -DSECRETS_PATH=\"$DEV_VAULT\" -o "$DEV_BIN" "$SRC" 2>"$WORK/build.err" \
  || { echo "build failed:"; cat "$WORK/build.err"; exit 1; }
BIN="$DEV_BIN"

echo
echo "== functional (dev, non-setuid) =="
check "inject single value (len)"       "10"  "$($BIN TEST_ALPHA -- sh -c 'echo ${#TEST_ALPHA}')"
check "inject multiple names"          "10/9" "$($BIN TEST_ALPHA TEST_BETA -- sh -c 'echo ${#TEST_ALPHA}/${#TEST_BETA}')"
check "silent child -> empty stdout"   ""   "$($BIN TEST_ALPHA -- true)"
$BIN TEST_ALPHA -- true >/dev/null 2>&1; check "valid run -> exit 0" "0" "$?"
$BIN NOPE -- true >/dev/null 2>&1;       check "missing secret -> exit 1" "1" "$?"
$BIN TEST_ALPHA >/dev/null 2>&1;         check "missing -- -> exit 2" "2" "$?"
$BIN TEST_ALPHA true >/dev/null 2>&1;    check "-- without cmd -> exit 2" "2" "$?"
$BIN TEST_ALPHA -- printenv >/dev/null 2>&1; check "guard refuses printenv" "3" "$?"
$BIN TEST_ALPHA -- sh -c "cat $DEV_VAULT" >/dev/null 2>&1; check "guard refuses vault cat" "3" "$?"
$BIN TEST -- true >/dev/null 2>&1;       check "exact key boundary (no prefix)" "1" "$?"
$BIN TEST_EQ -- true >/dev/null 2>&1;    check "value with '=' present" "0" "$?"
$BIN TEST_EMPTY -- true >/dev/null 2>&1; check "empty value -> exit 1" "1" "$?"
$BIN --help >/dev/null 2>&1;             check "--help -> exit 0" "0" "$?"
$BIN --names >/dev/null 2>&1;            check "--names -> exit 0" "0" "$?"
names=$($BIN --names)
check "--names lists TEST_ALPHA" "1" "$(echo "$names" | grep -c '^TEST_ALPHA$')"
check "--names excludes value"   "0" "$(echo "$names" | grep -c 'alpha12345')"
desc=$($BIN --describe)
check "--describe status SET"   "SET" "$(echo "$desc" | awk '$1=="TEST_ALPHA"{print $2}')"
check "--describe len 10"       "10"  "$(echo "$desc" | awk '$1=="TEST_ALPHA"{print $3}')"
check "--describe excludes val" "0"   "$(echo "$desc" | grep -c 'alpha12345')"
$BIN --check TEST_ALPHA >/dev/null 2>&1; check "--check set -> 0" "0" "$?"
$BIN --check NOPE >/dev/null 2>&1;       check "--check unset -> 1" "1" "$?"

# CTXREDACT_SECRETS override is honored in NON-setuid (dev) mode
CTXREDACT_SECRETS="$DEV_VAULT" $BIN TEST_BETA -- sh -c 'echo ${#TEST_BETA}' >/dev/null 2>&1
check "dev honors CTXREDACT_SECRETS override" "0" "$?"

echo
echo "== --redact (output scrubbing) =="
check "redact scrubs a raw value echo" "[REDACTED:TEST_ALPHA]" "$($BIN --redact TEST_ALPHA -- sh -c 'echo "$TEST_ALPHA"')"
check "redact keeps text, scrubs value" "hello [REDACTED:TEST_ALPHA]" "$($BIN --redact TEST_ALPHA -- sh -c 'echo hello "$TEST_ALPHA"')"
check "redact preserves exit code" "7" "$($BIN --redact TEST_ALPHA -- sh -c 'exit 7' >/dev/null 2>&1; echo $?)"
check "redact exit code is 0 on success" "0" "$($BIN --redact TEST_ALPHA -- sh -c 'echo hi' >/dev/null 2>&1; echo $?)"
# each secret gets its OWN labeled marker (agent can tell which was scrubbed)
both=$($BIN --redact TEST_ALPHA TEST_BETA -- sh -c 'echo "$TEST_ALPHA $TEST_BETA"')
check "multi-key markers are labeled" "[REDACTED:TEST_ALPHA] [REDACTED:TEST_BETA]" "$both"
# marker must not contain any secret value
echo "$both" | grep -q 'alpha12345\|beta67890' && bad "marker leaks value" || ok "marker leaks no value"

echo
echo "== privilege-drop (setuid): needs CTXREDACT_PWD_BIN + CTXREDACT_TEST_VAULT =="
PWD_BIN="${CTXREDACT_PWD_BIN:-}"
TV="${CTXREDACT_TEST_VAULT:-}"
if [ -n "$PWD_BIN" ] && [ -x "$PWD_BIN" ] && [ -u "$PWD_BIN" ] && [ "$(id -u)" != "0" ] && [ -n "$TV" ]; then
  # 1. child must NOT run as root
  child_uid=$("$PWD_BIN" TEST_ALPHA -- sh -c 'id -u')
  if [ "$child_uid" != "0" ]; then ok "child runs as non-root (uid $child_uid)"; else bad "child ran as ROOT (uid 0)"; fi

  # 2. value injected correctly (length only, never the value)
  check "setuid inject value (len)" "10" "$("$PWD_BIN" TEST_ALPHA -- sh -c 'echo ${#TEST_ALPHA}')"

  # 3. CTXREDACT_SECRETS override is IGNORED in setuid mode (H2): point it at a
  #    non-existent file; injection must still work from the compiled path.
  r="$(CTXREDACT_SECRETS=/nonexistent/env-override "$PWD_BIN" TEST_ALPHA -- sh -c 'echo ${#TEST_ALPHA}' 2>&1)"
  check "setuid ignores CTXREDACT_SECRETS override" "10" "$r"

  # 4. child CANNOT read the root-owned vault (drop works). The vault path is
  #    passed via env (not argv) so the advisory guard doesn't pre-empt it;
  #    this proves the privilege drop, not the guard.
  r="$(CTXREDACT_TEST_VAULT="$TV" "$PWD_BIN" TEST_ALPHA -- sh -c 'cat "$CTXREDACT_TEST_VAULT" >/dev/null 2>&1 && echo READ || echo DENIED' 2>/dev/null)"
  check "child cannot read the vault" "DENIED" "$r"

  # 5. advisory guard still trips on obvious dumps even in setuid mode
  "$PWD_BIN" TEST_ALPHA -- printenv >/dev/null 2>&1; check "setuid guard refuses printenv" "3" "$?"

  # 6. --redact scrubs output even when the child is non-root
  check "setuid --redact scrubs value" "[REDACTED:TEST_ALPHA]" "$("$PWD_BIN" --redact TEST_ALPHA -- sh -c 'echo "$TEST_ALPHA"' 2>/dev/null)"
else
  echo "  (skipped: no setuid binary + vault, or running as root)"
fi

echo
echo "== summary =="
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
