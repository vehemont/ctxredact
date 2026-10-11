#!/usr/bin/env bash
# test_bitwarden.sh: hermetic test of ctxredact --bitwarden WITHOUT a real
# Bitwarden account. A stub `bws` emits the same `NAME="VALUE"` env-format that
# the real Secrets Manager CLI produces, so the broker's flag parsing, vault
# lookup of BITWARDEN_TOKEN/PROJECT_ID, subprocess env-injection, output parse,
# and redaction are all exercised offline (CI-safe, no network, no token).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="$REPO/src/ctxredact.c"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  ok   - $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  FAIL - $1"; }

# --- fixture vault with the two bitwarden bootstrap entries (token is a FAKE) ---
VAULT="$WORK/vault.env"
{
  printf 'BITWARDEN_TOKEN=0.fake.uuid.secret\n'
  printf 'BITWARDEN_PROJECT_ID=11111111-2222-3333-4444-555555555555\n'
} > "$VAULT"

# --- stub bws: mimics `bws secret list <PROJECT_ID> -o env` ---
STUB="$WORK/bws"
cat > "$STUB" <<'SH'
#!/usr/bin/env bash
# emulate: bws secret list <PID> -o env ; token arrives via BWS_ACCESS_TOKEN
# argv: $1=secret $2=list $3=<PROJECT_ID> $4=-o $5=env
if [ "${1:-}" = "secret" ] && [ "${2:-}" = "list" ] && [ "${4:-}" = "-o" ] && [ "${5:-}" = "env" ]; then
  if [ -z "${BWS_ACCESS_TOKEN:-}" ]; then echo "stub: no token" >&2; exit 1; fi
  if [ "$3" != "11111111-2222-3333-4444-555555555555" ]; then
    echo "stub: wrong project $3" >&2; exit 1
  fi
  printf 'ALPHA="alpha12345"\nBETA="beta67890"\nQUOTED="va\\"lue"\n'
  exit 0
fi
echo "stub: unexpected args $*" >&2; exit 2
SH
chmod +x "$STUB"

# --- dev (non-setuid) broker ---
DEV="$WORK/ctxredact"
cc -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
   -fPIE -pie -Wl,-z,relro,-z,now \
   -DSECRETS_PATH="\"$VAULT\"" -o "$DEV" "$SRC" 2>"$WORK/build.err" \
   || { echo "build failed"; cat "$WORK/build.err"; exit 1; }

run(){ CTXREDACT_SECRETS="$VAULT" CTXREDACT_BWS="$STUB" "$DEV" "$@"; }

echo "== --bitwarden parse + inject + redact (hermetic) =="
# single secret injected, length returned (never value)
out=$(run --bitwarden --redact ALPHA -- sh -c 'echo "len=${#ALPHA}"; test "$ALPHA" = "alpha12345" && echo MATCH || echo DIFF' 2>/dev/null)
case "$out" in *len=10*MATCH*) ok "single secret fetched + injected (len, MATCH)";; *) bad "single secret: $out";; esac

# the value is redacted when echoed
out=$(run --bitwarden --redact ALPHA -- sh -c 'echo "v=$ALPHA"' 2>/dev/null)
case "$out" in *"[REDACTED:ALPHA]"*) ok "fetched value redacted in output";; *) bad "redact: $out";; esac

# multi-secret
out=$(run --bitwarden --redact ALPHA BETA -- sh -c 'echo "a=${#ALPHA} b=${#BETA}"' 2>/dev/null)
case "$out" in *"a=10 b=9"*) ok "multiple secrets injected";; *) bad "multi: $out";; esac

# quoted value: inner double-quote escaped, must unescape to va"lue (7 chars)
out=$(run --bitwarden --redact QUOTED -- sh -c 'echo "q=${#QUOTED}"; test "$QUOTED" = "va\"lue" && echo QMATCH || echo QDIFF' 2>/dev/null)
case "$out" in *"q=6"*"QMATCH"*) ok "quoted value unescaped + matched";; *) bad "quoted: $out";; esac

# fail-closed: unknown secret (error on stderr; also must not exec child)
out=$(run --bitwarden --redact NOPE -- sh -c 'echo x' 2>&1)
rc=$?
case "$rc" in 1) ok "missing secret -> fail-closed (exit 1)";; *) bad "missing: rc=$rc";; esac
case "$out" in *"NOPE"*) ok "missing secret reported by name";; *) bad "missing msg: $out";; esac
case "$out" in *"[REDACTED:"*) bad "child ran despite fail-closed";; *) ok "child did NOT run";; esac

# fail-closed: no BITWARDEN_TOKEN in vault
VAULT2="$WORK/vault2.env"; printf 'OTHER=1\n' > "$VAULT2"
out=$(CTXREDACT_SECRETS="$VAULT2" CTXREDACT_BWS="$STUB" "$DEV" --bitwarden --redact ALPHA -- sh -c 'echo x' 2>&1)
case "$out" in *BITWARDEN_TOKEN*not\ set*) ok "missing BITWARDEN_TOKEN -> clear error, no exec";; *) bad "no token: $out";; esac

# missing -- separator still enforced
run --bitwarden --redact ALPHA 2>&1 | grep -q "missing '--" && ok "still requires -- separator" || bad "-- separator"

echo
echo "== summary =="
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
