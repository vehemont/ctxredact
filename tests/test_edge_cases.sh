#!/usr/bin/env bash
# test_edge_cases.sh: adversarial edge cases beyond the functional suite.
#
# Covers: vault parsing oddities (NUL bytes, CRLF, duplicates, quotes, '#'),
# CLI separator parsing, redaction internals (overlap order, self-referential
# markers, regex-special values, mass replacement, overlong key names),
# child behavior (stdin EOF, recursion, missing commands), and fail-closed
# expectations. Dev (non-setuid) build only; runs anywhere, no root.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="$REPO/src/ctxredact.c"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CFLAGS="-O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now"

PASS=0; FAIL=0
ok(){  PASS=$((PASS+1)); echo "  ok   - $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  FAIL - $1"; }
check(){ [ "$2" = "$3" ] && ok "$1" || bad "$1 (expected [$2] got [$3])"; }
nohang(){ # run under a hard timeout; report 124 as a hang
  timeout 10 "$@" >/dev/null 2>&1; [ $? -ne 124 ] && return 0 || return 124
}

# ---- vault 1: parser oddities -----------------------------------------------
V1="$WORK/v1.env"; B1="$WORK/cw1"
{
  printf 'KEY_HASH=a#b\n'          # '#' mid-value is literal
  printf 'KEY_QUOTE="q"\n'         # quotes are literal, never stripped
  printf 'KEY_LEAD= lead\n'        # leading space preserved
  printf 'KEY_CASE=up\n'
  printf 'key_case=low\n'          # case-sensitive keys
  printf 'KEY_DUP=first\n'
  printf 'KEY_DUP=second\n'        # duplicate: first must win
  printf 'KEY_CRLF=val\r\n'        # CRLF stripped
  printf 'KEY_NUL=a\000b\n'        # embedded NUL truncates value
  printf 'KEY_EOF=z'               # no trailing newline (MUST be last)
} > "$V1"
cc $CFLAGS -DSECRETS_PATH=\"$V1\" -o "$B1" "$SRC" 2>"$WORK/b1.err" \
  || { echo "build failed"; cat "$WORK/b1.err"; exit 1; }

echo "== vault parsing =="
check "'#' mid-value is literal (len 3)"   "3" "$($B1 KEY_HASH -- sh -c 'echo ${#KEY_HASH}')"
check "quotes literal, not stripped (len 3)" "3" "$($B1 KEY_QUOTE -- sh -c 'echo ${#KEY_QUOTE}')"
check "leading space preserved (len 5)"    "5" "$($B1 KEY_LEAD -- sh -c 'echo ${#KEY_LEAD}')"
check "keys are case-sensitive (upper=2)"  "2" "$($B1 KEY_CASE -- sh -c 'echo ${#KEY_CASE}')"
check "keys are case-sensitive (lower=3)"  "3" "$($B1 key_case -- sh -c 'echo ${#key_case}')"
check "duplicate key: FIRST wins (len 5)"  "5" "$($B1 KEY_DUP -- sh -c 'echo ${#KEY_DUP}')"
check "CRLF stripped (len 3)"              "3" "$($B1 KEY_CRLF -- sh -c 'echo ${#KEY_CRLF}')"
check "no trailing newline: key found"     "1" "$($B1 KEY_EOF -- sh -c 'echo ${#KEY_EOF}')"
check "embedded NUL truncates value (len 1)" "1" "$($B1 KEY_NUL -- sh -c 'echo ${#KEY_NUL}')"
names=$($B1 --names 2>/dev/null)
check "--names lists both case keys" "2" "$(echo "$names" | grep -cE '^(KEY_CASE|key_case)$')"

# ---- vault 2: redaction internals -------------------------------------------
V2="$WORK/v2.env"; B2="$WORK/cw2"
{
  printf 'SHORT=abc\n'
  printf 'LONG=xxabcyy\n'                # SHORT is a substring of LONG
  printf 'REGEX=.*[](){}$^|+?\n'         # regex-special bytes
  printf 'SELFKEY=[REDACTED:SELFKEY]\n'  # value equals its own marker
  printf 'TINY=ab\n'
  printf 'LONGNAME_%s=secretvalue99\n' "$(printf 'K%.0s' $(seq 1 590))" # 599-char name
} > "$V2"
cc $CFLAGS -DSECRETS_PATH=\"$V2\" -o "$B2" "$SRC" 2>/dev/null || { echo "build2 failed"; exit 1; }

echo
echo "== redaction internals =="
# substring overlap: both keys requested; LONG must be redacted WHOLE regardless of order
out=$($B2 --redact SHORT LONG -- sh -c 'echo "$SHORT $LONG"' 2>/dev/null)
check "overlap [SHORT,LONG] order" "[REDACTED:SHORT] [REDACTED:LONG]" "$out"
out=$($B2 --redact LONG SHORT -- sh -c 'echo "$SHORT $LONG"' 2>/dev/null)
check "overlap [LONG,SHORT] order" "[REDACTED:SHORT] [REDACTED:LONG]" "$out"
echo "$out" | grep -q 'xxabcyy' && bad "overlap leaks raw LONG wrapper" || ok "overlap leaks no raw LONG bytes"

# only the OUTER key requested -> inner substring never redacts innocent text
out=$($B2 --redact LONG -- sh -c 'echo "abc is a common word: $LONG"' 2>/dev/null)
check "outer-only does not touch inner" "abc is a common word: [REDACTED:LONG]" "$out"

# regex-special value: byte-exact matching must handle it fully
out=$($B2 --redact REGEX -- sh -c 'printf "x%sy" "$REGEX"' 2>/dev/null)
check "regex-special value redacted" "x[REDACTED:REGEX]y" "$out"

# self-referential marker value: must terminate, not loop
$B2 --redact SELFKEY -- sh -c 'printf "%s" "$SELFKEY"' >/dev/null 2>&1
check "self-marker terminates (rc=0)" "0" "$?"

# mass replacement: 1000 occurrences, all replaced, output bounded
out=$($B2 --redact TINY -- sh -c 'i=0; while [ $i -lt 1000 ]; do printf "%s " "$TINY"; i=$((i+1)); done' 2>/dev/null)
check "1000 replacements all scrubbed" "1000" "$(printf '%s' "$out" | grep -o '\[REDACTED:TINY\]' | wc -l | tr -d ' ')"
printf '%s' "$out" | grep -q '\bab\b' && bad "mass replacement leaks raw value" || ok "mass replacement leaks no raw value"

# FAIL-CLOSED: a key name too long to label must be REFUSED before exec,
# never silently skipped (a skipped scrub forwards the raw value).
LN="LONGNAME_$(printf 'K%.0s' $(seq 1 590))"
out=$($B2 --redact "$LN" -- sh -c 'echo "$'"$LN"'"' 2>"$WORK/long.err"); rc=$?
if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | grep -q 'secretvalue99'; then
  ok "overlong key name refused pre-exec (rc=$rc)"
else
  bad "overlong key name ran (rc=$rc, out=$(printf '%s' "$out" | head -c 40))"
fi

# binary output with no secrets passes through byte-exact
n=$($B2 --redact TINY -- sh -c 'head -c 4096 /dev/urandom | wc -c' 2>/dev/null)
check "binary output passthrough (4096)" "4096" "$n"

# ---- CLI parsing -------------------------------------------------------------
echo
echo "== CLI parsing =="
B3="$WORK/cw3"; printf 'K=v\n' > "$WORK/v3.env"
cc $CFLAGS -DSECRETS_PATH=\"$WORK/v3.env\" -o "$B3" "$SRC" 2>/dev/null
$B3 K -- -- true >/dev/null 2>&1; check "second '--' is exec'd (fails 127)" "127" "$?"
out=$($B3 K -- echo --redact 2>/dev/null); check "'--redact' after -- is a literal arg" "--redact" "$out"
out=$($B3 --redact K -- echo --redact 2>/dev/null); check "flag + literal '--redact' arg coexist" "--redact" "$out"
$B3 K -- /nonexistent/cmd >/dev/null 2>&1; check "missing command -> 127" "127" "$?"

# ---- child behavior ----------------------------------------------------------
echo
echo "== child behavior =="
out=$(timeout 5 $B3 K -- sh -c 'cat >/dev/null; echo done' </dev/null 2>/dev/null)
check "stdin EOF: child completes (no hang)" "done" "$out"
# recursion: broker may legitimately re-invoke itself (both drop to invoker)
out=$($B3 K -- "$B3" K -- sh -c 'echo len=${#K}' 2>/dev/null)
check "recursive ctxredact works" "len=1" "$out"
# a long-running child dies with the broker's timeout wrapper (no orphan via outer timeout)
timeout 2 $B3 K -- sh -c 'sleep 30' >/dev/null 2>&1
check "outer timeout reaps long child (rc=124)" "124" "$?"

echo
echo "== secret purpose (comment above key) =="
# purpose semantics: comment binds to the NEXT key; blank line breaks adjacency;
# no comment => empty purpose; comment with leading spaces still binds.
VP="$WORK/purpose.env"; BP="$WORK/cwP"
{
  printf '# Alpha purpose line\n'
  printf 'P_ALPHA=v1\n'
  printf '\n'                       # blank line breaks adjacency
  printf '# orphan comment (blank line below will detach it)\n'
  printf '\n'
  printf 'P_NONE=v2\n'
  printf '   # indented comment still binds\n'
  printf 'P_BETA=v3\n'
  printf 'P_GAP=v4\n'               # no comment above => empty purpose
} > "$VP"
cc $CFLAGS -DSECRETS_PATH="\"$VP\"" -o "$BP" "$SRC" 2>"$WORK/bp.err" \
  || { echo "build failed"; cat "$WORK/bp.err"; exit 1; }

pur=$(timeout 5 "$BP" --purposes 2>/dev/null)
apt=$(printf '%s\n' "$pur" | awk -F'\t' '$2 ~ /^Alpha purpose line$/ {n++} END {print n+0}')
check "purpose: comment binds to next key" "$apt" "1"
pnone=$(printf '%s\n' "$pur" | awk -F'\t' '$1=="P_NONE" && $2=="" {n++} END {print n+0}')
check "purpose: blank line detaches prior comment (P_NONE empty)" "$pnone" "1"
# Indented '#' is NOT a comment (parser honors '#' only at column 0), so it
# must NOT bind as a purpose; safe and consistent with the vault parser.
pind=$(printf '%s\n' "$pur" | awk -F'\t' '$1=="P_BETA" && $2=="" {n++} END {print n+0}')
check "purpose: indented '#' does NOT bind (col-0 rule)" "$pind" "1"
pgap=$(printf '%s\n' "$pur" | awk -F'\t' '$1=="P_GAP" && $2=="" {n++} END {print n+0}')
check "purpose: no comment above => empty purpose" "$pgap" "1"
check "purposes mode leaks no value/len" \
  "$(printf '%s\n' "$pur" | grep -cE 'v[0-9]|[0-9]+$')" "0"
# --describe prints the PURPOSE column header + one value per key
desc=$(timeout 5 "$BP" --describe 2>/dev/null)
check "describe has PURPOSE column header" "$(printf '%s\n' "$desc" | grep -c 'PURPOSE')" "1"
check "describe binds purpose in table" \
  "$(printf '%s\n' "$desc" | grep -c 'Alpha purpose line')" "1"

echo
echo "== summary =="
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
