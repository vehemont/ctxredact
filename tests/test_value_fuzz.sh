#!/usr/bin/env bash
# Character-level fuzz of secret VALUES through real scripts.
#
# Answers: "do escaping issues occur when hostile characters are inside a
# secret and a script uses it?" by exercising the three real usage patterns:
#
#   1. SAFE PATTERN: compare/length without echoing (test "$K" = "$1")
#   2. ACCIDENTAL ECHO (quoted): printf "%s" "$K"   -> must come back as marker
#   3. SLOPPY ECHO (unquoted): printf "%s" $K      -> shell may transform
#      (word-splitting/globbing happen in the USER's command before redaction
#      ever sees bytes; single-token values must still redact exactly)
#
# Canary values ($(echo CANARY_RAN), `echo CANARY_RAN`) prove no layer ever
# RE-EVALUATES a secret's contents.
#
# Fixture values are printable-only: the vault is a line-based KEY=value file
# (embedded NUL/newline truncation is covered in test_edge_cases.sh).
set -u
SRC="$(cd "$(dirname "$0")/.." && pwd)/src/ctxredact.c"
V=$(mktemp -d)
BIN="$V/ctxredact-dev"
EMPTY="$V/empty"; mkdir -p "$EMPTY"
# Compile a NON-setuid dev broker for this run: the setuid live broker ignores
# CTXREDACT_SECRETS (by design), but parsing/injection/redaction code paths are
# identical. Same approach as tests/test_ctxredact.sh. (Quote shape matters:
# -DSECRETS_PATH='"/path"': inner quotes must survive to the compiler.)
cc -O2 -DSECRETS_PATH='"/nonexistent/vault.env"' -o "$BIN" "$SRC" 2>/dev/null || {
  echo "cannot compile dev broker (cc missing?)"; exit 1; }
trap 'rm -rf "$V"' EXIT

PASS=0; FAIL=0; KNOWN=0

ok()     { PASS=$((PASS+1)); }
bad()    { FAIL=$((FAIL+1)); echo "  FAIL - $1"; [ -n "${2:-}" ] && echo "        $2"; }
known()  { KNOWN=$((KNOWN+1)); }

leaks() {  # $1=text, $2..=probes ; returns 0 if any probe found OUTSIDE markers
  local t="$1" p
  t=${t//\[REDACTED:*\]/}   # marker text itself may contain a fuzz value
  shift
  for p in "$@"; do
    [ -z "$p" ] && continue
    case "$t" in *"$p"*) return 0 ;; esac
  done
  return 1
}

mapfile -t CASES < <(python3 - <<'PYEOF'
hostile = list("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
cases = [f"zz{c}zz" for c in hostile]
cases += [
    'a"b"c', "a'b'c", "a`b`c", "a$b", "a${b}c", "a\\b", "\\\\", '""', "''",
    "a b", "a  b", " leading", "trailing ", "tab\there",
    "$(echo CANARY_RAN)", "`echo CANARY_RAN`", "${CANARY_VAR}",
    "$(danger)", "${danger}", "`danger`", "$((1+1))",
    "glob*star", "gl?ob", "gl[ob]", "gl{ob,b}",
    "semi;colon", "pipe|char", "amp&ers", "100%yes", "hash#tag", "at@sign",
    "colon:value", "eq=uals", "plus+", "dash-dash", "dot.file", "sla/sh",
    "back\\\\slash", "a'b\"c", "~tilde", "^caret", "<angle>", "(paren)",
    "[bracket]", "{brace}",
    "[REDACTED:TEST_KEY]", "[REDACTED:", "[REDACTED:X]", "REDACTED", "[]",
]
print("\n".join(cases))
PYEOF
)

echo "== fuzzing ${#CASES[@]} hostile values through 3 script usage patterns =="

for val in "${CASES[@]}"; do
  umask 077
  { echo "TEST_KEY=$val"; echo "OTHER_KEY=staticvalue"; } > "$V/vault.env"
  unset CTXREDACT_SECRETS
  run() { CTXREDACT_SECRETS="$V/vault.env" "$BIN" --redact TEST_KEY -- sh -c "$1" 2>&1; }

  # --- 1. safe pattern: equality via argv, length via ${#} (never echoes value)
  out=$(run 'test "$TEST_KEY" = "$1" && echo MATCH || echo DIFF; echo "len=${#TEST_KEY}"' )
  # (value passed as $1 by the harness below; it must be in argv, so rerun inline)
  out=$(CTXREDACT_SECRETS="$V/vault.env" "$BIN" --redact TEST_KEY -- \
        sh -c 'test "$TEST_KEY" = "$1" && echo MATCH || echo DIFF; echo "len=${#TEST_KEY}"' sh "$val" 2>&1)
  case "$out" in *MATCH*) ok ;; *) bad "safe-pattern round-trip mangled" "value=$(printf %q "$val") out=$out" ;; esac
  leaks "$out" "$val" && bad "safe-pattern LEAK" "value=$(printf %q "$val") out=$out" || ok

  # --- 2. accidental echo, QUOTED: marker must replace the value
  out=$(run 'printf "v=%s\n" "$TEST_KEY"')
  if case "$val" in *"[REDACTED:"*) true ;; *) false ;; esac; then
    : # marker-spoof class: value IS marker text; swap is textually invisible.
    : # assert only no-canary below.
  else
    case "$out" in *"[REDACTED:TEST_KEY]"*) ok ;; *) bad "quoted echo NOT redacted" "value=$(printf %q "$val") out=$out" ;; esac
    frag_h=${val:0:8}; frag_t=${val: -8}
    leaks "$out" "$val" "$frag_h" "$frag_t" \
      && bad "quoted echo LEAK (value or frag)" "value=$(printf %q "$val") out=$out" || ok
  fi
  case "$out" in *CANARY_RAN*) bad "RE-EVALUATION: canary executed!" "value=$(printf %q "$val") out=$out" ;; *) ok ;; esac
  case "$out" in *"staticvalue"*) bad "OTHER_KEY leaked into output" "$out" ;; *) ok ;; esac

  # --- 3. sloppy echo, UNQUOTED, inside empty dir (glob finds nothing):
  # single-token values pass through the shell untouched -> must still redact.
  out=$(run 'cd "$1" && printf "v=%s\n" $TEST_KEY' sh "$EMPTY")
  if case "$val" in ""|*[[:space:]]*) true ;; *) false ;; esac; then
    known   # whitespace values get word-split by the USER's shell first;
            # documented transform class (same as base64), not a redaction bug
  else
    case "$out" in *"[REDACTED:TEST_KEY]"*) ok ;;
      *) bad "unquoted echo not redacted (single-token)" "value=$(printf %q "$val") out=$out" ;;
    esac
    leaks "$out" "$val" && bad "unquoted echo LEAK (single-token)" "value=$(printf %q "$val") out=$out" || ok
  fi
done

echo
echo "== summary =="
echo "PASS=$PASS FAIL=$FAIL KNOWN_GAPS=$KNOWN"
[ "$FAIL" -eq 0 ]
