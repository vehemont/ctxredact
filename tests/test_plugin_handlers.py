#!/usr/bin/env python3
"""Handler-level regression tests for the ctxredact Hermes plugin.

Run:  python3 tests/test_plugin_handlers.py
Builds a scratch dev binary + fake vault, then exercises tools.py handlers
with _binary() monkeypatched (the validation logic is tested separately).

These are SYNTHETIC secrets; never run against the live vault.
"""
import json
import importlib
import os
import stat
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "plugin"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "ctxredact_plugin", os.path.join(REPO, "plugin", "__init__.py"))
tools = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tools)  # single-file plugin; import as a module

ALPHA = "alpha12345"
BETA = "beta67890"

PASS = 0
FAIL = 0


def check(name, ok_, detail=""):
    global PASS, FAIL
    if ok_:
        PASS += 1
        print(f"  ok   - {name}")
    else:
        FAIL += 1
        print(f"  FAIL - {name} {detail}")


def main():
    work = tempfile.mkdtemp()
    vault = os.path.join(work, "vault.env")
    devbin = os.path.join(work, "ctxredact-dev")
    with open(vault, "w") as f:
        f.write(f"# Alpha-used-by-unit-tests\nTEST_ALPHA={ALPHA}\n"
                f"# Beta-creds-for-the-bridge\nTEST_BETA={BETA}\n")
    rc = subprocess.run(
        ["cc", "-O2", "-Wall", "-fPIE", "-pie",
         f'-DSECRETS_PATH="{vault}"', "-o", devbin,
         os.path.join(REPO, "src", "ctxredact.c")],
        capture_output=True, text=True)
    if rc.returncode != 0:
        print("build failed:", rc.stderr)
        sys.exit(1)
    os.chmod(devbin, 0o755)
    _real_binary = tools._binary           # save for restore later
    tools._binary = lambda: devbin         # monkeypatch: skip setuid validation

    print("== run_with_secrets ==")
    # 1. redaction is mandatory: passing redact=false must NOT disable scrubbing
    r = json.loads(tools.run_with_secrets(
        {"command": 'echo "$TEST_ALPHA"', "keys": ["TEST_ALPHA"], "redact": False}))
    check("redact=false param is IGNORED (always scrubs)",
          ALPHA not in r.get("output", "") and "REDACTED:TEST_ALPHA" in r.get("output", ""),
          repr(r))
    # 2. labeled marker is returned, value never present
    r = json.loads(tools.run_with_secrets(
        {"command": 'echo hi "$TEST_ALPHA" bye', "keys": ["TEST_ALPHA"]}))
    check("labeled marker in output", r["output"] == "hi [REDACTED:TEST_ALPHA] bye\n", repr(r))
    # 3. multi-key: distinct markers
    r = json.loads(tools.run_with_secrets(
        {"command": 'echo "$TEST_ALPHA $TEST_BETA"', "keys": ["TEST_ALPHA", "TEST_BETA"]}))
    check("multi-key distinct markers",
          "[REDACTED:TEST_ALPHA]" in r["output"] and "[REDACTED:TEST_BETA]" in r["output"]
          and ALPHA not in r["output"] and BETA not in r["output"], repr(r))
    # 4. stderr allowlist: child stderr is scrubbed via the output pipe; broker
    #    stderr (warning lines) is allowlisted. SNEAKY must not appear anywhere.
    r = json.loads(tools.run_with_secrets(
        {"command": 'echo "SNEAKY $TEST_ALPHA" >&2', "keys": ["TEST_ALPHA"]}))
    check("child stderr scrubbed, value gone",
          ALPHA not in r["output"] and ALPHA not in r["stderr"]
          and "[REDACTED:TEST_ALPHA]" in r["output"],
          repr(r))
    # 4b. direct unit test of the stderr allowlist
    mixed = tools._safe_stderr(
        "ctxredact: warning: not setuid-root; child will inherit agent perms\n"
        "error: secret 'FOO' not set/empty in /vault\n"
        "LEAKED SECRET VALUE base64==\n"
        "error: oom\n")
    check("stderr allowlist keeps known, drops unknown",
          mixed.splitlines()[:2] == [
              "ctxredact: warning: not setuid-root; child will inherit agent perms",
              "error: secret 'FOO' not set/empty in /vault"]
          and "LEAKED" not in mixed and "[1 unrecognized" in mixed, repr(mixed))
    # 5. no command / no keys -> error, no exec
    r = json.loads(tools.run_with_secrets({"command": "", "keys": ["TEST_ALPHA"]}))
    check("empty command rejected", "error" in r, repr(r))
    r = json.loads(tools.run_with_secrets({"command": "echo hi", "keys": []}))
    check("empty keys rejected", "error" in r, repr(r))
    # 6. CTXREDACT_SECRETS in the handler env must not reach the broker
    os.environ["CTXREDACT_SECRETS"] = "/nonexistent/poison"
    r = json.loads(tools.run_with_secrets(
        {"command": 'echo ${#TEST_ALPHA}', "keys": ["TEST_ALPHA"]}))
    check("CTXREDACT_SECRETS poisoned env ignored", r["output"].strip() == str(len(ALPHA)), repr(r))
    del os.environ["CTXREDACT_SECRETS"]
    # 7. timeout kills the whole process group (no orphan children).
    #    Shorten the timeout so the test doesn't take two minutes.
    orig_timeout = tools.DEFAULT_TIMEOUT
    tools.DEFAULT_TIMEOUT = 3
    try:
        r = json.loads(tools.run_with_secrets(
            {"command": 'sleep 300', "keys": ["TEST_ALPHA"]}))
        check("timeout returns error json", "error" in r and "timed out" in r.get("error", ""), repr(r))
        import time
        time.sleep(0.5)  # let SIGKILL settle
        p = subprocess.run(["pgrep", "-f", "sleep 300"], capture_output=True, text=True)
        check("no orphaned child after timeout", p.returncode != 0, repr(p.stdout))
    finally:
        tools.DEFAULT_TIMEOUT = orig_timeout

    # 8. ambient environment is NOT inherited: a secret set in the handler's
    #    own environment must not reach the child (env-dumping commands cannot
    #    leak gateway credentials).
    os.environ["AMBIENT_TEST_SECRET"] = "sk-live-ambient-secret-123"
    r = json.loads(tools.run_with_secrets(
        {"command": 'echo "ambient=${AMBIENT_TEST_SECRET:-absent}"', "keys": ["TEST_ALPHA"]}))
    check("ambient env NOT inherited by child",
          "sk-live-ambient-secret-123" not in r["output"]
          and r["output"].strip().endswith("absent"), repr(r["output"]))
    del os.environ["AMBIENT_TEST_SECRET"]

    # 9. non-UTF-8 child output is handled (errors=replace) without orphaning
    r = json.loads(tools.run_with_secrets(
        {"command": 'printf "ok\\xff\\xfe\\n"; echo "$TEST_ALPHA"', "keys": ["TEST_ALPHA"]}))
    check("non-UTF8 output survives + redaction intact",
          "ok" in r["output"] and ALPHA not in r["output"], repr(r["output"][:60]))

    # 10. basic PATH still available to the child (shell utilities resolve)
    r = json.loads(tools.run_with_secrets(
        {"command": 'which sh && echo ${#TEST_ALPHA}', "keys": ["TEST_ALPHA"]}))
    check("child PATH works", "/bin/sh" in r["output"] or "/usr/bin/sh" in r["output"], repr(r["output"]))

    # 11. output cap: a child dumping 500KB must be truncated, never returned whole.
    #     Head+tail cap: the final line (the interesting part of long output) must
    #     survive, the omission marker must state how much was dropped, and the
    #     result must report true sizes so the model knows what it's missing.
    orig_cap = tools.MAX_OUTPUT_CHARS
    tools.MAX_OUTPUT_CHARS = 5000
    try:
        r = json.loads(tools.run_with_secrets(
            {"command": 'head -c 500000 /dev/zero | tr "\\0" "x"; echo; echo "FINAL: error 42"; echo "$TEST_ALPHA"',
             "keys": ["TEST_ALPHA"]}))
        check("oversized output truncated + flagged",
              r.get("truncated") is True and len(r["output"]) < 5600
              and "characters omitted" in r["output"], repr(r["output"][-120:]))
        check("tail survives truncation",
              "FINAL: error 42" in r["output"]
              and r["output"].index("FINAL: error 42") > r["output"].index("omitted"),
              repr(r["output"][-120:]))
        check("true sizes reported", r.get("output_chars", 0) > 500_000
              and r["output_chars"] > len(r["output"]), repr(r.get("output_chars")))
        check("secret still redacted inside capped output",
              ALPHA not in r["output"] and "[REDACTED:TEST_ALPHA]" in r["output"],
              repr(r["output"][-160:]))
    finally:
        tools.MAX_OUTPUT_CHARS = orig_cap

    # 11b. degenerate boundary: a cap smaller than TAIL_CHARS must still be
    #      honored; head must never go negative (caught live: cap=300 < tail=4000
    #      made the "truncated" output LONGER than the cap and duplicated content)
    orig_cap, orig_tail = tools.MAX_OUTPUT_CHARS, tools.TAIL_CHARS
    tools.MAX_OUTPUT_CHARS = 300
    try:
        r = json.loads(tools.run_with_secrets(
            {"command": 'head -c 500000 /dev/zero | tr "\\0" "x"',
             "keys": ["TEST_ALPHA"]}))
        out = r["output"]
        check("tiny cap still honored (head never negative)",
              r.get("truncated") is True and len(out) < 700
              and "kept first 225 + last 75 of 500,000" in out,
              repr(out[-120:]))
    finally:
        tools.MAX_OUTPUT_CHARS, tools.TAIL_CHARS = orig_cap, orig_tail

    # 11c. operator env override: CTXREDACT_MAX_OUTPUT is read at import time;
    #      valid values raise the viewport, garbage/zero/negative fall back to
    #      the default (never break the plugin, never allow zero).
    def _reload():
        spec = importlib.util.spec_from_file_location(
            "ctxredact_plugin", os.path.join(REPO, "plugin", "__init__.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    saved = os.environ.get("CTXREDACT_MAX_OUTPUT")
    try:
        for val, want in (("200000", 200_000), ("junk", 64_000), ("0", 64_000), ("-5", 64_000), ("", 64_000)):
            os.environ["CTXREDACT_MAX_OUTPUT"] = val
            m = _reload()
            check(f"CTXREDACT_MAX_OUTPUT={val!r} -> {want:,}",
                  m.MAX_OUTPUT_CHARS == want, repr(m.MAX_OUTPUT_CHARS))
    finally:
        if saved is None:
            os.environ.pop("CTXREDACT_MAX_OUTPUT", None)
        else:
            os.environ["CTXREDACT_MAX_OUTPUT"] = saved

    print("== check_secret / list_secrets ==")
    r = json.loads(tools.check_secret({"name": "TEST_ALPHA"}))
    check("check_secret set=true", r == {"name": "TEST_ALPHA", "set": True}, repr(r))
    r = json.loads(tools.check_secret({"name": "NOPE"}))
    check("check_secret set=false", r == {"name": "NOPE", "set": False}, repr(r))
    r = json.loads(tools.list_secrets({}))
    check("list_secrets names only, no values",
          r["keys"] == ["TEST_ALPHA", "TEST_BETA"] and ALPHA not in json.dumps(r), repr(r))
    check("list_secrets surfaces purposes (comment above key)",
          r["purposes"] == {"TEST_ALPHA": "Alpha-used-by-unit-tests",
                            "TEST_BETA": "Beta-creds-for-the-bridge"}, repr(r.get("purposes")))

    print("== _binary() validation and auto-discovery ==")
    # restore the real _binary (undo the monkeypatch from earlier)
    tools._binary = _real_binary
    # dev binary is not setuid/root-owned -> must be rejected
    os.environ["CTXREDACT_BIN"] = devbin
    try:
        tools._binary()
        check("non-setuid binary rejected", False, "no exception raised")
    except ValueError as e:
        check("non-setuid binary rejected", "setuid" in str(e) or "root" in str(e), str(e))
    # missing binary -> rejected
    os.environ["CTXREDACT_BIN"] = os.path.join(work, "does-not-exist")
    try:
        tools._binary()
        check("missing binary rejected", False, "no exception raised")
    except ValueError as e:
        check("missing binary rejected", "not found" in str(e), str(e))
    os.environ.pop("CTXREDACT_BIN", None)
    # auto-discovery: if a real setuid broker is installed on this machine,
    # the plugin should find it; otherwise it must raise the explanatory error.
    installed = "/usr/local/bin/ctxredact"
    if os.path.exists(installed):
        st = os.stat(installed)
        if stat.S_ISREG(st.st_mode) and st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
            check("auto-discovery finds installed broker", tools._binary() == installed)
    else:
        # CI: no broker installed; auto-discovery must raise the explanatory error
        try:
            tools._binary()
            check("auto-discovery raises when absent", False, "no exception")
        except ValueError as e:
            check("auto-discovery raises when absent", "not found" in str(e), str(e))
            # the message must carry a copy-pasteable root bootstrap one-liner
            check("broker-missing offers curl|sudo bash bootstrap",
                  "curl -fsSL" in str(e) and "| sudo bash" in str(e), str(e))
            check("auto-discovery names CTXREDACT_BIN fallback",
                  "CTXREDACT_BIN" in str(e), str(e))

    # Deterministic bootstrap-message check: force discovery to fail no matter
    # what is on this host, and assert the copy-pasteable root one-liner.
    print("== broker-missing bootstrap message (forced) ==")
    _saved_candidates = tools._CANDIDATE_BINS
    _saved_which = tools.shutil.which
    try:
        tools._CANDIDATE_BINS = ()
        tools.shutil.which = lambda *a, **k: None
        try:
            tools._binary()
            check("forced-missing raises", False, "no exception")
        except ValueError as e:
            msg = str(e)
            check("forced-missing names the broker", "broker not found" in msg, msg)
            check("bootstrap offers curl|sudo bash", "curl -fsSL" in msg and "| sudo bash" in msg, msg)
            check("bootstrap names restart", "restart Hermes" in msg, msg)
            check("bootstrap names CTXREDACT_BIN fallback", "CTXREDACT_BIN" in msg, msg)
    finally:
        tools._CANDIDATE_BINS = _saved_candidates
        tools.shutil.which = _saved_which

    print(f"\nPASS={PASS} FAIL={FAIL}")
    subprocess.run(["rm", "-rf", work])
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
