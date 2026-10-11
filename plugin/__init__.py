"""ctxredact Hermes plugin: single file, zero dependencies.

Registers three tools that let an agent USE secrets without ever SEEING them:

    run_with_secrets(command, keys)  run a shell command with vault secrets
    check_secret(name)               is a vault key set?
    list_secrets()                   vault key names only

The handler never holds a secret value: the setuid-root ctxredact broker
injects values into the child process environment and scrubs every occurrence
from its output (replaced with [REDACTED:KEY] markers). Redaction is
mandatory; there is no opt-out parameter, so no prompt-injected or confused
call can switch scrubbing off.

Security properties:
  * minimal child env (PATH/HOME/LANG/TERM/TMPDIR/SHELL/USER + LC_*): ambient
    gateway secrets (LLM provider keys, tokens) are NOT inherited, so an
    environment-dumping command cannot leak them
  * broker stderr is allowlisted line-by-line before entering context
  * the broker binary is validated (regular file, root-owned, setuid-root)
  * timeout kills the broker's whole process group (no orphans)

Broker discovery: first valid candidate wins (zero config):
  1. $CTXREDACT_BIN (explicit; must validate or it is a hard error)
  2. /usr/local/bin/ctxredact               (install.sh default)
  3. /etc/ctxredact/bin/ctxredact
  4. /usr/bin/ctxredact
  5. `ctxredact` on PATH

Install: `sudo ./install.sh` from the repo (builds the broker, seeds the vault,
installs + enables the plugin). From the Hermes plugin store, `hermes plugins
install ctxredact` drops in just the plugin (running as the user); the setuid
broker is installed separately via the bootstrap one-liner in the
broker-not-found message. Restart the gateway afterwards.
"""
import json
import logging
import os
import shutil
import signal
import stat
import subprocess

logger = logging.getLogger(__name__)

# The child gets a MINIMAL environment: the broker injects the requested vault
# secrets, and nothing else rides along. Ambient gateway variables (LLM provider
# keys, GITHUB_PAT, ...) are deliberately NOT inherited; a command that dumps
# its environment would otherwise leak every secret the gateway process holds,
# and --redact only scrubs vault-injected values. Commands that need other
# variables should set them inline: 'VAR=value cmd'.
_ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "TERM", "TMPDIR", "SHELL", "USER")

_CANDIDATE_BINS = (
    "/usr/local/bin/ctxredact",          # install.sh default
    "/etc/ctxredact/bin/ctxredact",
    "/usr/bin/ctxredact",
)

# One-line broker install. The setuid-root broker cannot be installed by
# `hermes plugins install` (that runs as the invoking user, not root), so when
# the broker is missing the plugin points at a bootstrap one-liner the user runs
# as root. Override with CTXREDACT_INSTALL_URL when your packaging URL differs.
_INSTALL_URL = os.environ.get(
    "CTXREDACT_INSTALL_URL",
    "https://raw.githubusercontent.com/vehemont/ctxredact/main/install.sh",
)


def _broker_missing(reason: str) -> str:
    """Build the broker-absent message with a copy-pasteable root install line."""
    return (
        f"ctxredact broker not found ({reason}).\n"
        "This plugin only exposes the tools; the setuid-root broker must be "
        "installed by root. Run:\n"
        f"    curl -fsSL {_INSTALL_URL} | sudo bash\n"
        "then restart Hermes. (Or set CTXREDACT_BIN to your broker path.)"
    )

DEFAULT_TIMEOUT = 120            # seconds; module-level so tests can shorten it


def _env_int(name: str, default: int) -> int:
    """Read a positive int from the environment; fall back to default.

    Used for operator-tunable constants (CTXREDACT_MAX_OUTPUT). Never a
    per-call parameter: an LLM must not be able to raise its own output
    viewport. Invalid values fall back to the default rather than breaking
    the plugin at import time.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return val if val > 0 else default


# Tool-result viewport cap. Deliberately NOT an LLM-settable parameter (same
# reasoning as removing the redact=false knob): a model must not be able to
# talk itself into a context bomb. Operators who genuinely need a larger
# viewport set CTXREDACT_MAX_OUTPUT in the gateway environment at deploy time.
MAX_OUTPUT_CHARS = _env_int("CTXREDACT_MAX_OUTPUT", 64_000)
TAIL_CHARS = 4_000               # on truncation, also keep this many chars from the end

# Broker stderr lines known to be safe: static text, key names, paths only.
# Never secret values. Anything unrecognized is filtered out before the stderr
# text is returned into the agent's context.
_SAFE_STDERR_PREFIXES = (
    "ctxredact:",
    "error: secret '",
    "error: missing '-- command args...' separator",
    "error: at least one secret NAME is required",
    "error: oom",
    "usage:",
)


def _validated(path: str) -> str:
    """Check one candidate path; raise ValueError with the reason if invalid."""
    try:
        st = os.stat(path)
    except OSError:
        raise ValueError(f"ctxredact binary not found at {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"ctxredact path {path} is not a regular file")
    if st.st_uid != 0:
        raise ValueError(f"ctxredact binary {path} is not owned by root")
    if not (st.st_mode & stat.S_ISUID):
        raise ValueError(f"ctxredact binary {path} is not setuid-root")
    return path


def _binary() -> str:
    """Resolve the broker: explicit CTXREDACT_BIN, then standard locations.

    An explicitly set CTXREDACT_BIN must validate, otherwise it is a hard
    error (explicit config should fail loudly, never silently fall through).
    """
    explicit = os.environ.get("CTXREDACT_BIN")
    if explicit:
        return _validated(explicit)
    candidates = list(_CANDIDATE_BINS)
    on_path = shutil.which("ctxredact")
    if on_path:
        candidates.append(on_path)
    for path in candidates:
        try:
            return _validated(path)
        except ValueError:
            continue
    raise ValueError(_broker_missing("looked for " + ", ".join(candidates)))


def _minimal_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k in _ENV_ALLOWLIST or k.startswith("LC_")}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    return env


def _kill_group(proc) -> None:
    """Kill the broker's whole process group (broker + command + children)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def _safe_stderr(text: str) -> str:
    """Allowlist broker stderr lines; drop anything unrecognized."""
    kept = []
    dropped = 0
    for line in text.splitlines():
        if any(line.startswith(p) for p in _SAFE_STDERR_PREFIXES):
            kept.append(line)
        else:
            dropped += 1
    if dropped:
        kept.append(f"[{dropped} unrecognized broker stderr line(s) filtered]")
    return "\n".join(kept)


def run_with_secrets(args, **kwargs) -> str:
    command = (args.get("command") or "").strip()
    keys = args.get("keys") or []
    source = (args.get("source") or "env").strip().lower()
    if not command:
        return json.dumps({"error": "no command supplied"})
    if not keys:
        return json.dumps({"error": "no keys supplied"})
    try:
        binary = _binary()
    except ValueError as exc:
        return json.dumps({"error": str(exc)})

    # Redaction is mandatory; there is deliberately no opt-out parameter.
    argv = [binary, "--redact"]
    if source == "bitwarden":
        # Broker fetches the named secrets from Bitwarden Secrets Manager itself
        # (so --redact can scrub their values from output). Requires the vault to
        # hold BITWARDEN_TOKEN + BITWARDEN_PROJECT_ID.
        argv.append("--bitwarden")
    argv += [str(k) for k in keys] + ["--", "sh", "-c", command]
    # Minimal env (see _minimal_env): ambient gateway secrets are not inherited
    # by the child, so an environment-dumping command cannot leak them. The
    # broker adds the requested vault secrets on top of this.
    env = _minimal_env()
    if source == "bitwarden":
        # Tell the broker where bws lives; fall back to its PATH lookup.
        bws = os.environ.get("CTXREDACT_BWS") or shutil.which("bws") or ""
        if bws:
            env["CTXREDACT_BWS"] = bws
    # start_new_session: the broker leads its own process group, so on
    # timeout we can kill the entire tree (broker + command + its children)
    # instead of leaving orphans running after the tool call was declared dead.
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, errors="replace", env=env,
                                start_new_session=True)
    except Exception as exc:
        return json.dumps({"error": f"ctxredact failed to start: {exc}"})
    try:
        stdout, stderr = proc.communicate(timeout=DEFAULT_TIMEOUT)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        return json.dumps({"error": "ctxredact command timed out"})
    except Exception as exc:  # decode/pipe errors mid-stream: kill and report
        _kill_group(proc)
        return json.dumps({"error": f"ctxredact failed: {exc}"})

    # stdout is redacted by the broker; stderr is allowlisted here. Both are
    # capped so a child that dumps megabytes can't blow up the conversation
    # context (the broker caps at 32 MiB; that's still far too much for a
    # tool result). On truncation keep BOTH ends: the head usually carries
    # structure (headers, column layout) and the tail carries the outcome
    # (final status, error, exit summary): a head-only cap would hide the
    # most informative part of long output. The omission marker tells the
    # model exactly how much it is missing and that re-running with a
    # filter (grep/tail/jq) or a file redirect will recover the rest.
    def _cap(s: str) -> str:
        n = len(s)
        if n <= MAX_OUTPUT_CHARS:
            return s
        # tail share shrinks proportionally so head is never negative; a cap
        # smaller than TAIL_CHARS must still be honored (caught live: cap=300
        # with tail=4000 produced a "truncated" result LONGER than the cap)
        tail = min(TAIL_CHARS, MAX_OUTPUT_CHARS // 4)
        head = MAX_OUTPUT_CHARS - tail
        omitted = n - MAX_OUTPUT_CHARS
        return (s[:head]
                + f"\n[... {omitted:,} characters omitted ...]\n"
                + s[n - tail:]
                + f"\n[output truncated: kept first {head:,} + last {tail:,} "
                  f"of {n:,} characters - re-run with grep/tail or redirect to a file "
                  f"to see the rest]")
    return json.dumps({
        "exit_code": proc.returncode,
        "output": _cap(stdout),
        "stderr": _cap(_safe_stderr(stderr)),
        "truncated": len(stdout) > MAX_OUTPUT_CHARS or len(stderr) > MAX_OUTPUT_CHARS,
        "output_chars": len(stdout),
        "stderr_chars": len(stderr),
    })


def check_secret(args, **kwargs) -> str:
    name = (args.get("name") or "").strip()
    if not name:
        return json.dumps({"error": "no name supplied"})
    try:
        binary = _binary()
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    try:
        proc = subprocess.run([binary, "--check", name], capture_output=True, text=True, timeout=30)
        return json.dumps({"name": name, "set": proc.returncode == 0})
    except Exception as exc:
        return json.dumps({"error": f"ctxredact check failed: {exc}"})


def list_secrets(args, **kwargs) -> str:
    try:
        binary = _binary()
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    try:
        # `--purposes` gives NAME\tpurpose per secret (no values, no lengths),
        # so the model can pick the right credential by what it's FOR.
        proc = subprocess.run([binary, "--purposes"], capture_output=True, text=True, timeout=30)
        pairs = []
        for ln in proc.stdout.splitlines():
            if "\t" in ln:
                name, _, purpose = ln.partition("\t")
                pairs.append((name.strip(), purpose.strip()))
        keys = [n for n, _ in pairs]
        purposes = {n: p for n, p in pairs if p}
        return json.dumps({"count": len(keys), "keys": keys, "purposes": purposes,
                           "set": proc.returncode == 0})
    except Exception as exc:
        return json.dumps({"error": f"ctxredact list failed: {exc}"})


# ---------------------------------------------------------------------------
# Tool schemas: what the LLM reads to decide when/how to call the tools.
# ---------------------------------------------------------------------------

RUN_WITH_SECRETS = {
    "name": "run_with_secrets",
    "description": (
        "Run a shell command with the named secrets injected into its environment, "
        "resolved from the local ctxredact vault. The secret values NEVER appear in "
        "the arguments or the returned output: reference secrets as ${KEY} in the "
        "command. Any occurrence of a secret in the output is replaced with a "
        "[REDACTED:KEY] marker (labeled with the key name). Redaction is always on "
        "and cannot be disabled. Multi-step guidance: if a LATER step needs the "
        "secret, call run_with_secrets again for that step. Never pass a "
        "[REDACTED:KEY] marker onward as if it were the real value, and prefer "
        "commands that report success/length/status rather than echoing secrets. "
        "Pass ONLY the keys you actually need."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": (
                    "Shell command to run, referencing secrets as ${KEY} "
                    "(e.g. 'curl -H \"Authorization: Bearer $API_TOKEN\" "
                    "https://api.example.com/status'). Runs via sh -c."
                ),
            },
            "keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Vault key names to inject, e.g. ['MONITORING_TOKEN'].",
            },
            "source": {
                "type": "string",
                "enum": ["env", "bitwarden"],
                "default": "env",
                "description": (
                    "'env' (default) reads keys from the local vault file. "
                    "'bitwarden' fetches them on demand from the Bitwarden Secrets "
                    "Manager project named by BITWARDEN_PROJECT_ID, authenticated by "
                    "the BITWARDEN_TOKEN vault entry. Bitwarden values are fetched by "
                    "the broker itself so they are redacted just like local ones. "
                    "Use 'bitwarden' when the secret should not live on this machine."
                ),
            },
        },
        "required": ["command", "keys"],
    },
}

CHECK_SECRET = {
    "name": "check_secret",
    "description": (
        "Check whether a named vault secret is set and non-empty. Returns set=true/false. "
        "Never returns the value. Use to test a key exists before a run_with_secrets call."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Vault key name, e.g. 'MONITORING_TOKEN'."},
        },
        "required": ["name"],
    },
}

LIST_SECRETS = {
    "name": "list_secrets",
    "description": (
        "List the names of all secrets in the vault (never the values). Each entry "
        "carries a short 'purpose' describing what the credential is FOR, when one "
        "has been declared in the vault (as a '# comment' line above the key). Use "
        "the purpose to pick the right key rather than guessing."
    ),
    "parameters": {"type": "object", "properties": {}},
}


def register(ctx):
    """Wire schemas to handlers and register the ctxredact toolset."""
    ctx.register_tool(
        name=RUN_WITH_SECRETS["name"],
        toolset="ctxredact",
        schema=RUN_WITH_SECRETS,
        handler=run_with_secrets,
    )
    ctx.register_tool(
        name=CHECK_SECRET["name"],
        toolset="ctxredact",
        schema=CHECK_SECRET,
        handler=check_secret,
    )
    ctx.register_tool(
        name=LIST_SECRETS["name"],
        toolset="ctxredact",
        schema=LIST_SECRETS,
        handler=list_secrets,
    )
    logger.info("ctxredact plugin registered 3 tools")
