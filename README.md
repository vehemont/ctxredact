# ctxredact

A small **setuid-root secret broker**. It lets an unprivileged agent *use* a
secret without ever *seeing* it. This is useful when a process needs credentials
to run commands, and you want the values to stay out of transcripts, logs, and
LLM context.

> **Security-critical software.** This installs a setuid-root binary. Read
> [`SECURITY.md`](SECURITY.md) first: the threat model, the review checklist,
> and how to report vulnerabilities. Build from source yourself; there is no
> distributed binary.

```
ctxredact API_TOKEN -- curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/...
ctxredact DB_USER DB_PASSWORD -- python3 report.py           # reads os.environ
ctxredact --bitwarden API_TOKEN -- curl -H "X-Key: $API_TOKEN" https://api...   # fetch from Bitwarden
ctxredact --names          # list keys (no values)
ctxredact --describe       # key / SET-UNSET / length / purpose (no values)
ctxredact --purposes       # name + purpose per key (no values, no lengths)
ctxredact --check NAME     # exit 0 if set, 1 if not
```

## How it works

1. The vault (`vault.env`, `KEY=value` lines) is owned `root:root`, mode **0600**,
   so the agent user cannot read it.
2. `ctxredact` is **setuid-root** (4755). When the agent runs it, the effective
   uid is root, so it can read the vault.
3. It injects the requested secret(s) into the child process's **environment**,
   then **drops privileges** (`setgroups(0)`, `setgid(real)`, `setuid(real)`)
   **before** `exec`.
4. The child runs as the ordinary agent. It cannot read the vault, and it only
   sees the one env var it was given. The broker returns only the child's stdout.

Because the value lives only inside the child process environment, and never on
the broker's stdout, the secret never enters the caller's context.

## Build hardening

The setuid binary is built with **PIE**, **full RELRO** (`-z relro -z now`),
**stack protector** (`-fstack-protector-strong`), **`_FORTIFY_SOURCE=2`**, and an
**NX stack**. These are the standard protections for a setuid-root binary.

## Install (one command, as root)

```bash
sudo ./install.sh
```

That installs everything in one pass: the hardened setuid-root broker to
`/usr/local/bin/ctxredact`, seeds the vault at `/etc/ctxredact/vault.env`
(root:root 0600), copies the Hermes plugin into the invoking user's
`~/.hermes/plugins/ctxredact/`, **enables it**, and bootstraps `bws` (for the
optional Bitwarden source). Then:

1. Put real secrets in `/etc/ctxredact/vault.env` (as root), `KEY=value` lines.
   (or, for the Bitwarden source, fill `BITWARDEN_TOKEN` + `BITWARDEN_PROJECT_ID`)
2. Restart the Hermes gateway. The agent gets `run_with_secrets`, `check_secret`,
   and `list_secrets` with **zero configuration**: the plugin auto-discovers the
   broker, and the only real config is the vault (or Bitwarden).

Options: `--prefix DIR` for a scratch install (tests/CI), `--no-plugin` for
broker-only, `--no-bws` to skip the Bitwarden CLI download.

`install.sh` enforces `root:root 0755` on the install and bin directories (so the
runtime user cannot swap the setuid binary), `root:root 0600` on the vault, and
`4755 setuid-root` on the binary.

## Purpose field (optional but recommended)

Add a `# comment` line immediately above a key in the vault to describe what that
credential is for:

```
# Token for the monitoring API
MONITORING_TOKEN=your-token-here
```

The purpose appears in `--describe`, `--purposes`, and in the agent's
`list_secrets` output, so the model can pick the right key by meaning instead of
guessing from the name. Rules:

- Put the comment **directly above** the key. A blank line detaches it.
- Keep it **non-secret**. It is visible to the agent and to the model it calls,
  so describe the purpose only. Never put a value, a partial value, or a hint at
  a value there.
- Put `#` at the start of the line (column 0). An indented `#` is not treated as
  a comment.

## Bitwarden Secrets Manager source (optional)

If you do not want secrets on the device at all, the `--bitwarden` source pulls
them on demand from a [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) project instead of the local vault file:

```
ctxredact --bitwarden DB_PASS -- python3 report.py   # DB_PASS fetched from Bitwarden
```

The broker resolves the secret **itself** and passes it to the child's
environment, so (with `--redact`) the value is scrubbed from output exactly like
a local one. The value never touches a file on disk, and only the secrets you
name are injected into the child's environment, which keeps the blast radius to
that set of credentials.

### Multiple secrets in one call

`--bitwarden` takes any number of names, so a script that needs several is a
single invocation and a single Bitwarden round-trip:

```
ctxredact --bitwarden --redact DB_PASS API_TOKEN SMTP_PASS -- ./etl.sh
```

Inside `etl.sh`, read them all as environment variables (`$DB_PASS`,
`$API_TOKEN`, `$SMTP_PASS`). Behind the scenes the broker calls `bws secret
list <PROJECT_ID> -o env` once (not once per name), extracts just the names you
asked for, injects each as its own env var, and registers every fetched value
for redaction. Only the named secrets land in the child's environment; the rest
of the project is not injected.

One thing to keep in mind: `bws secret list` returns the **whole project**, so
even though only the named secrets are injected, every value in the project
briefly passes through the broker's pipe buffer. If a project holds many
secrets that are rarely used together, split groups that are always used
together into their own project (and machine account), so a project only ever
holds what one script needs.

Setup on the Bitwarden side (the free tier is enough: up to 2 users, 3 projects, 3
machine accounts):

1. Create a **project** (e.g. `ctxredact`) in Secrets Manager.
2. Add your secrets. The secret **key** is what you pass to `ctxredact` (use
   POSIX-friendly names: letters, digits, underscore; not starting with a digit).
3. Create a **machine account**, and on its **Projects** tab grant **Can read**
   on that project.
4. On its **Access tokens** tab, generate an **access token** (starts with `0.`).
   Copy it, it is shown only once.
5. Put the token and the project id in the local vault (the token is a secret,
   so it belongs in the root-only vault; the project id is a UUID, safe to store
   there too):

```
BITWARDEN_TOKEN=0.<the access token>
BITWARDEN_PROJECT_ID=<the project UUID>
```

To use it you also need the official `bws` CLI on the machine (the broker shells
out to it): install it via [Bitwarden's SDK releases](https://github.com/bitwarden/sdk-sm/releases),
or point `ctxredact` at it with `CTXREDACT_BWS=/path/to/bws`. The broker runs
`bws` under a dedicated unprivileged `ctxredact` user and refuses to start it if
the binary is not root-owned, so install it where a non-root user cannot replace
it (install.sh does this for you at `/usr/local/bin/bws`).

Security notes:

- The access token is the credential: anyone with it can read every secret the
  machine account can access. Treat it like a high-value bearer token and store
  it in the root-only vault, not in the model's context.
- Granting a project to a machine account is the blast-radius control: a
  compromised token exposes only that project, never your whole vault.
- Because the broker fetches the value, `--redact` covers it. A value fetched
  only *inside* the child process would be invisible to redaction. As with the
  local vault source, redaction is plain-text only and does not follow values
  through base64/hex/URI encoding.

## Build (dev, non-setuid)

```bash
make        # produces a non-setuid binary for local testing
```

The dev binary lands at `/tmp/ctxredact-dev/bin/ctxredact`, with the vault path
compiled in as `/tmp/ctxredact-dev/vault.env`. Override with `PREFIX=...`.

## Test

```bash
./tests/test_ctxredact.sh                       # functional tests (no root)
# Privilege-drop tests need a setuid build + a non-root invoker:
sudo install.sh --prefix /tmp/cwtest
CTXREDACT_PWD_BIN=/tmp/cwtest/bin/ctxredact \
CTXREDACT_TEST_VAULT=/tmp/cwtest/vault.env \
su - "$USER" -c './tests/test_ctxredact.sh'     # run as NON-root
```

## Security model and limits

The broker keeps secret values out of the caller's context. It is a capability
broker: it hands a value to a process that asks for it. It does not prevent a
hostile command from using a value it was given.

- The child runs as the caller, so any command can print its own environment
  (`ctxredact NAME -- sh -c 'echo "$NAME"'`). The `looks_like_leak()` filter is
  advisory, meant as a convenience tripwire. Treat it that way; do not rely on it
  as protection.
- The two things the broker actually guarantees are: (a) secrets stay out of the
  caller's context and transcripts, and (b) the privilege drop stops the child
  from reading the vault file. A hostile principal that already has arbitrary
  command execution as the same user is outside this protection.
- A compromise of this binary is a **root compromise**. It is deliberately tiny
  and drops privilege before running the child, but any setuid-root code is
  within the blast radius if exploited.
- **Redaction scope is plain-text only.** `--redact` scrubs exact, literal
  matches of a secret value. It does **not** follow a value through base64,
  hex, or URI encoding, so a command that encodes a value before emitting it
  (for example `echo "$NAME" | base64`) still leaks it. This is an explicit
  scope decision: the broker is a capability broker, not a confidentiality
  firewall, and a hostile command can always transform a value it was given.

### Hardening measures

- **Fail-closed privilege drop.** `setgroups`/`setgid`/`setuid` returns are
  checked. If the drop fails, the broker aborts rather than exec a privileged
  child.
- **No env-trust for the vault path.** The caller-supplied `CTXREDACT_SECRETS`
  override is honored only in non-setuid (dev/test) builds. A setuid-root build
  always uses the compiled-in path.
- **Root-owned install root.** The setuid binary cannot be swapped by the runtime
  user.
- **Full ELF hardening.** PIE + full RELRO + stack protector + `_FORTIFY_SOURCE`.
- **Bitwarden fetch runs untrusted-principal-safe.** The `bws` client used by the
  `--bitwarden` source must be a root-owned, non-agent-writable binary, and it
  runs under a dedicated unprivileged `ctxredact` uid (never the caller's uid).
  This keeps the Bitwarden access token out of any process the invoking user
  can substitute or read, so a substituted `bws` or a `/proc` environment read
  cannot exfiltrate the token. If `bws` is missing, agent-writable, or the
  dedicated uid is unavailable, the broker refuses the Bitwarden source
  (fail-closed) rather than running unsafely.

## Hermes Agent integration (built-in plugin)

A native Hermes plugin makes the broker a first-class toolset the agent calls
directly. There is no manual `ctxredact ... -- ...` in the terminal. It is
installed and **auto-enabled** by `install.sh` into `~/.hermes/plugins/ctxredact/`
(a single `__init__.py` + `plugin.yaml`; `install.sh` runs
`hermes plugins enable ctxredact`, then restart the gateway to load it).
Tested against Hermes Agent v0.21.6. It registers:

- `run_with_secrets(command, keys, source='env')`: run an arbitrary shell
  `command` with the named secrets injected (referenced as `${KEY}`) and the
  output always scrubbed of any secret value (marked `[REDACTED:KEY]`). There is
  no opt-out for redaction, so a prompt-injected call cannot switch scrubbing
  off. Set `source='bitwarden'` to fetch the keys on demand from Bitwarden
  Secrets Manager. Returns `{exit_code, output, stderr, truncated, output_chars,
  stderr_chars}`; broker stderr is allowlisted line-by-line.
- `check_secret(name)`: is the key set and non-empty?
- `list_secrets()`: key names plus an optional short purpose per key. The purpose
  comes from a `# comment` line above the key, so the agent can pick the right
  credential by what it is for rather than by guessing from the name. Purposes
  are non-secret; never put a value or a hint at a value there.

The handler validates the broker binary before use (regular file, root-owned,
setuid-root) and rejects a misconfigured `CTXREDACT_BIN`.

Because the handler never holds a value and redaction is mandatory (always on,
fail-closed on allocation errors), credentials never reach the agent's context.
A bundled skill ([`skill/ctxredact-secrets`](skill/ctxredact-secrets/SKILL.md))
teaches the agent when and how to use the tools (reference succinctly, prefer
length/status checks over echoing the value).

### Examples

These show the actual context impact: the tool call the model makes (input)
and what comes back into the conversation (output). The vault here holds two
synthetic keys:

```
# Token for the monitoring API
MONITORING_TOKEN=mtr-secret-abcdef
# Home automation long-lived access token
HOME_AUTO_TOKEN=hauto-token-123456
```

**1. Choosing a key by purpose.** The model calls `list_secrets` and reads the
purpose to pick the right credential instead of guessing from the name.

```text
INPUT   tools.list_secrets()

OUTPUT  {"count": 2,
         "keys": ["MONITORING_TOKEN", "HOME_AUTO_TOKEN"],
         "purposes": {"MONITORING_TOKEN": "Token for the monitoring API",
                      "HOME_AUTO_TOKEN": "Home automation long-lived access token"},
         "set": true}
```

**2. Accidental echo is scrubbed.** If a command echoes a secret, the value never
appears. The tool swaps in a labeled marker so the model knows which key was
redacted.

```text
INPUT   {"command": "echo \"key=$MONITORING_TOKEN\"",
         "keys": ["MONITORING_TOKEN"]}

OUTPUT  {"exit_code": 0,
         "output": "key=[REDACTED:MONITORING_TOKEN]\n",
         "truncated": false,
         "output_chars": 32,
         "stderr_chars": 68}
```

The marker is `[REDACTED:MONITORING_TOKEN]`, not a bare `[REDACTED]`. The model
can tell which secret was swapped and knows to call `run_with_secrets` again for
any later step that needs it.

**3. Preferred pattern: report a property, not the value.** Asking the command to
return the length or status instead of echoing keeps the value out of the
conversation altogether.

```text
INPUT   {"command": "test -n \"$HOME_AUTO_TOKEN\" && echo \"set name=HOME_AUTO_TOKEN len=${#HOME_AUTO_TOKEN}\"",
         "keys": ["HOME_AUTO_TOKEN"]}

OUTPUT  {"exit_code": 0,
         "output": "set name=HOME_AUTO_TOKEN len=18\n",
         "truncated": false,
         "output_chars": 32,
         "stderr_chars": 68}
```

**4. Oversized output is capped, and the model is told it is incomplete.** The
tool keeps the head and the tail (where an error or final status usually is),
reports the true size, and flags `truncated: true`.

```text
INPUT   {"command": "seq 1 2000 | tr \"\\n\" \" \"; echo; echo FINAL_LINE_MARKER",
         "keys": ["MONITORING_TOKEN"]}

OUTPUT  {"exit_code": 0,
         "output": "1 2 3 4 5 6 ... 1999 2000 \nFINAL_LINE_MARKER\n\n[output truncated: kept first 300 + last 100 of 8,912 characters - re-run with grep/tail or redirect to a file to see the rest]",
         "truncated": true,
         "output_chars": 8912,
         "stderr_chars": 68}
```

The model knows exactly how much was dropped (8,512 characters) and that the
final marker (`FINAL_LINE_MARKER`) survived in the tail, so it can re-run with
`grep`/`tail` to see any part it actually needs. The `- re-run with grep/tail`
hint is part of what the model reads, not a command you issue.

### Tool output and truncation

Tool results are capped at 64k characters so a chatty child cannot flood the
conversation context. The cap shapes only what the model sees in the tool result;
the command itself runs to completion with full output wherever you redirect it
(CLI use has no cap at all). On truncation the result keeps the head and the tail
(the tail is usually where the outcome or error lives), reports true total sizes,
and flags `truncated: true` so the model knows to re-run with `grep`/`tail` or a
file redirect. Operators who need a larger viewport can raise it with the
`CTXREDACT_MAX_OUTPUT` environment variable (characters, read at plugin load). It
is not a per-call parameter, so the model cannot raise its own limit.

### Multi-step use

If a later step needs a secret, call `run_with_secrets` again for that step. Never
pass a `[REDACTED:KEY]` marker onward as if it were the real value. The marker is
self-labeled so the model understands the swap.

## License

MIT. See [LICENSE](LICENSE).
