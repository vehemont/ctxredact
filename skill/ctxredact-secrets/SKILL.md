---
name: ctxredact-secrets
description: Use secrets safely via the ctxredact Hermes plugin (run_with_secrets / check_secret / list_secrets) so credentials never enter the agent's context.
category: security
---

# ctxredact secrets plugin

When a command needs a credential (SSH, curl basic/bearer auth, API calls, DB
queries), do **not** paste a raw secret, and do **not** run the broker directly
in the terminal. Use the plugin tools. The values live in a root-only vault; the
broker injects them into the child process and scrubs them from output, so they
never appear in the conversation.

## Tools

- `run_with_secrets(command, keys, source='env')`: run a shell command with the
  named secrets injected. Reference them as `${KEY}`. Redaction is always on and
  cannot be disabled. Any occurrence of a secret value in the output is replaced
  with a `[REDACTED:KEY]` marker. Returns `{exit_code, output, stderr}`.
  Set `source='bitwarden'` to fetch the keys on demand from Bitwarden Secrets
  Manager (the broker pulls them itself so they are still redacted). Use the
  Bitwarden source when a secret must not live on this machine.
- `check_secret(name)`: returns `{set: bool}` (never the value).
- `list_secrets()`: returns key names plus an optional purpose per key. Use the
  purpose to pick the right credential.

## Usage rules (important)

1. **Only pass the keys you actually need.** A secret is injected only if its
   name is in `keys`.
2. **Reference secrets as `${KEY}`** in `command`. For example:
   `run_with_secrets(command: 'curl -H "Authorization: Bearer ${API_TOKEN}" https://api.example.com/status', keys: ['MONITORING_TOKEN'])`.
3. **Prefer reporting length or status over echoing the value.** For example, use
   `echo len=${#MONITORING_TOKEN}` to confirm a secret is non-empty. Redaction
   removes the value from output anyway, so do not build logic on echoing it.
4. If a command must send the secret somewhere (auth header, SSH password
   prompt), that is fine. The value stays inside the child process. The broker
   only scrubs output, not the command's own behavior.
5. **`[REDACTED:KEY]` is a marker, not data.** If output shows
   `[REDACTED:MONITORING_TOKEN]`, the broker swapped the real value out. Never
   pass the marker string onward as if it were the credential. If a later step
   needs the same secret, call `run_with_secrets` again for that step. Chain
   steps inside one command when possible rather than piping values between
   turns.

## Example

```text
# curl with bearer token; token never enters context
run_with_secrets(
  command: 'curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${API_TOKEN}" https://api.example.com/status',
  keys: ['MONITORING_TOKEN']
)
# -> {"exit_code":0,"output":"200",...}

# check a secret exists before using it
check_secret(name: 'MONITORING_TOKEN')           # -> {"name":"MONITORING_TOKEN","set":true}

# discovery, with a purpose to guide key choice
list_secrets()                                # -> {"count":N,"keys":[...],"purposes":{...}}
```

## Fallback

If the plugin tools are not loaded yet, you can still use the broker directly.
Use the installed binary (usually `/usr/local/bin/ctxredact`, or wherever
`install.sh` placed it):

```bash
ctxredact --redact API_TOKEN -- sh -c 'some-command'
```

The plugin is the preferred path once a gateway restart has loaded it.
