# Security policy for ctxredact

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report privately by email to the repository owner (see the GitHub profile of the
repo owner for a contact address). Include:

- what you found and how to reproduce it (a minimal PoC is ideal),
- the affected version or commit,
- your assessment of impact.

We aim to acknowledge reports within **3 business days** and to ship a fix or a
clear mitigation plan within **14 days**. Coordinated disclosure credit is given
unless you prefer to stay anonymous.

## Threat model (what this project does and does NOT protect against)

ctxredact is a capability broker. Its goal is narrow and specific: **keep secret
values out of an LLM agent's context and out of transcripts/logs during ordinary,
accidental operation.** It does not stop a hostile process from using a value it
was given.

**Protected (by design):**

- The vault file is `root:root 0600`; the agent cannot read it directly.
- The broker drops to the invoker's uid before exec; the child cannot read the
  vault either (fail-closed: if the drop fails, nothing is exec'd).
- `--redact` scrubs any byte-exact occurrence of an injected secret from the
  child's merged stdout/stderr, fail-closed on allocation errors.
- The `CTXREDACT_SECRETS` path override is ignored in setuid mode.
- The broker refuses to run for real uid 0 (no root-shell abuse).
- Hermes plugin handlers: redaction is mandatory (no opt-out parameter),
  broker stderr is allowlisted, and the broker binary is validated (regular
  file, root-owned, setuid) before use.

**NOT protected (inherent to granting arbitrary execution with a secret):**

- A child can exfiltrate via base64/hex/URL encoding or any transformation.
  Exact-match redaction cannot recognize re-encoded values.
- A child can write the secret to a file, network socket, or other IPC channel
  and read it back outside the broker's output filter.
- Length and timing side-channels are not eliminated.
- `[REDACTED:KEY]` markers can be spoofed by a child (deception, not leakage).

If your threat model includes a hostile principal running arbitrary code, you
need a sandbox around the child (e.g. bubblewrap/firejail, network egress
control, allowlisted commands). ctxredact is one layer of that stack, and it
does not substitute for the rest.

## Security-relevant design decisions

- **Fail-closed privilege drop**: `setgroups`/`setgid`/`setuid` return values
  are checked; failure aborts before the child runs (setuid mode only; in dev
  builds `setgroups` legitimately fails without CAP_SETGID).
- **Fail-closed redaction**: if the scrub buffer cannot be allocated, output is
  replaced with `[redaction error]`. Unredacted output is never forwarded.
- **Compiled-in vault path** in setuid mode; the env override exists only for
  non-setuid dev/test builds.
- **No value disclosure in metadata modes**: `--names`, `--describe`,
  `--purposes`, `--check` emit names/status/length/purpose only. Length is
  acknowledged as a minor fingerprinting side-channel.
- **Install hygiene**: install root and binary directory are root-owned 0755
  (an unprivileged user cannot swap the setuid binary), binary is 4755,
  hardened compile flags (PIE, full RELRO/BIND_NOW, stack protector,
  `_FORTIFY_SOURCE=2`, NX).

## Known residual findings

Documented in `README.md` under "Security model and limits" and in the bundled
skill: transform escapes, write-then-read-back, and marker spoofing. These are
fundamental to arbitrary-exec plus exact-match redaction, not implementation
bugs.

## Review checklist before you deploy

This is a setuid-root binary. Before trusting it on a real system:

1. Read `src/ctxredact.c` end-to-end (~370 lines, stdlib only).
2. Build it yourself from source (`install.sh` compiles on your machine; there
   is no distributed binary).
3. Run `tests/test_ctxredact.sh` as a non-root user with
   `CTXREDACT_PWD_BIN` pointing at a scratch setuid build.
4. Confirm the vault is `root:root 0600` and the install root is root-owned.
5. Only put secrets in the vault that you are comfortable granting to the
   invoking user as an environment capability.
