/*
 * ctxredact: secret broker (setuid-root model).
 *
 * PURPOSE
 *   Grant an unprivileged principal a CAPABILITY ("run this command with SECRET
 *   in its environment") without ever exposing the secret value to the
 *   caller's stdout, so the value never enters an LLM context or a transcript.
 *
 * SECURITY MODEL (installed via install.sh)
 *   - The vault is root:root, mode 0600. The agent user cannot read it.
 *   - This binary is setuid-root (mode 4755). When the agent execs it:
 *       real uid  = agent (e.g. 10000), effective uid = root.
 *     Root lets it read the vault and then reliably drop privileges.
 *   - Before exec'ing the child it calls setgroups(0), setgid(real_gid),
 *     setuid(real_uid) and CHECKS EVERY RETURN. If any drop syscall fails it
 *     aborts with a fatal error: the child is NEVER exec'd while privileged
 *     (fail-closed, not fail-open). The child runs as the ordinary agent and
 *     cannot read the vault; it only inherits the requested env var(s).
 *   - The vault path is NOT taken from the environment in setuid mode. The
 *     caller-supplied CTXREDACT_SECRETS override is honored ONLY when the
 *     binary is NOT setuid-root (dev/test builds), so a hostile caller cannot
 *     redirect a setuid-root file read to an arbitrary path.
 *
 * --redact
 *   When supplied, the broker ALSO scrubs the child's output. Because the
 *   broker holds the injected values in memory, it replaces any exact
 *   occurrence of a secret in the child's (merged) stdout/stderr with
 *   "[REDACTED:NAME]" (labeled with the key name so the caller understands
 *   the swap instead of treating the marker as literal data) before returning
 *   it. Redaction FAILS CLOSED: if the scrub buffer cannot be allocated the
 *   output is replaced with "[redaction error]"; unredacted output is never
 *   forwarded. This neutralizes obvious leaks (`sh -c 'echo "$NAME"'`) at the
 *   output layer, not just at the command layer. It is still NOT a
 *   confidentiality firewall against a hostile principal with arbitrary
 *   command execution (the child can exfiltrate via steganography, base64,
 *   length-only side-channels, file writes, etc.): it closes the naive-echo
 *   gap, which is where accidental leaks happen.
 *
 * USAGE
 *   ctxredact [--redact] NAME [NAME2 ...] -- command args...
 *   ctxredact --names | --describe | --check NAME | --help
 *
 * SAFETY
 *   - Refuses to run if the REAL uid is 0, so it can't be used as a root shell.
 *   - Entails setuid-root: a compromise of this binary is a root compromise.
 *     It is deliberately tiny and drops privilege before running the child.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef SECRETS_PATH
#define SECRETS_PATH "/etc/ctxredact/vault.env"
#endif

static const char REDACT_PREFIX[] = "[REDACTED:";
static const char REDACT_SUFFIX[] = "]";
static const char REDACT_ERROR[] = "[redaction error]";

static char *secret_value(const char *path, const char *name) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *line = NULL; size_t cap = 0; ssize_t n;
    size_t nlen = strlen(name);
    char *found = NULL;
    while ((n = getline(&line, &cap, f)) != -1) {
        if (n && line[n-1] == '\n') line[n-1] = '\0';
        if (n > 1 && line[n-2] == '\r') line[n-2] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        if (strncmp(line, name, nlen) == 0 && line[nlen] == '=') {
            found = strdup(line + nlen + 1);
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

/* ADVISORY filter, NOT a security boundary; see the honest-limit note above. */
static int looks_like_leak(const char *cmdline, const char *secrets_path) {
    const char *sigs[] = {
        "printenv", " env", "env ", "env|",
        "getenv", "os.environ", "os.getenv", "environ",
        "/proc/", NULL
    };
    for (int i = 0; sigs[i]; i++)
        if (strstr(cmdline, sigs[i])) return 1;
    if (strstr(cmdline, secrets_path)) return 1;
    return 0;
}

static char *read_all_fd(int fd);   /* defined below; used by run_capture2 */

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [--redact] NAME [NAME2 ...] -- command args...\n"
        "       %s --bitwarden [--redact] NAME [NAME2 ...] -- command args...\n"
        "       %s --names\n"
        "       %s --purposes\n"
        "       %s --describe\n"
        "       %s --check NAME\n"
        "       %s --help\n"
        "\n"
        "Inject the named secret(s) from the vault into the child command's\n"
        "environment, then run it as the CURRENT user (never as root).\n"
        "With --redact, the child's stdout/stderr is scrubbed of any exact\n"
        "occurrence of an injected value before it is returned.\n"
        "With --bitwarden, the named secret(s) are fetched on demand from the\n"
        "Bitwarden Secrets Manager project named by BITWARDEN_PROJECT_ID,\n"
        "authenticated by the BITWARDEN_TOKEN vault entry. The broker fetches\n"
        "them itself so --redact can scrub their values from output.\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

/* Drop to the invoker (real uid/gid). Fail-closed: abort on any error. */
static int drop_to_invoker(void) {
    gid_t rgid = getgid();
    uid_t ruid = getuid();
    if (setgroups(0, NULL) != 0 || setgid(rgid) != 0 || setuid(ruid) != 0) {
        fprintf(stderr, "ctxredact: FATAL: privilege drop failed\n");
        return -1;
    }
    return 0;
}

/*
 * Replace every occurrence of needle[0..nlen) in src[0..slen) with repl. Returns
 * a NUL-terminated malloc'd buffer, or NULL on allocation failure. The caller
 * MUST treat NULL as fatal (fail closed): forwarding unredacted output on OOM
 * would leak the secret. *outlen receives the result length.
 */
static char *replace_all(const char *src, size_t slen,
                         const char *needle, size_t nlen,
                         const char *repl, size_t rlen, size_t *outlen) {
    if (nlen == 0) {
        char *c = malloc(slen + 1);
        if (c) { memcpy(c, src, slen); c[slen] = '\0'; *outlen = slen; }
        else *outlen = 0;
        return c;
    }
    size_t count = 0;
    for (size_t i = 0; i + nlen <= slen; ) {
        if (memcmp(src + i, needle, nlen) == 0) { count++; i += nlen; }
        else i++;
    }
    char *out;
    if (rlen >= nlen) {
        out = malloc(slen + count * (rlen - nlen) + 1);
    } else {
        out = malloc(slen + 1); /* rlen < nlen => net shrink */
    }
    if (!out) {
        /* Fail closed: never forward unredacted output on OOM. */
        *outlen = 0;
        return NULL;
    }
    size_t o = 0;
    for (size_t i = 0; i < slen; ) {
        if (i + nlen <= slen && memcmp(src + i, needle, nlen) == 0) {
            memcpy(out + o, repl, rlen); o += rlen; i += nlen;
        } else {
            out[o++] = src[i++];
        }
    }
    out[o] = '\0';
    *outlen = o;
    return out;
}

/* Drop to an arbitrary unprivileged uid (and its real gid). Used for the bws
   child so the Bitwarden token is never visible to the invoking principal's
   uid, which could otherwise read it via /proc/<pid>/environ. Fail-closed. */
static int drop_to_uid(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    gid_t gid = pw ? pw->pw_gid : (gid_t)uid;
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
        fprintf(stderr, "ctxredact: FATAL: drop to uid %u failed\n", (unsigned)uid);
        return -1;
    }
    return 0;
}

/* Resolve the unprivileged uid the Bitwarden fetch should run as. Default is
   the dedicated system user 'ctxredact' (created by install.sh). An explicit
   CTXREDACT_BWS_UID override is honored for testing, but only a positive,
   non-root uid that is NOT the invoking user is accepted. Returns -1 (fail
   closed: use the dedicated user, never the invoker or root) on any problem. */
static int resolve_bws_uid(uid_t invoker) {
    const char *e = getenv("CTXREDACT_BWS_UID");
    if (e && *e) {
        char *end = NULL;
        long v = strtol(e, &end, 10);
        if (end != e && *end == '\0' && v > 0 && (uid_t)v != 0 && (uid_t)v != invoker)
            return (int)v;
        fprintf(stderr, "ctxredact: refusing invalid CTXREDACT_BWS_UID\n");
        return -1;
    }
    struct passwd *pw = getpwnam("ctxredact");
    if (pw && pw->pw_uid != 0 && pw->pw_uid != invoker) return (int)pw->pw_uid;
    fprintf(stderr,
        "ctxredact: no dedicated 'ctxredact' user for the Bitwarden fetch; "
        "run install.sh (it creates one) or set CTXREDACT_BWS_UID to an "
        "unprivileged uid that is not the current user\n");
    return -1;
}

/* Validate that the bws executable is secure to exec in the --bitwarden path:
   a regular file, owned by root, and NOT writable by group/other (so the
   invoking principal cannot substitute a fake bws that reads the token from
   its environment). Returns 0 on success, -1 with a message otherwise. */
static int validate_bws(const char *bws) {
    struct stat st;
    if (stat(bws, &st) != 0) { fprintf(stderr, "ctxredact: bws not found: %s\n", bws); return -1; }
    if (!S_ISREG(st.st_mode)) { fprintf(stderr, "ctxredact: bws not a regular file: %s\n", bws); return -1; }
    if (st.st_uid != 0) { fprintf(stderr, "ctxredact: bws is not root-owned; refusing (substitution risk): %s\n", bws); return -1; }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) { fprintf(stderr, "ctxredact: bws is group/other-writable; refusing: %s\n", bws); return -1; }
    return 0;
}

/* Capture a subprocess's stdout, optionally injecting one env var into it
   (used to hand the Bitwarden token to bws without it appearing in argv).
   When drop_uid is non-zero the child runs under that uid. Both stdout and
   stderr are captured (so a misbehaving bws cannot leak via the inherited
   stderr), and the caller receives stdout in *out and stderr in *err_out.
   Returns 0 on success (nothing to report on failure; children always exit). */
static int run_capture2(char **argv, const char *env_name, const char *env_val,
                        int drop_uid, char **out, char **err_out) {
    int po[2], pe[2];
    if (pipe(po) != 0 || pipe(pe) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(po[0]); close(po[1]); close(pe[0]); close(pe[1]); return -1; }
    if (pid == 0) {
        if (drop_uid > 0 && drop_to_uid((uid_t)drop_uid) != 0) _exit(127);
        if (env_name && env_val) setenv(env_name, env_val, 1);
        if (dup2(po[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(pe[1], STDERR_FILENO) < 0) _exit(127);
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(po[1]); close(pe[1]);
    *out = read_all_fd(po[0]); close(po[0]);
    *err_out = read_all_fd(pe[0]); close(pe[0]);
    waitpid(pid, NULL, 0);
    return 0;
}

static char *read_all_fd(int fd) {
    size_t cap = 64u * 1024u, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    ssize_t r;
    while ((r = read(fd, buf + len, cap - len - 1)) > 0) {
        len += (size_t)r;
        if (len >= cap - 1) {
            if (cap >= 32u * 1024u * 1024u) break;
            cap *= 2; char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; } buf = nb;
        }
    }
    if (len < cap) buf[len] = '\0'; else buf[cap-1] = '\0';
    return buf;
}

/* Fetch one or more secret values from Bitwarden Secrets Manager.
   token = machine-account access token; project_id = UUID of the project to
   pull from; for each name in names[i], set vals[i] = malloc'd value.
   Returns 0 on success, non-zero on failure. Values are resolved from a single
   `bws secret list <project_id> -o env` call, so redaction can cover every
   fetched value (a value fetched only inside the child would be unredactable).
   bws is located via CTXREDACT_BWS env or PATH. */
static int bitwarden_fetch(const char *token, const char *project_id,
                           char **names, int nnames, char **out_vals,
                           int privileged, uid_t invoker) {
    if (!token || !*token || !project_id || !*project_id) return 1;
    /* Resolve bws. Prefer the explicit CTXREDACT_BWS env; in the setuid model
       fall back to a fixed absolute path (the broker's PATH may not include
       /usr/local/bin, and a bare PATH lookup would be attacker-influencable). */
    const char *bws = getenv("CTXREDACT_BWS");
    if (!bws || !*bws) bws = "/usr/local/bin/bws";
    /* In the setuid-root security model the bws binary MUST be root-owned and
       not agent-writable, otherwise the invoking principal can substitute a
       fake bws that reads the token from its environment. In non-setuid
       (dev/test) builds there is no privilege boundary to protect, so skip. */
    int drop_uid = 0;
    if (privileged) {
        if (validate_bws(bws) != 0) return 5;         /* refuse a substitutable bws */
        drop_uid = resolve_bws_uid(invoker);
        if (drop_uid < 0) return 6;                    /* no safe uid to run bws as */
    }
    char *argv[6];
    argv[0] = (char*)bws; argv[1] = "secret"; argv[2] = "list";
    argv[3] = (char*)project_id; argv[4] = "-o"; argv[5] = "env";
    /* argv is not NUL-terminated for the execvp call, so build a NUL array. */
    char *cmd[7];
    memcpy(cmd, argv, sizeof(argv));
    cmd[6] = NULL;
    char *out = NULL, *err = NULL;
    /* Run bws under the dedicated unprivileged uid (in setuid mode) so the
       token in its env is not readable by the invoking principal, which could
       otherwise read it via /proc/<pid>/environ during the fetch. Capture
       BOTH streams and discard bws stderr so nothing leaks unredacted. */
    if (run_capture2(cmd, "BWS_ACCESS_TOKEN", token, drop_uid, &out, &err) != 0) {
        free(out); free(err); return 2;
    }
    if (!out) { free(err); return 2; }
    free(err);   /* bws stderr is captured and never forwarded */

    /* Parse NAME="VALUE" lines. bws env output quotes values with double
       quotes and escapes any inner double quote as \". We only need the value
       per requested name; unquote and resolve the \" and \\ escapes. */
    int rc = 0;
    char *save = NULL;
    for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        /* strip surrounding double quotes from both name and value */
        char *name = line, *val = eq + 1;
        size_t nl = strlen(name);
        if (nl && name[nl-1] == '\r') name[nl-1] = '\0';
        if (*name == '"') { memmove(name, name+1, strlen(name)); }   /* drop leading quote */
        nl = strlen(name);
        if (nl && name[nl-1] == '"') name[nl-1] = '\0';               /* drop trailing quote */
        nl = strlen(val);
        if (nl && val[nl-1] == '\r') val[nl-1] = '\0';
        if (val[0] == '"') { memmove(val, val+1, strlen(val)); }      /* drop leading quote */
        nl = strlen(val);
        if (nl && val[nl-1] == '"') val[nl-1] = '\0';                 /* drop trailing quote */
        /* resolve \" and \\ escapes (bws quotes values with double quotes) */
        {
            char *r = val, *w = val;
            while (*r) {
                if (*r == '\\' && (r[1] == '"' || r[1] == '\\')) { *w++ = r[1]; r += 2; }
                else { *w++ = *r++; }
            }
            *w = '\0';
        }
        for (int i = 0; i < nnames; i++) {
            if (out_vals[i]) continue;
            if (strcmp(name, names[i]) == 0) {
                out_vals[i] = strdup(val);
                if (!out_vals[i]) { rc = 3; goto done; }
            }
        }
    }
    for (int i = 0; i < nnames; i++) {
        if (!out_vals[i] || !*out_vals[i]) {
            fprintf(stderr, "error: secret '%s' not found in Bitwarden project %s\n",
                    names[i], project_id);
            for (int j = 0; j < nnames; j++) { free(out_vals[j]); out_vals[j] = NULL; }
            rc = 4; goto done;
        }
    }
done:
    free(out);
    return rc;
}

/* Fork the child through a pipe, redact its merged output, return exit status.
   names[i] is used only to label the "[REDACTED:NAME]" marker. */
static int run_redacted(char **child, char **names, char **vals, int n, int privileged) {
    int p[2];
    if (pipe(p) != 0) { perror("ctxredact: pipe"); return 127; }
    pid_t pid = fork();
    if (pid < 0) { perror("ctxredact: fork"); return 127; }
    if (pid == 0) {
        /* Child: drop privilege, route output through the pipe, exec. */
        if (privileged && drop_to_invoker() != 0) _exit(127);
        if (dup2(p[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(p[1], STDERR_FILENO) < 0) _exit(127);
        close(p[0]); close(p[1]);
        execvp(child[0], child);
        perror("ctxredact: exec failed");
        _exit(127);
    }
    /* Parent: filter the child's output. */
    close(p[1]);
    const size_t cap = 32u * 1024u * 1024u;  /* 32 MiB output ceiling */
    size_t alloc = 64u * 1024u;
    size_t len = 0;
    char *buf = malloc(alloc);
    if (!buf) { close(p[0]); waitpid(pid, NULL, 0); return 127; }
    ssize_t r;
    while ((r = read(p[0], buf + len, alloc - len - 1)) > 0) {
        len += (size_t)r;
        if (len >= alloc - 1) {
            if (alloc >= cap) {
                /* Ceiling reached. The buffer may end MID-SECRET (the tail was
                   never read), leaving a partial value that exact-match
                   redaction cannot catch. Drop the last (max_secret_len - 1)
                   bytes so nothing partially-matching can be forwarded. */
                size_t maxsl = 0;
                for (int i = 0; i < n; i++) {
                    size_t vl = strlen(vals[i]);
                    if (vl > maxsl) maxsl = vl;
                }
                if (maxsl > 1 && len > maxsl - 1) len -= (maxsl - 1);
                break;
            }
            alloc *= 2;
            char *nb = realloc(buf, alloc);
            if (!nb) { free(buf); close(p[0]); waitpid(pid, NULL, 0); return 127; }
            buf = nb;
        }
    }
    close(p[0]);
    buf[len] = '\0';

    /* Sort keys by value length DESCENDING before scrubbing. If a shorter
       value is a substring of a longer one, redacting the short one first
       mangles the long value (marker spliced mid-secret) so it never fully
       matches again, leaking fragments. Longest-first avoids that. */
    int *order = malloc((size_t)n * sizeof(int));
    if (order) {
        for (int i = 0; i < n; i++) order[i] = i;
        for (int i = 1; i < n; i++) {           /* insertion sort (n is tiny) */
            int ti = order[i], j = i - 1;
            while (j >= 0 && strlen(vals[order[j]]) < strlen(vals[ti])) {
                order[j + 1] = order[j]; j--;
            }
            order[j + 1] = ti;
        }
    }
    char *cur = buf;
    for (int oi = 0; oi < n; oi++) {
        int i = order ? order[oi] : oi;
        size_t vl = strlen(vals[i]);
        if (vl == 0) continue;
        /* Label the marker with the key name so a downstream agent reads
           "[REDACTED:KEY]" and understands the swap; it will not pass the
           marker string on as if it were real data in a multi-step task. */
        char marker[512];
        int ml = snprintf(marker, sizeof(marker), "%s%s%s", REDACT_PREFIX, names[i], REDACT_SUFFIX);
        if (ml < 0 || (size_t)ml >= sizeof(marker)) continue; /* name too long: skip scrubbing this one */
        size_t nl = 0;
        char *next = replace_all(cur, strlen(cur), vals[i], vl, marker, (size_t)ml, &nl);
        free(cur);
        cur = next;
        if (!cur) {
            /* Allocation failed mid-scrub: fail CLOSED. Never forward output
               that may still contain an unredacted secret. */
            cur = strdup(REDACT_ERROR);
            if (!cur) { waitpid(pid, NULL, 0); return 127; }
            break;
        }
    }
    fwrite(cur, 1, strlen(cur), stdout);
    fflush(stdout);
    free(cur);
    free(order);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 127;
}

int main(int argc, char **argv) {
    if (getuid() == 0) {
        fprintf(stderr, "ctxredact: refusing to run as real root\n");
        return 2;
    }
    int privileged = (geteuid() == 0);
    if (!privileged) {
        fprintf(stderr, "ctxredact: warning: not setuid-root; child will inherit agent perms\n");
    }

    const char *secrets = SECRETS_PATH;
    if (!privileged) {
        const char *o = getenv("CTXREDACT_SECRETS");
        if (o && *o) secrets = o;
    }

    if (argc == 2 && strcmp(argv[1], "--help") == 0) { usage(argv[0]); return 0; }
    if (argc == 3 && strcmp(argv[1], "--check") == 0) {
        char *v = secret_value(secrets, argv[2]);
        int ok = (v && *v);
        if (ok) free(v);
        return ok ? 0 : 1;
    }
    if (argc == 2 && strcmp(argv[1], "--names") == 0) {
        FILE *f = fopen(secrets, "r");
        if (!f) return 1;
        char *line = NULL; size_t cap = 0; ssize_t n;
        while ((n = getline(&line, &cap, f)) != -1) {
            char *eq = strchr(line, '=');
            if (eq && (line[0] != '#')) { *eq = '\0'; printf("%s\n", line); }
        }
        free(line); fclose(f);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {
        FILE *f = fopen(secrets, "r");
        if (!f) return 1;
        char *line = NULL; size_t cap = 0; ssize_t n;
        char purpose[512]; int have_purpose = 0;
        printf("%-20s\t%-6s\t%-8s\t%s\n", "KEY", "STATUS", "LEN", "PURPOSE");
        while ((n = getline(&line, &cap, f)) != -1) {
            if (n && line[n-1] == '\n') line[n-1] = '\0';
            if (n > 1 && line[n-2] == '\r') line[n-2] = '\0';
            if (line[0] == '#') {                       /* purpose = comment above key */
                char *p = line + 1;
                while (*p == ' ' || *p == '\t') p++;
                snprintf(purpose, sizeof purpose, "%s", p);
                have_purpose = 1;
                continue;
            }
            if (line[0] == '\0') {                      /* blank line breaks adjacency */
                have_purpose = 0;
                continue;
            }
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            char *val = eq + 1;
            size_t vlen = strlen(val);
            while (vlen && (val[vlen-1] == '\n' || val[vlen-1] == '\r')) val[--vlen] = '\0';
            printf("%-20s\t%-6s\t%-8zu\t%s\n", line, vlen ? "SET" : "UNSET", vlen,
                   have_purpose ? purpose : "");
            have_purpose = 0;
        }
        free(line); fclose(f);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--purposes") == 0) {
        /* Machine-readable: one 'NAME\tpurpose' line per secret, no values, no
         * lengths (keeps the model-facing surface to the minimum). The purpose
         * is the comment immediately above the key. Empty purpose = bare '\t'. */
        FILE *f = fopen(secrets, "r");
        if (!f) return 1;
        char *line = NULL; size_t cap = 0; ssize_t n;
        char purpose[512]; int have_purpose = 0;
        while ((n = getline(&line, &cap, f)) != -1) {
            if (n && line[n-1] == '\n') line[n-1] = '\0';
            if (n > 1 && line[n-2] == '\r') line[n-2] = '\0';
            if (line[0] == '#') {
                char *p = line + 1;
                while (*p == ' ' || *p == '\t') p++;
                snprintf(purpose, sizeof purpose, "%s", p);
                have_purpose = 1;
                continue;
            }
            if (line[0] == '\0') { have_purpose = 0; continue; }
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            /* strip trailing newline from name */
            size_t nlen = strlen(line);
            while (nlen && (line[nlen-1] == '\n' || line[nlen-1] == '\r')) line[--nlen] = '\0';
            printf("%s\t%s\n", line, have_purpose ? purpose : "");
            have_purpose = 0;
        }
        free(line); fclose(f);
        return 0;
    }

    if (argc < 3) { usage(argv[0]); return 2; }

    int dash = -1;
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "--") == 0) { dash = i; break; }
    if (dash < 0 || dash + 2 > argc) {
        fprintf(stderr, "error: missing '-- command args...' separator\n");
        return 2;
    }

    /* Reject a --redact token appearing AFTER the separator (it'd be a command
       arg). Collect the flags only if they appear before '--'. */
    int redact = 0, bitwarden = 0;
    for (int i = 1; i < dash; i++) {
        if (strcmp(argv[i], "--redact") == 0) redact = 1;
        if (strcmp(argv[i], "--bitwarden") == 0) bitwarden = 1;
    }

    /* Build a filtered name list excluding the reserved flag tokens. */
    int nnames = 0;
    for (int i = 1; i < dash; i++)
        if (strcmp(argv[i], "--redact") != 0 && strcmp(argv[i], "--bitwarden") != 0) nnames++;
    if (nnames == 0) { fprintf(stderr, "error: at least one secret NAME is required\n"); return 2; }
    char **names = malloc((size_t)nnames * sizeof(char*));
    int k = 0;
    for (int i = 1; i < dash; i++)
        if (strcmp(argv[i], "--redact") != 0 && strcmp(argv[i], "--bitwarden") != 0) names[k++] = argv[i];

    char **vals = calloc((size_t)nnames, sizeof(char*));
    if (!vals) { free(names); fprintf(stderr, "error: oom\n"); return 2; }

    if (bitwarden) {
        /* Pull from Bitwarden Secrets Manager. The broker reads the token and
           project id from the same secured file, then resolves the requested
           secret values itself, so --redact can scrub them from output (a
           value fetched only inside the child would be unredactable). */
        char *token = secret_value(secrets, "BITWARDEN_TOKEN");
        char *proj  = secret_value(secrets, "BITWARDEN_PROJECT_ID");
        if (!token || !*token) {
            fprintf(stderr, "error: BITWARDEN_TOKEN not set in %s\n", secrets);
            free(token); free(proj); free(vals); free(names);
            return 1;
        }
        if (!proj || !*proj) {
            fprintf(stderr, "error: BITWARDEN_PROJECT_ID not set in %s\n", secrets);
            free(token); free(proj); free(vals); free(names);
            return 1;
        }
        int brc = bitwarden_fetch(token, proj, names, nnames, vals, privileged, getuid());
        free(token); free(proj);
        if (brc != 0) {
            fprintf(stderr, "error: bitwarden fetch failed (code %d)\n", brc);
            free(vals); free(names);
            return 1;
        }
    } else {
        for (int i = 0; i < nnames; i++) {
            vals[i] = secret_value(secrets, names[i]);
            if (!vals[i] || !*vals[i]) {
                fprintf(stderr, "error: secret '%s' not set/empty in %s\n", names[i], secrets);
                for (int j = 0; j < i; j++) free(vals[j]);
                free(vals); free(names);
                return 1;
            }
        }
    }
    for (int i = 0; i < nnames; i++) {
        /* FAIL CLOSED: --redact labels markers as "[REDACTED:<name>]". A name
           too long for the marker buffer cannot be scrubbed safely; skipping
           it would forward the raw value. Refuse before exec'ing anything. */
        if (redact && strlen(names[i]) > 480) {
            fprintf(stderr, "ctxredact: refusing --redact: key name too long to label: %s\n", names[i]);
            for (int j = 0; j <= i; j++) free(vals[j]);
            free(vals); free(names);
            return 4;
        }
    }

    size_t cmdlen = 0;
    for (int i = dash + 1; i < argc; i++) cmdlen += strlen(argv[i]) + 1;
    char *cmdline = malloc(cmdlen + 1);
    if (cmdline) {
        cmdline[0] = '\0';
        for (int i = dash + 1; i < argc; i++) { strcat(cmdline, argv[i]); if (i + 1 != argc) strcat(cmdline, " "); }
    }
    /* The advisory leak guard applies only without --redact: with --redact the
       broker scrubs values from the child's output, so a guard false-positive
       (e.g. the word "environment") would just block legitimate commands. */
    if (!redact && cmdline && looks_like_leak(cmdline, secrets)) {
        fprintf(stderr, "ctxredact: refused, command looks like it would expose the secret\n");
        free(cmdline);
        for (int j = 0; j < nnames; j++) free(vals[j]);
        free(vals); free(names);
        return 3;
    }
    free(cmdline);

    if (!redact) {
        if (privileged && drop_to_invoker() != 0) {
            for (int j = 0; j < nnames; j++) free(vals[j]);
            free(vals); free(names);
            _exit(1);
        }
        for (int i = 0; i < nnames; i++) setenv(names[i], vals[i], 1);
        char **child = argv + dash + 1;
        execvp(child[0], child);
        perror("ctxredact: exec failed");
        for (int j = 0; j < nnames; j++) free(vals[j]);
        free(vals); free(names);
        return 127;
    }

    /* --redact: setenv BEFORE fork so the child inherits the secret. */
    for (int i = 0; i < nnames; i++) setenv(names[i], vals[i], 1);
    int rc = run_redacted(argv + dash + 1, names, vals, nnames, privileged);
    for (int j = 0; j < nnames; j++) free(vals[j]);
    free(vals); free(names);
    return rc;
}
