#!/usr/bin/env bash
# install.sh - ONE-COMMAND INSTALL. Run as root:
#
#   sudo ./install.sh
#
# Builds + installs the setuid-root ctxredact broker, seeds the vault, installs
# the Hermes plugin, enables it, and bootstraps bws (for the optional Bitwarden
# source). After it finishes, restart Hermes and the agent gets
# run_with_secrets / check_secret / list_secrets. The only real configuration is
# the vault (or Bitwarden).
#
#   sudo ./install.sh --prefix /tmp/x   # scratch install (tests/CI)
#   sudo ./install.sh --no-plugin       # broker + vault only
#   sudo ./install.sh --no-bws          # skip the Bitwarden CLI bootstrap
#
# Security properties enforced here:
#   * install dirs are root:root 0755 (runtime user cannot swap the setuid
#     binary, nor the vault beneath it).
#   * vault is root:root 0600 (agent cannot read it).
#   * binary is setuid-root 4755, built hardened (PIE + full RELRO + stack
#     protector + _FORTIFY_SOURCE).
set -euo pipefail

# Locate the hermes CLI (for plugin enable + bws bootstrap). It is usually on
# PATH, but containerized installs keep it under a venv not on root's PATH.
# SECURITY: this resolves an executable that a ROOT install.sh will exec. Never
# accept a PATH lookup result blindly: require an absolute, root-owned,
# non-world-writable binary, or fall back to a hardcoded safe path.
find_hermes() {
  local candidate=""
  if command -v hermes >/dev/null 2>&1; then candidate="$(command -v hermes)"; fi
  if [ -x /opt/hermes/.venv/bin/hermes ]; then candidate="/opt/hermes/.venv/bin/hermes"; fi
  if [ -x "${HERMES_REAL_HOME:-${HOME}}/.local/bin/hermes" ]; then
    candidate="${HERMES_REAL_HOME:-${HOME}}/.local/bin/hermes"
  fi
  if [ -n "$candidate" ] && [ "$(id -u)" -eq 0 ] && [ -f "$candidate" ]; then
    if [ "$(stat -c '%U' "$candidate" 2>/dev/null)" = "root" ] \
       && [ "$(stat -c '%A' "$candidate" 2>/dev/null | cut -c8-10)" = "r-x" ] \
       && [ "$(stat -c '%A' "$candidate" 2>/dev/null | cut -c8)" != "w" ]; then
      printf '%s\n' "$candidate"; return 0
    fi
    # Root execs the hermes CLI; if it is not root-owned, do NOT exec it as root.
    # Fall through to a non-exec behavior below rather than running untrusted code.
    return 1
  fi
  # Non-root install or nothing found: fall back to a PATH lookup (the invoking
  # user's own binary is only used for enable/bootstrap when NOT privileged).
  if [ -n "$candidate" ]; then printf '%s\n' "$candidate"; return 0; fi
  return 1
}
HERMES_BIN="$(find_hermes || true)"

PREFIX="/usr/local"
ETC="/etc/ctxredact"
NO_PLUGIN=0
NO_BWS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; ETC="${2}/etc/ctxredact"; shift 2 ;;
    --no-plugin) NO_PLUGIN=1; shift ;;
    --no-bws) NO_BWS=1; shift ;;
    -h|--help)
      echo "usage: sudo ./install.sh [--prefix DIR] [--no-plugin] [--no-bws]"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo ./install.sh" >&2; exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${REPO_DIR}/src"
BIN_DIR="${PREFIX}/bin"
ETC_DIR="${ETC}"
VAULT="${ETC_DIR}/vault.env"
BINARY="${BIN_DIR}/ctxredact"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

# --- 1/5: install dirs (root:root 0755) -----------------------------------
install -d -o root -g root -m 0755 "$BIN_DIR" "$ETC_DIR"

# --- 2/5: seed vault if absent (root:root 0600) ---------------------------
if [ ! -s "$VAULT" ]; then
  if [ -f "${REPO_DIR}/vault.env.example" ]; then
    install -o root -g root -m 0600 "${REPO_DIR}/vault.env.example" "$VAULT"
    echo "    created ${VAULT} from vault.env.example - FILL IN REAL VALUES."
  else
    install -o root -g root -m 0600 /dev/null "$VAULT"
    echo "    created empty ${VAULT}."
  fi
else
  chown root:root "$VAULT"; chmod 600 "$VAULT"
fi

# --- 3/5: build hardened setuid-root broker -------------------------------
cc -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
   -fPIE -pie -Wl,-z,relro,-z,now \
   -DSECRETS_PATH=\"$VAULT\" \
   -o "${BUILD}/ctxredact" "${SRC_DIR}/ctxredact.c"
strip "${BUILD}/ctxredact" 2>/dev/null || true

# --- 4/5: install setuid-root 4755 -----------------------------------------
install -m 4755 -o root -g root "${BUILD}/ctxredact" "$BINARY"

# --- 3b: create the dedicated unprivileged 'ctxredact' user (Bitwarden fetch) ---
# The broker runs the `bws` client under this uid so the Bitwarden access token
# (which lives in bws's environment) is never readable by the invoking agent
# user via /proc/<pid>/environ. No shell, no home, no password; it only exists
# as a low-value uid to exec a read-only fetch.
if [ "$NO_BWS" -eq 0 ]; then
  if ! id ctxredact >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin ctxredact 2>/dev/null \
      || useradd --system -M -s /bin/false ctxredact 2>/dev/null \
      || echo "    (warning: could not create 'ctxredact' user; create it or set CTXREDACT_BWS_UID)"
  fi
  echo "    bws runs as: ctxredact ($(id -u ctxredact 2>/dev/null || echo 'unset'))"
fi

# --- 4b: bootstrap bws (Bitwarden source is optional, but zero-config if used) --
# Prefer Hermes's own pinned+checksummed installer when available. The broker
# runs bws as root in the setuid model, so the binary MUST be root-owned and
# not agent-writable (else the agent could substitute a fake bws). Hermes
# installs bws into the user's bin dir (agent-owned); so after installing,
# this block copies it to a root-owned /usr/local/bin/bws and hardens it.
if [ "$NO_PLUGIN" -eq 0 ] && [ "$NO_BWS" -eq 0 ] && [ -n "$HERMES_BIN" ]; then
  echo "    bws: hermes secrets bitwarden install (pinned)"
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    su - "$SUDO_USER" -c "\"$HERMES_BIN\" secrets bitwarden install" >/dev/null 2>&1 \
      && echo "    bws installed" || echo "    (bws install skipped - rerun 'hermes secrets bitwarden install')"
  else
    "$HERMES_BIN" secrets bitwarden install >/dev/null 2>&1 \
      && echo "    bws installed" || echo "    (bws install skipped - rerun 'hermes secrets bitwarden install')"
  fi
  # Locate the bws binary Hermes just installed (it is agent-owned), then
  # reinstall a hardened ROOT-owned copy the broker can safely exec.
  BWS_SRC=""
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    BWS_SRC=$(su - "$SUDO_USER" -c 'command -v bws' 2>/dev/null || true)
  fi
  [ -z "$BWS_SRC" ] && BWS_SRC=$(command -v bws 2>/dev/null || true)
  [ -z "$BWS_SRC" ] && BWS_SRC=$(ls /opt/hermes/.venv/bin/bws /usr/local/bin/bws 2>/dev/null | head -1 || true)
  if [ -n "$BWS_SRC" ]; then
    rm -f /usr/local/bin/bws   # drop any agent-writable symlink/copy
    install -o root -g root -m 0755 "$BWS_SRC" /usr/local/bin/bws 2>/dev/null \
      && echo "    bws hardened (root-owned): /usr/local/bin/bws" \
      || echo "    (bws left as-is; install it root-owned to /usr/local/bin/bws for the Bitwarden source)"
  else
    echo "    (could not locate bws; visit https://github.com/bitwarden/sdk-sm/releases)"
  fi
fi

# --- 5/5: Hermes plugin ----------------------------------------------------
INSTALLED_PLUGIN=""
if [ "$NO_PLUGIN" -eq 0 ] && [ -f "${REPO_DIR}/plugin/__init__.py" ]; then
  # prefer the invoking (non-root) user's home when running under sudo
  TARGET_HOME="${SUDO_USER:+$(getent passwd "${SUDO_USER}" | cut -d: -f6)}"
  TARGET_HOME="${TARGET_HOME:-$HOME}"
  PLUG_DIR="${TARGET_HOME}/.hermes/plugins/ctxredact"
  install -d -o "${SUDO_USER:-root}" -m 0755 "$PLUG_DIR" 2>/dev/null || install -d -m 0755 "$PLUG_DIR"
  install -m 0644 "${REPO_DIR}/plugin/__init__.py" "${REPO_DIR}/plugin/plugin.yaml" "$PLUG_DIR/"
  chown -R "${SUDO_USER:-root}" "$PLUG_DIR" 2>/dev/null || true
  INSTALLED_PLUGIN="$PLUG_DIR"
  # --- 5b: auto-enable (drop-in - otherwise the plugin is discovered but inert) --
  if [ -n "$HERMES_BIN" ]; then
    ENABLE_CMD="plugins enable ctxredact --no-allow-tool-override"
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
      if su - "$SUDO_USER" -c "\"$HERMES_BIN\" $ENABLE_CMD" >/dev/null 2>&1; then
        echo "    plugin enabled: ctxredact"
      else
        echo "    (plugin not auto-enabled - run: hermes plugins enable ctxredact)"
      fi
    else
      if "$HERMES_BIN" $ENABLE_CMD >/dev/null 2>&1; then
        echo "    plugin enabled: ctxredact"
      else
        echo "    (plugin not auto-enabled - run: hermes plugins enable ctxredact)"
      fi
    fi
  fi
fi

echo
echo "==> installed"
ls -l "$BINARY" "$VAULT" ${INSTALLED_PLUGIN:+"$INSTALLED_PLUGIN/__init__.py"} 2>/dev/null
echo
echo "done. Only one config step left:"
echo "  put real secrets in $VAULT (as root):    KEY=value lines"
echo "  (or, for the Bitwarden source, fill BITWARDEN_TOKEN + BITWARDEN_PROJECT_ID)"
echo
echo "plugin: ${INSTALLED_PLUGIN:+, installed and auto-enabled at $INSTALLED_PLUGIN}${INSTALLED_PLUGIN:-not installed}"
echo
echo "restart Hermes, then the agent has run_with_secrets / check_secret / list_secrets"
if [ "$NO_BWS" -eq 1 ]; then
  echo "(bitwarden source disabled via --no-bws; bws not installed)"
elif [ -z "$HERMES_BIN" ]; then
  echo "(hermes CLI not found - install bws manually: https://github.com/bitwarden/sdk-sm/releases)"
fi
