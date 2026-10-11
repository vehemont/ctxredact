# Dev build only. The packaged setuid-root install is install.sh.
# Hardened flags match the setuid production build so dev behaves the same.
#
# SAFETY: `make` writes a NON-setuid dev binary. If PREFIX points at a real
# install, running `make` as root would silently REPLACE the hardened setuid
# binary with a plain-root one (4755 -> 0755), breaking the broker for every
# user. That is why the guard below refuses a root `make`.
#
# The default is a scratch path so an unprivileged `make` can actually build.
PREFIX ?= /tmp/ctxredact-dev
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
           -fPIE -pie -Wl,-z,relro,-z,now \
           -DSECRETS_PATH=\"$(PREFIX)/vault.env\"
BIN      = $(PREFIX)/bin/ctxredact

ifeq ($(shell id -u),0)
$(warning Refusing to run make as root: it would overwrite the setuid install with a dev build. Use install.sh instead.)
.PHONY: all
all:
	@exit 1
else
all: $(BIN)
endif

$(BIN): src/ctxredact.c
	@mkdir -p $(PREFIX)/bin
	$(CC) $(CFLAGS) -o $@ src/ctxredact.c
	@chmod 0755 $@
	@echo "NOTE: dev build is NOT setuid-root. Use install.sh for the real broker."

clean:
	rm -f $(BIN)

.PHONY: all clean
