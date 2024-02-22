
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?=
SYSCONFDIR ?= /etc
BINDIR ?= $(PREFIX)/bin
SYSTEMDUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemdsystemunitdir systemd 2>/dev/null || echo "$(PREFIX)/lib/systemd/system")
WITH_SYSTEMDUNITS ?=

ifeq ($(WITH_SYSTEMDUNITS),)
ifneq ($(strip $(wildcard $(SYSTEMDUNITDIR))),)
WITH_SYSTEMDUNITS := yes
endif
endif

install:
	install -v -m 0755 wirething-poc.sh "$(DESTDIR)$(BINDIR)/wirething-poc.sh" && install -v -m 0700 -d "$(DESTDIR)$(SYSCONFDIR)/wirething"
	@[ "$(WITH_SYSTEMDUNITS)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(SYSTEMDUNITDIR)" && install -v -m 0644 systemd/wirething-poc* "$(DESTDIR)$(SYSTEMDUNITDIR)/"
