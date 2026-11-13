PREFIX?=/usr/local
BINDIR?=$(PREFIX)/bin
MANDIR?=$(PREFIX)/share/man
STRIP?=strip

FEATURES+=-DWANT_FULLSCRAPE -DWANT_ACCESSLIST_BLACK -DWANT_RESTRICT_STATS -DWANT_RESTRICT_FULLSCRAPE -DWANT_IP_FROM_PROXY -DWANT_KEEPALIVE

FEATURES+=-DOT_BUCKET_COUNT_BITS=10

include Mk/gzip.mk

CFLAGS?=-O3

OT_CFLAGS+=-Wall -Wextra -Wwrite-strings -pipe -pthread

HARDENING=-fstack-protector-strong -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
HARDENING_LD!=	case `uname -s` in Darwin) ;; *) printf %s "-pie -Wl,-z,relro,-z,now" ;; esac
OT_LDFLAGS+=-pthread
OT_LDLIBS+=-lyaml

COMPILE=$(CPPFLAGS) $(OT_CFLAGS) $(FEATURES)
LINK=$(LDFLAGS) $(OT_LDFLAGS) $(LDLIBS) $(OT_LDLIBS)

BINARY=yukitracker
HEADERS=$(wildcard src/*.h)
SOURCES=$(wildcard src/*.c)

BUILDSTAMP=.buildstamp
BUILDDEPS=Makefile VERSION Mk/release.mk $(BUILDSTAMP)

all: $(BINARY)

$(BINARY): $(SOURCES) $(HEADERS) $(BUILDDEPS)
	$(CC) -o $@ $(CFLAGS) $(COMPILE) $(HARDENING) $(SOURCES) $(LINK) $(HARDENING_LD)
	$(STRIP) $@

$(BUILDSTAMP): FORCE
	@echo "$(CFLAGS) $(COMPILE) $(HARDENING) $(LINK) $(HARDENING_LD)" | cmp -s - $@ 2>/dev/null || echo "$(CFLAGS) $(COMPILE) $(HARDENING) $(LINK) $(HARDENING_LD)" > $@

clean:
	rm -f $(BINARY) $(BUILDSTAMP)

install: $(BINARY)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/man5
	install -m 755 $(BINARY) $(DESTDIR)$(BINDIR)
	install -m 644 man1/yukitracker.1 $(DESTDIR)$(MANDIR)/man1
	install -m 644 man5/yukitracker.conf.5 $(DESTDIR)$(MANDIR)/man5

FORCE:

.PHONY: all clean install FORCE

include Mk/release.mk
