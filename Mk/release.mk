override VERSION := $(shell cat VERSION)
OT_CFLAGS += -DTRACKER_VERSION=\"$(VERSION)\"

DISTNAME=yukitracker-$(VERSION)

dist:
	@test "`git describe --tags --match 'v*' --exact-match 2>/dev/null`" = "v$(VERSION)" || \
		{ echo "HEAD must carry the tag v$(VERSION). Tag the release, or correct VERSION."; exit 1; }
	rm -rf $(DISTNAME) $(DISTNAME).tar.gz
	git archive --format=tar --prefix=$(DISTNAME)/ HEAD | tar -xf -
	printf '%s\n' "$(VERSION)" > $(DISTNAME)/VERSION
	tar -czf $(DISTNAME).tar.gz $(DISTNAME)
	tar -cjf $(DISTNAME).tar.bz2 $(DISTNAME)
	rm -rf $(DISTNAME)

.PHONY: dist
