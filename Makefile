IMAGE ?= dmarc-analyzer
VIEWER := dist/dmarc-viewer
IMAGE_STAMP := .build/image-$(IMAGE)
CONFIG_EXAMPLE := config/analyzer.env.example
DESKTOP_SRC := contrib/dmarc-viewer.desktop
DESKTOP_DIR := $(HOME)/.local/share/applications
DESKTOP_DST := $(DESKTOP_DIR)/dmarc-viewer.desktop
PIPE_SRC := contrib/dmarc-analyzer-pipe
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc

.PHONY: all image viewer desktop uninstall-desktop install-pipe check clean distclean help

all: image viewer

help:
	@echo "Targets:"
	@echo "  all               Build the pipe image and the desktop viewer (default)"
	@echo "  check             Byte-compile the Python sources"
	@echo "  image             Build Docker image $(IMAGE)"
	@echo "  viewer            Build standalone executable $(VIEWER)"
	@echo "  desktop           Register the viewer as an Open With handler (optional)"
	@echo "  uninstall-desktop Remove the Open With registration"
	@echo "  install-pipe      Install the Postfix pipe wrapper to $(PREFIX)/bin"
	@echo "  clean             Remove build stamps and the viewer binary (keeps dist/analyzer.env)"
	@echo "  distclean         Also remove the $(IMAGE) image"

check:
	python3 -m py_compile src/dmarc_analyzer.py src/dmarc_viewer.py

image: $(IMAGE_STAMP)

$(IMAGE_STAMP): Dockerfile src/dmarc_analyzer.py requirements.txt
	docker build -t $(IMAGE) .
	mkdir -p $(dir $@)
	touch $@

viewer: $(VIEWER)

$(VIEWER): Dockerfile.viewer src/dmarc_analyzer.py src/dmarc_viewer.py requirements.txt $(CONFIG_EXAMPLE)
	docker build -f Dockerfile.viewer --target export --output type=local,dest=dist .
	test -f dist/analyzer.env || cp $(CONFIG_EXAMPLE) dist/analyzer.env

desktop: $(VIEWER)
	mkdir -p $(DESKTOP_DIR)
	sed -e 's|^Exec=.*|Exec=$(abspath $(VIEWER)) %f|' \
	    -e 's|^TryExec=.*|TryExec=$(abspath $(VIEWER))|' \
	    $(DESKTOP_SRC) > $(DESKTOP_DST)
	update-desktop-database $(DESKTOP_DIR)

uninstall-desktop:
	rm -f $(DESKTOP_DST)
	-update-desktop-database $(DESKTOP_DIR)

install-pipe: image $(PIPE_SRC)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(PIPE_SRC) $(DESTDIR)$(PREFIX)/bin/dmarc-analyzer-pipe
	install -d $(DESTDIR)$(SYSCONFDIR)/dmarc
	test -f $(DESTDIR)$(SYSCONFDIR)/dmarc/analyzer.env || \
	  install -m 600 $(CONFIG_EXAMPLE) $(DESTDIR)$(SYSCONFDIR)/dmarc/analyzer.env

clean:
	rm -f $(VIEWER)
	rm -rf .build src/build src/dist

distclean: clean
	-docker rmi $(IMAGE)
