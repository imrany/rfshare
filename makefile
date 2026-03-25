# rfshare build & installer Makefile
# ─────────────────────────────────────────────────────────────────────────────
#  make                     → release build for the current platform
#  make install             → build + install (Linux/macOS)
#  make uninstall           → remove rfshare (Linux/macOS)
#  make pkg-linux           → .tar.gz archive for Linux
#  make pkg-mac             → .app bundle (macOS only)
#  make pkg-mac-dmg         → .dmg disk image (macOS only, needs create-dmg)
#  make pkg-windows         → .msi installer (Windows only, needs WiX v4)
#  make pkg-windows-zip     → .zip portable archive (Windows)
#  make bundle              → cargo-bundle (Linux .deb / macOS .app)
#  make clean               → cargo clean

APP     = rfshare
VERSION = 0.7.0
TARGET  = target/release/$(APP)
OS     := $(shell uname -s 2>/dev/null || echo Windows)

.PHONY: all build install uninstall \
        pkg-linux pkg-mac pkg-mac-dmg \
        pkg-windows pkg-windows-zip \
        bundle clean

# ── default ───────────────────────────────────────────────────────────────────
all: build

build:
	cargo build --release

# ── Linux / macOS install ─────────────────────────────────────────────────────
install: build
	@echo "Running installer…"
	@bash install.sh

uninstall:
	@bash install.sh --uninstall

# ── Linux package: tar.gz ─────────────────────────────────────────────────────
pkg-linux: build
	@echo "Creating Linux archive…"
	mkdir -p dist
	tar -czf dist/$(APP)-$(VERSION)-linux-x86_64.tar.gz \
	    -C target/release $(APP) \
	    --transform 's|$(APP)|$(APP)-$(VERSION)/$(APP)|' \
	    --add-file rfshare.desktop \
	    --add-file install.sh \
	    --add-file assets/icon.png \
	    --add-file LICENSE \
	    --add-file README.md 2>/dev/null || \
	( mkdir -p /tmp/rfshare-pkg/$(APP)-$(VERSION) && \
	  cp target/release/$(APP) /tmp/rfshare-pkg/$(APP)-$(VERSION)/ && \
	  cp rfshare.desktop install.sh LICENSE README.md /tmp/rfshare-pkg/$(APP)-$(VERSION)/ 2>/dev/null; \
	  mkdir -p /tmp/rfshare-pkg/$(APP)-$(VERSION)/assets && \
	  cp assets/icon.png /tmp/rfshare-pkg/$(APP)-$(VERSION)/assets/ 2>/dev/null; \
	  tar -czf dist/$(APP)-$(VERSION)-linux-x86_64.tar.gz \
	      -C /tmp/rfshare-pkg $(APP)-$(VERSION) && \
	  rm -rf /tmp/rfshare-pkg )
	@echo "→ dist/$(APP)-$(VERSION)-linux-x86_64.tar.gz"

# ── macOS: .app bundle ────────────────────────────────────────────────────────
pkg-mac: build
	@echo "Creating macOS .app bundle…"
	mkdir -p dist
	mkdir -p dist/$(APP).app/Contents/MacOS
	mkdir -p dist/$(APP).app/Contents/Resources
	cp target/release/$(APP) dist/$(APP).app/Contents/MacOS/
	chmod +x dist/$(APP).app/Contents/MacOS/$(APP)
	@# Convert PNG to ICNS if possible
	@if command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1; then \
	    mkdir -p /tmp/rfshare.iconset; \
	    for s in 16 32 64 128 256 512; do \
	        sips -z $$s $$s assets/icon.png --out /tmp/rfshare.iconset/icon_$${s}x$${s}.png >/dev/null; \
	        sips -z $$((s*2)) $$((s*2)) assets/icon.png --out /tmp/rfshare.iconset/icon_$${s}x$${s}@2x.png >/dev/null; \
	    done; \
	    iconutil -c icns /tmp/rfshare.iconset -o dist/$(APP).app/Contents/Resources/rfshare.icns; \
	    rm -rf /tmp/rfshare.iconset; \
	    echo "  ICNS icon generated"; \
	else \
	    cp assets/icon.png dist/$(APP).app/Contents/Resources/rfshare.png; \
	    echo "  PNG icon used (install iconutil for .icns)"; \
	fi
	@# Write Info.plist
	@printf '%s' '<?xml version="1.0" encoding="UTF-8"?>\n\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n\
<plist version="1.0"><dict>\n\
    <key>CFBundleName</key><string>rfshare</string>\n\
    <key>CFBundleDisplayName</key><string>rfshare</string>\n\
    <key>CFBundleIdentifier</key><string>dev.rfshare.app</string>\n\
    <key>CFBundleVersion</key><string>$(VERSION)</string>\n\
    <key>CFBundleShortVersionString</key><string>$(VERSION)</string>\n\
    <key>CFBundlePackageType</key><string>APPL</string>\n\
    <key>CFBundleExecutable</key><string>rfshare</string>\n\
    <key>CFBundleIconFile</key><string>rfshare</string>\n\
    <key>NSHumanReadableCopyright</key><string>Copyright © 2025 Imrany</string>\n\
    <key>NSHighResolutionCapable</key><true/>\n\
    <key>LSMinimumSystemVersion</key><string>10.14</string>\n\
</dict></plist>\n' > dist/$(APP).app/Contents/Info.plist
	@echo "→ dist/$(APP).app"

# ── macOS: .dmg ───────────────────────────────────────────────────────────────
# Requires: brew install create-dmg
pkg-mac-dmg: pkg-mac
	@echo "Creating macOS .dmg…"
	create-dmg \
	    --volname "rfshare $(VERSION)" \
	    --volicon "assets/icon.icns" \
	    --window-pos 200 120 \
	    --window-size 600 400 \
	    --icon-size 100 \
	    --icon "rfshare.app" 175 190 \
	    --hide-extension "rfshare.app" \
	    --app-drop-link 425 190 \
	    "dist/$(APP)-$(VERSION)-mac.dmg" \
	    "dist/$(APP).app"
	@echo "→ dist/$(APP)-$(VERSION)-mac.dmg"

# ── Windows: .msi (requires WiX v4) ──────────────────────────────────────────
# Install WiX: winget install WixToolset.WixToolset
# Then run this target on Windows.
pkg-windows: build
	@echo "Creating Windows .msi…"
	mkdir -p dist wix/stage
	cp target/release/$(APP).exe wix/stage/$(APP).exe
	cp assets/icon.ico wix/stage/$(APP).ico
	wix build wix/main.wxs \
	    -b wix/stage \
	    -o dist/$(APP)-$(VERSION)-windows-x64.msi
	rm -rf wix/stage
	@echo "→ dist/$(APP)-$(VERSION)-windows-x64.msi"

# ── Windows: portable .zip ────────────────────────────────────────────────────
pkg-windows-zip: build
	@echo "Creating Windows portable .zip…"
	mkdir -p dist
	powershell -NoProfile -Command \
	    "Compress-Archive -Force \
	        -Path target/release/rfshare.exe, assets/icon.ico, install.ps1, README.md \
	        -DestinationPath dist/$(APP)-$(VERSION)-windows-x64-portable.zip"
	@echo "→ dist/$(APP)-$(VERSION)-windows-x64-portable.zip"

# ── cargo-bundle (.deb on Linux, .app on macOS) ───────────────────────────────
# Install: cargo install cargo-bundle
bundle:
	cargo bundle --release

clean:
	cargo clean
	rm -rf dist
