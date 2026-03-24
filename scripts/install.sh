#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  rfshare installer — Linux & macOS
#  https://github.com/imrany/rfshare
#
#  One-liner (auto-detects OS, downloads the right installer):
#    curl -fsSL https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.sh | bash
#
#  Options:
#    --version v0.5.0   install a specific release (default: latest)
#    --prefix  /path    override install prefix    (default: /usr/local)
#    --binary-only      skip .deb/.dmg, install bare binary only
#    --uninstall        remove rfshare from this system
#
#  Environment:
#    PREFIX=$HOME/.local   user-only install, no sudo needed
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="imrany/rfshare"
APP="rfshare"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share"
DESKTOP_DIR="$SHARE_DIR/applications"
ICON_DIR="$SHARE_DIR/icons/hicolor"
VERSION=""
BINARY_ONLY=false

# ── colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null; then
    BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    RED='\033[0;31m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'
else
    BOLD=''; GREEN=''; YELLOW=''; RED=''; CYAN=''; DIM=''; RESET=''
fi

say()    { printf "${GREEN}==>${RESET}${BOLD} %s${RESET}\n" "$*"; }
info()   { printf "    ${DIM}%s${RESET}\n" "$*"; }
warn()   { printf "${YELLOW}  ! %s${RESET}\n" "$*"; }
die()    { printf "${RED}  ✗ error:${RESET} %s\n" "$*" >&2; exit 1; }
header() { printf "\n${BOLD}${CYAN}%s${RESET}\n" "$*"; }

# ── parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall)    UNINSTALL=true;        shift ;;
        --binary-only)  BINARY_ONLY=true;      shift ;;
        --version|-v)   VERSION="$2";          shift 2 ;;
        --prefix)       PREFIX="$2"
                        BIN_DIR="$PREFIX/bin"
                        SHARE_DIR="$PREFIX/share"
                        DESKTOP_DIR="$SHARE_DIR/applications"
                        ICON_DIR="$SHARE_DIR/icons/hicolor"
                        shift 2 ;;
        --help|-h)
            sed -n '3,12p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *)  die "Unknown argument: $1 (try --help)" ;;
    esac
done
UNINSTALL="${UNINSTALL:-false}"

# ── detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="linux";  EXT="tar.gz" ;;
    Darwin) PLATFORM="macos";  EXT="tar.gz" ;;
    *)      die "Unsupported OS '$OS'. On Windows use: irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex" ;;
esac

case "$ARCH" in
    x86_64|amd64) ;;
    arm64|aarch64)
        if [[ "$PLATFORM" == "macos" ]]; then
            warn "No native arm64 build yet — x86_64 binary runs under Rosetta 2."
        else
            die "No arm64 Linux build available. Build from source: cargo build --release"
        fi ;;
    *) warn "Unknown arch '$ARCH' — trying x86_64 binary." ;;
esac

# ── sudo helper ───────────────────────────────────────────────────────────────
SUDO=""
setup_sudo() {
    if [[ ! -d "$BIN_DIR" ]] || [[ ! -w "$BIN_DIR" ]]; then
        if command -v sudo &>/dev/null; then
            SUDO="sudo"
            info "sudo will be used to write to $BIN_DIR"
        else
            die "Cannot write to $BIN_DIR. Run as root, use sudo, or set PREFIX to a writable path:\n    PREFIX=\$HOME/.local bash install.sh"
        fi
    fi
}

# ── downloader ────────────────────────────────────────────────────────────────
if   command -v curl &>/dev/null; then DL="curl -fsSL";  DL_O="curl -fSL --progress-bar -o"
elif command -v wget &>/dev/null; then DL="wget -qO-";   DL_O="wget --progress=bar:force -O"
else die "curl or wget is required. Install one and re-run."
fi

# ── uninstall ─────────────────────────────────────────────────────────────────
if $UNINSTALL; then
    header "Uninstalling rfshare"
    setup_sudo
    $SUDO rm -f "$BIN_DIR/$APP"
    $SUDO rm -f "$DESKTOP_DIR/$APP.desktop"
    for size in 16 32 48 64 128 256; do
        $SUDO rm -f "$ICON_DIR/${size}x${size}/apps/$APP.png"
    done
    [[ "$PLATFORM" == "macos" ]] && $SUDO rm -rf "/Applications/rfshare.app" && say "Removed /Applications/rfshare.app"
    command -v update-desktop-database &>/dev/null && $SUDO update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    say "rfshare uninstalled."
    exit 0
fi

# ── resolve version ───────────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
    info "Fetching latest release from GitHub…"
    VERSION="$($DL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [[ -n "$VERSION" ]] || die "Could not determine latest version. Pass --version vX.Y.Z manually."
fi
[[ "$VERSION" == v* ]] || VERSION="v${VERSION}"
VER_NUM="${VERSION#v}"   # "0.5.0"

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

# ── print banner ─────────────────────────────────────────────────────────────
header "rfshare $VERSION · $PLATFORM"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
# Platform-specific installer path
# ──────────────────────────────────────────────────────────────────────────────
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

download_and_verify() {
    local url="$1" dest="$2" sha_url="$3"
    info "Downloading $(basename "$dest")…"
    $DL_O "$dest" "$url" || die "Download failed: $url"

    local sha_dest="${dest}.sha256"
    local skip=false
    $DL_O "$sha_dest" "$sha_url" 2>/dev/null || { warn "Checksum file not found — skipping verification."; skip=true; }

    if ! $skip; then
        local expected actual
        expected="$(awk '{print tolower($1)}' "$sha_dest")"
        if   command -v sha256sum &>/dev/null; then actual="$(sha256sum "$dest" | awk '{print $1}')"
        elif command -v shasum    &>/dev/null; then actual="$(shasum -a 256 "$dest" | awk '{print $1}')"
        else warn "No sha256sum/shasum — skipping checksum."; skip=true; fi

        if ! $skip; then
            [[ "$expected" == "$actual" ]] || \
                die "Checksum mismatch!\n  expected: $expected\n  got:      $actual\n\nDelete and retry."
            info "✓ Checksum verified (${actual:0:16}…)"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  LINUX  →  prefer .deb, fall back to binary tar.gz
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "linux" ]]; then

    DEB_NAME="rfshare-${VERSION}-linux-x86_64.deb"
    DEB_URL="$BASE_URL/$DEB_NAME"

    # Check whether .deb installer is available and dpkg is present
    USE_DEB=false
    if ! $BINARY_ONLY && command -v dpkg &>/dev/null; then
        # quick HEAD check — if the asset 404s, fall back to tar.gz
        if curl -fsIo /dev/null "$DEB_URL" 2>/dev/null || \
           wget -q --spider     "$DEB_URL" 2>/dev/null; then
            USE_DEB=true
        fi
    fi

    if $USE_DEB; then
        say "Installing via .deb package"
        DEB_PATH="$TMPDIR_WORK/$DEB_NAME"
        download_and_verify "$DEB_URL" "$DEB_PATH" "$DEB_URL.sha256"

        say "Running dpkg…"
        if [[ -w /usr/bin ]]; then
            dpkg -i "$DEB_PATH"
        else
            sudo dpkg -i "$DEB_PATH"
        fi
        say "rfshare $VERSION installed via .deb"

        # Refresh desktop/icon caches
        command -v update-desktop-database &>/dev/null && \
            { sudo update-desktop-database /usr/share/applications 2>/dev/null || true; }
        command -v gtk-update-icon-cache &>/dev/null && \
            { sudo gtk-update-icon-cache -qtf /usr/share/icons/hicolor 2>/dev/null || true; }

    else
        # ── Fall back: tar.gz binary + manual desktop/icon install ────────────
        $USE_DEB && say "dpkg not found — installing binary directly." || true
        setup_sudo
        ARCHIVE="rfshare-linux-${VERSION}.tar.gz"
        ARCHIVE_PATH="$TMPDIR_WORK/$ARCHIVE"
        download_and_verify \
            "$BASE_URL/$ARCHIVE" \
            "$ARCHIVE_PATH"      \
            "$BASE_URL/$ARCHIVE.sha256"

        say "Extracting…"
        tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR_WORK"
        chmod +x "$TMPDIR_WORK/rfshare"

        $SUDO mkdir -p "$BIN_DIR"
        $SUDO install -m755 "$TMPDIR_WORK/rfshare" "$BIN_DIR/rfshare"
        say "Binary  →  $BIN_DIR/rfshare"

        # Desktop entry
        DESKTOP_URL="https://raw.githubusercontent.com/$REPO/main/rfshare.desktop"
        ICON_URL="https://raw.githubusercontent.com/$REPO/main/assets/icon.png"
        $DL_O "$TMPDIR_WORK/rfshare.desktop" "$DESKTOP_URL" 2>/dev/null || true
        $DL_O "$TMPDIR_WORK/icon.png"         "$ICON_URL"    2>/dev/null || true

        if [[ -f "$TMPDIR_WORK/rfshare.desktop" ]]; then
            $SUDO mkdir -p "$DESKTOP_DIR"
            $SUDO install -Dm644 "$TMPDIR_WORK/rfshare.desktop" "$DESKTOP_DIR/rfshare.desktop"
            say "Desktop entry  →  $DESKTOP_DIR/rfshare.desktop"
        fi

        if [[ -f "$TMPDIR_WORK/icon.png" ]]; then
            if command -v convert &>/dev/null; then
                for size in 16 32 48 64 128 256; do
                    $SUDO mkdir -p "$ICON_DIR/${size}x${size}/apps"
                    convert "$TMPDIR_WORK/icon.png" -resize "${size}x${size}" \
                        "$TMPDIR_WORK/icon_${size}.png" 2>/dev/null
                    $SUDO install -Dm644 "$TMPDIR_WORK/icon_${size}.png" \
                        "$ICON_DIR/${size}x${size}/apps/rfshare.png"
                done
                say "Icons  →  $ICON_DIR/{16..256}x.../apps/rfshare.png"
            else
                $SUDO mkdir -p "$ICON_DIR/256x256/apps"
                $SUDO install -Dm644 "$TMPDIR_WORK/icon.png" "$ICON_DIR/256x256/apps/rfshare.png"
                warn "ImageMagick not found — only 256px icon installed"
            fi
            command -v update-desktop-database &>/dev/null && \
                $SUDO update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
            command -v gtk-update-icon-cache &>/dev/null && \
                $SUDO gtk-update-icon-cache -qtf "$ICON_DIR" 2>/dev/null || true
        fi
    fi

fi   # end Linux

# ══════════════════════════════════════════════════════════════════════════════
#  macOS  →  prefer .dmg, fall back to .app bundle, then binary tar.gz
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "macos" ]]; then

    DMG_NAME="rfshare-${VERSION}-macos.dmg"
    DMG_URL="$BASE_URL/$DMG_NAME"

    USE_DMG=false
    if ! $BINARY_ONLY; then
        if curl -fsIo /dev/null "$DMG_URL" 2>/dev/null || \
           wget -q --spider     "$DMG_URL" 2>/dev/null; then
            USE_DMG=true
        fi
    fi

    if $USE_DMG; then
        say "Installing via .dmg"
        DMG_PATH="$TMPDIR_WORK/$DMG_NAME"
        download_and_verify "$DMG_URL" "$DMG_PATH" "$DMG_URL.sha256"

        say "Mounting disk image…"
        MOUNT_DIR="$(mktemp -d)"
        hdiutil attach "$DMG_PATH" -mountpoint "$MOUNT_DIR" -nobrowse -quiet

        say "Copying rfshare.app to /Applications…"
        APP_SRC="$(find "$MOUNT_DIR" -name "rfshare.app" -maxdepth 2 | head -1)"
        if [[ -n "$APP_SRC" ]]; then
            rm -rf /Applications/rfshare.app
            cp -R "$APP_SRC" /Applications/rfshare.app
            say ".app bundle  →  /Applications/rfshare.app"
        else
            warn "rfshare.app not found in DMG — falling back to binary install."
            USE_DMG=false
        fi

        hdiutil detach "$MOUNT_DIR" -quiet || true
        rm -rf "$MOUNT_DIR"
    fi

    if ! $USE_DMG; then
        # ── Build .app from the tar.gz binary ─────────────────────────────────
        say "Building .app bundle from binary archive…"
        ARCHIVE="rfshare-macos-${VERSION}.tar.gz"
        ARCHIVE_PATH="$TMPDIR_WORK/$ARCHIVE"
        download_and_verify \
            "$BASE_URL/$ARCHIVE" \
            "$ARCHIVE_PATH"      \
            "$BASE_URL/$ARCHIVE.sha256"

        tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR_WORK"
        chmod +x "$TMPDIR_WORK/rfshare"

        # Build .app
        APP_BUNDLE="$TMPDIR_WORK/rfshare.app"
        mkdir -p "$APP_BUNDLE/Contents/MacOS"
        mkdir -p "$APP_BUNDLE/Contents/Resources"
        cp "$TMPDIR_WORK/rfshare" "$APP_BUNDLE/Contents/MacOS/rfshare"

        # Download icon and generate .icns
        ICON_URL="https://raw.githubusercontent.com/$REPO/main/assets/icon.png"
        $DL_O "$TMPDIR_WORK/icon.png" "$ICON_URL" 2>/dev/null || true
        ICON_REF="rfshare"

        if [[ -f "$TMPDIR_WORK/icon.png" ]] && \
           command -v iconutil &>/dev/null && command -v sips &>/dev/null; then
            ICONSET="$TMPDIR_WORK/rfshare.iconset"
            mkdir -p "$ICONSET"
            for size in 16 32 64 128 256 512; do
                sips -z $size $size "$TMPDIR_WORK/icon.png" \
                    --out "$ICONSET/icon_${size}x${size}.png" &>/dev/null
                sips -z $((size*2)) $((size*2)) "$TMPDIR_WORK/icon.png" \
                    --out "$ICONSET/icon_${size}x${size}@2x.png" &>/dev/null
            done
            iconutil -c icns "$ICONSET" -o "$APP_BUNDLE/Contents/Resources/rfshare.icns"
        elif [[ -f "$TMPDIR_WORK/icon.png" ]]; then
            cp "$TMPDIR_WORK/icon.png" "$APP_BUNDLE/Contents/Resources/rfshare.png"
            warn "iconutil not found — PNG icon used (may appear low-res)"
        fi

        cat > "$APP_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleName</key>              <string>rfshare</string>
    <key>CFBundleDisplayName</key>       <string>rfshare</string>
    <key>CFBundleIdentifier</key>        <string>dev.rfshare.app</string>
    <key>CFBundleVersion</key>           <string>$VER_NUM</string>
    <key>CFBundleShortVersionString</key><string>$VER_NUM</string>
    <key>CFBundlePackageType</key>       <string>APPL</string>
    <key>CFBundleExecutable</key>        <string>rfshare</string>
    <key>CFBundleIconFile</key>          <string>$ICON_REF</string>
    <key>NSHumanReadableCopyright</key>  <string>Copyright © 2025 Imrany</string>
    <key>NSHighResolutionCapable</key>   <true/>
    <key>LSMinimumSystemVersion</key>    <string>10.14</string>
</dict></plist>
PLIST

        rm -rf /Applications/rfshare.app
        cp -R "$APP_BUNDLE" /Applications/rfshare.app
        say ".app bundle  →  /Applications/rfshare.app"
    fi

    # Always also install CLI binary so 'rfshare' works in Terminal
    setup_sudo
    $SUDO mkdir -p "$BIN_DIR"
    $SUDO install -m755 /Applications/rfshare.app/Contents/MacOS/rfshare "$BIN_DIR/rfshare"
    say "CLI binary  →  $BIN_DIR/rfshare"

    # Register with Launch Services (Spotlight / Finder)
    LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    [[ -x "$LSREG" ]] && "$LSREG" -f /Applications/rfshare.app 2>/dev/null || true

fi   # end macOS

# ── PATH hint ─────────────────────────────────────────────────────────────────
if ! command -v rfshare &>/dev/null 2>&1; then
    echo ""
    warn "$BIN_DIR is not in your \$PATH."
    warn "Add this to your shell profile (~/.bashrc / ~/.zshrc):"
    warn "    export PATH=\"\$PATH:$BIN_DIR\""
fi

# ── done ─────────────────────────────────────────────────────────────────────
echo ""
printf "${GREEN}  ✓ rfshare ${VERSION} installed${RESET}\n"
echo ""
printf "  ${CYAN}Run:${RESET}       rfshare\n"
[[ "$PLATFORM" == "macos" ]] && printf "  ${CYAN}Or open:${RESET}   /Applications/rfshare.app  (Finder / Launchpad)\n"
printf "  ${CYAN}Uninstall:${RESET} curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | bash -s -- --uninstall\n"
echo ""
