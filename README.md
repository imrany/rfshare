# RFSHARE

**rfshare** is a modern, encrypted peer-to-peer file sharing application built with Rust and the egui framework. It enables fast, secure file transfers between devices on the same network or across the internet using a relay server. The app runs in the background with system tray support, like Telegram Desktop.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)](https://github.com/imrany/rfshare)

## ✨ Features

### Core Features
- **🔒 End-to-End Encrypted Transfers** - X25519 key exchange + AES-256-GCM encryption for all transfers
- **🌐 Local Network Discovery** - Automatic device discovery via UDP broadcast on port 44444
- **📁 Folder Synchronization** - Automatically sync folders with selected devices (Pro feature)
- **🌍 Remote File Sharing** - Share files across the internet via relay server (Pro feature)
- **📊 Transfer History** - Complete log of all sent and received files with search functionality
- **🎨 Modern UI** - Clean interface with dark/light theme support
- **🖱️ Drag & Drop** - Simply drag files into the app to add them to the queue
- **📱 Cross-Platform** - Works on Windows, macOS, and Linux

### Technical Highlights
- **Resumable Transfers** - Interrupted transfers can be resumed from where they stopped
- **Real-time Progress** - Visual progress bars for all active transfers
- **Desktop Notifications** - System notifications when files are received
- **Smart Sync** - Only syncs files that have changed (uses modification timestamps)
- **Network Monitoring** - Automatically detects IP changes and reconnects
- **No Cloud Storage** - Files never leave your devices or relay server (relay only pipes encrypted data)

## 📸 Demonstration

<table>
   <tr>
    <td align="center"><b>1. Scanning for devices</b></td>
    <td align="center"><b>2. Sending a file</b></td>
   </tr>
   <tr>
    <td align="center"><img src="./assets/rfshare_scan.png" alt="Scan Image" width="400" height="500"/></td>
    <td align="center"><img src="./assets/rfshare_send.png" alt="Send Image" width="400" height="500"/></td>
   </tr>
   <tr>
    <td align="center"><b>3. Receiving a file</b></td>
    <td align="center"><b>4. History tab</b></td>
   </tr>
   <tr>
    <td align="center"><img src="./assets/rfshare_receive.png" alt="Received Image" width="400" height="500"/></td>
    <td align="center"><img src="./assets/rfshare_received_tab.png" alt="History Tab Image" width="400" height="500"/></td>
   </tr>
   <tr>
    <td align="center"><b>5. Sync a folder (Pro feature)</b></td>
   </tr>
   <tr>
    <td align="center"><img src="./assets/rfshare_sync.png" alt="Sync Image" width="400" height="500"/></td>
   </tr>
</table>

## 🚀 Quick Start

### Installation

#### 🐧 Linux
```bash
curl -fsSL https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.sh | bash
```

Installs the `.deb` package on Debian/Ubuntu (includes desktop entry and icon).  
Falls back to a bare binary on other distros.

> **Note for GNOME users**: Tray icons are hidden by default. Install the AppIndicator extension:
 ```bash

sudo apt install gnome-shell-extension-manager
sudo apt install gnome-shell-extension-appindicator
 # Then enable it via Extension Manager or gnome-extensions
## extension-manager
# gnome-extensions list
```

> **User-only install (no sudo):**
> ```bash
> PREFIX=$HOME/.local curl -fsSL https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.sh | bash
> ```

#### 🍎 macOS
```bash
curl -fsSL https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.sh | bash
```

Installs the `.dmg` when available, otherwise builds a `.app` bundle and copies it to `/Applications`.  
Also installs the `rfshare` CLI to `/usr/local/bin`.

#### 🪟 Windows
Paste this into **PowerShell** (no admin needed):

```powershell
irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1 | iex
```

Installs the `.msi` when available, otherwise extracts the portable `.exe`.  
Adds rfshare to your PATH, creates a Start Menu shortcut, and registers it in Add/Remove Programs.

### Pin a specific version

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.sh | bash -s -- --version v0.15.0
```

**Windows**
```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1))) -Version v0.15.0
```

### Uninstall

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.sh | bash -s -- --uninstall
```

**Windows**
```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1))) -Uninstall
```

Or: **Settings → Apps → rfshare → Uninstall**

### Manual download

All binaries and installers are on the [Releases](https://github.com/imrany/rfshare/releases/latest) page.

| Platform | Installer | Portable |
|----------|-----------|---------|
| 🐧 Linux | `rfshare-vX.X.X-linux-x86_64.deb` | `rfshare-linux-vX.X.X.tar.gz` |
| 🍎 macOS | `rfshare-vX.X.X-macos.dmg` | `rfshare-macos-vX.X.X.tar.gz` |
| 🪟 Windows | `rfshare-vX.X.X-windows-x64.msi` | `rfshare-windows-vX.X.X.zip` |

Each file has a matching `.sha256` checksum.

### Basic Usage

1. **Start the app** - It automatically starts listening for incoming files
2. **Send files locally**:
   - Click the **Scan** tab
   - Click **Scan** to discover devices on your network
   - Select a device from the list
   - Go to **Send** tab
   - Drag and drop files or click **Browse**
   - Click **Send**

3. **Receive files**:
   - Files are automatically saved to your Downloads folder
   - Desktop notifications appear when transfers complete
   - View received files in the **History** tab

4. **Remote sharing (Pro)**:
   - **Receiver**: Click **Scan** → **Remote** → **Go Online** → Share the code
   - **Sender**: Click **Scan** → **Remote** → Enter code → **Connect** → Send files

5. **Folder sync (Pro)**:
   - Select a device
   - Go to **Sync** tab
   - Click **Set folder to watch**
   - Click **Start watching**
   - Any new files in the folder auto-sync to the selected device

## 🔧 Architecture

### Network Protocols

| Port | Protocol | Purpose |
|------|----------|---------|
| 44444 | UDP | Device discovery broadcast |
| 44445 | TCP | Encrypted file transfer |

### Security Stack

```
┌─────────────────────────────────────────────┐
│           Application Layer                 │
├─────────────────────────────────────────────┤
│         AES-256-GCM (Authenticated)         │
├─────────────────────────────────────────────┤
│    X25519 ECDH (Key Exchange)               │
├─────────────────────────────────────────────┤
│    TCP Socket (Direct or Relay)             │
└─────────────────────────────────────────────┘
```

### Transfer Flow

1. **Discovery** - UDP broadcast finds peers on the network
2. **Key Exchange** - X25519 ephemeral key exchange for perfect forward secrecy
3. **Encryption** - AES-256-GCM encrypts all file data
4. **Transfer** - Chunked transfer with resume capability
5. **Verification** - GCM authentication ensures integrity

## 📊 Features Comparison

| Feature | Free | Pro |
|---------|------|-----|
| Local Network Transfer | ✅ | ✅ |
| Direct File Transfer | ✅ | ✅ |
| Encrypted Transfer | ✅ | ✅ |
| Transfer History | ✅ | ✅ |
| Drag & Drop | ✅ | ✅ |
| Desktop Notifications | ✅ | ✅ |
| **Remote Transfer** | ❌ | ✅ |
| **Folder Sync** | ❌ | ✅ |
| **Remote Folder Sync** | ❌ | ✅ |
| **Unlimited Devices** | ❌ | ✅ |
| **Organization License** | ❌ | ✅ |

## 💰 Pro License

### Activate Pro

1. Go to **Settings** → **License**
2. Enter your license key
3. Click **Activate**

**Pro License Key:**
```bash
29714-5B90A-54A40-254F4-B7B1C
```

### Get a License

Support development and get Pro features:
- [GitHub Sponsors](https://github.com/sponsors/imrany)
- Includes remote sharing and folder sync
- Helps fund continued development

## 🏗️ Building from Source

### Prerequisites
- Rust 1.70 or later
- Cargo package manager
- **Linux**: GTK development libraries (for system tray)
  ```bash
  # Ubuntu/Debian
  sudo apt install libgtk-3-dev
  # Fedora
  sudo dnf install gtk3-devel
  # Arch
  sudo pacman -S gtk3
  ```

### Build
```bash
# Clone the repository
git clone https://github.com/imrany/rfshare.git
cd rfshare

# Build in release mode
cargo build --release

# Run the application
./target/release/rfshare
```

## 📁 File Locations

### Configuration
- **Windows**: `%APPDATA%\rfshare\`
- **Linux**: `~/.config/rfshare/`
- **macOS**: `~/Library/Application Support/rfshare/`

### Files
- `prefs.json` - User preferences and settings
- `history.csv` - Transfer history log
- `license` - Pro license information

## 🔐 Security Details

### Key Exchange Process
1. Both peers generate ephemeral X25519 keypairs
2. Public keys are exchanged over the TCP connection
3. Shared secret is derived using Diffie-Hellman
4. AES-256-GCM key is derived using SHA-256 with app-specific salt
5. All subsequent communication uses the derived key

### Encryption Features
- **Perfect Forward Secrecy** - Session keys are not stored
- **Authenticated Encryption** - GCM mode provides integrity checking
- **Per-Connection Keys** - Unique keys for each transfer
- **No Key Reuse** - Fresh keys for every session

## 🎯 Use Cases

1. **Home Network Sharing** - Share files between computers on same Wi-Fi
2. **Remote Work** - Send files to colleagues across the internet
3. **Backup Sync** - Automatically sync folders to another computer
4. **Quick File Transfer** - Fast, no-server transfers between devices
5. **Secure Sharing** - Encrypted transfers for sensitive files

## 🐛 Troubleshooting

### Common Issues

**Q: Can't see devices on the network**
- Ensure both devices are on the same network/subnet
- Check if firewall is blocking UDP port 44444
- Try running as administrator (Windows) or with sudo (Linux)

**Q: Remote connection fails**
- Verify internet connectivity
- Ensure the relay server is accessible
- Check if port 443 is open (for HTTPS) or port 80 (for HTTP)

**Q: Transfer is slow**
- Direct transfers are limited by your network speed
- Remote transfers go through the relay server
- Try using a wired connection for large files

**Q: Can't find the app after installation**
- **Windows**: Start Menu → rfshare
- **macOS**: Applications folder → rfshare.app
- **Linux**: Run `rfshare` in terminal or find in application menu

**Q: Folder sync isn't working**
- Ensure you have a Pro license activated
- Check that the selected device is online
- Verify the folder exists and is readable
- Look at the Activity log for errors

## 🤝 Contributing

Contributions are welcome! Areas where help is needed:

- **UI/UX improvements** - Enhance the egui interface
- **Performance optimizations** - Faster transfers, better chunking
- **Additional protocols** - WebRTC, QUIC support
- **Mobile versions** - iOS/Android ports
- **Documentation** - Improve this README and code comments

### Development Setup
```bash
# Clone and build
git clone https://github.com/imrany/rfshare.git
cd rfshare
cargo build

# Run with logging
RUST_LOG=debug cargo run

# Run tests
cargo test
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [egui](https://github.com/emilk/egui) - Immediate mode GUI library
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic implementations
- [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) - X25519 implementation
- [egui_material_icons](https://crates.io/crates/egui_material_icons) - Material Design icons

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/imrany/rfshare/issues)
- **Discussions**: [GitHub Discussions](https://github.com/imrany/rfshare/discussions)
