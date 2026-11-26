# ClamAV Local Setup Guide for PIXELTRUTH

PIXELTRUTH uses **ClamAV** (`clamscan`) for local-only, offline-capable malware scanning. ClamAV is free and open-source software ([https://www.clamav.net/](https://www.clamav.net/), [https://docs.clamav.net/](https://docs.clamav.net/)).

PIXELTRUTH never installs antivirus binaries automatically and continues operating normally for metadata and forensic inspection if ClamAV is not installed.

---

## 1. Intel macOS Installation

Homebrew is **not** required. Choose any official or package-manager installation method below.

### Option A — Official ClamAV macOS Installer (No Homebrew Required)
1. Download the official macOS `.pkg` installer (or Intel `x86_64` archive) from [https://www.clamav.net/downloads](https://www.clamav.net/downloads).
2. Open the `.pkg` installer and follow the macOS installation prompts (typically installs into `/usr/local/clamav` or `/usr/local/bin`).
3. Verify the installation in Terminal:
   ```zsh
   /usr/local/bin/clamscan --version
   ```
   (or `/usr/local/clamav/bin/clamscan --version` depending on your installer).

### Option B — MacPorts (No Homebrew Required)
```zsh
sudo port install clamav
```

### Option C — Homebrew (Optional)
```zsh
brew install clamav
```

### Updating Virus Signatures on macOS
Before scanning, download the official signature database (`main.cvd`, `daily.cvd`, `bytecode.cvd`):
1. If needed, copy the sample `freshclam.conf.sample` to `freshclam.conf` (removing the `Example` line as documented at [https://docs.clamav.net/](https://docs.clamav.net/)).
2. Run:
   ```zsh
   freshclam
   ```
3. Confirm signatures are loaded:
   ```zsh
   clamscan --version
   ```

---

## 2. Windows Installation

### Option A — Official ClamAV Windows Installer (Recommended)
1. Download the official Windows `.msi` or `.zip` release (`win64` / `x64`) from [https://www.clamav.net/downloads](https://www.clamav.net/downloads).
2. Run the `.msi` installer (default location: `C:\Program Files\ClamAV`).
3. Configure `freshclam.conf` inside `C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample`:
   - Copy it to `C:\Program Files\ClamAV\freshclam.conf`.
   - Comment out or remove the line containing `Example`.
4. Open Command Prompt or PowerShell as Administrator and download signatures:
   ```powershell
   "C:\Program Files\ClamAV\freshclam.exe"
   ```
5. Verify installation:
   ```powershell
   "C:\Program Files\ClamAV\clamscan.exe" --version
   ```

---

## 3. Custom Executable or Database Paths (Optional)

PIXELTRUTH automatically searches `PATH` and standard macOS/Windows installation locations. If you installed ClamAV in a custom directory, set these environment variables before launching PIXELTRUTH:

- `PIXELTRUTH_CLAMSCAN_PATH` — Full path to `clamscan` (or `clamscan.exe` on Windows).
- `PIXELTRUTH_CLAMAV_DB_DIR` — Full path to the directory containing `daily.cvd`/`daily.cld`, `main.cvd`/`main.cld`, and `bytecode.cvd`/`bytecode.cld`.

### Example (macOS)
```zsh
export PIXELTRUTH_CLAMSCAN_PATH="/usr/local/clamav/bin/clamscan"
export PIXELTRUTH_CLAMAV_DB_DIR="/usr/local/clamav/share/clamav"
```

### Example (Windows PowerShell)
```powershell
$env:PIXELTRUTH_CLAMSCAN_PATH = "C:\Tools\ClamAV\clamscan.exe"
$env:PIXELTRUTH_CLAMAV_DB_DIR = "C:\Tools\ClamAV\database"
```

---

## 4. Database Freshness & Offline Use

- Once signatures are downloaded with `freshclam`, PIXELTRUTH runs `clamscan` completely offline with zero external API calls.
- If the signature database is older than 7 days, PIXELTRUTH flags the scan as **incomplete / outdated** and reminds you to run `freshclam` manually. PIXELTRUTH never updates signatures or modifies system files automatically.
