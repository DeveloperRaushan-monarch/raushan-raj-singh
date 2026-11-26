# ExifTool Setup & Licensing for PIXELTRUTH

PIXELTRUTH uses **ExifTool** as its primary broad metadata extraction engine when available, with automatic fallback to PIXELTRUTH's built-in Python container, EXIF, XMP, IPTC, and ICC parsers.

## Licensing & Redistribution

- ExifTool is created by Phil Harvey and is dual-licensed under the **Perl Artistic License** and the **GNU GPL v1+**.
- Because ExifTool is an external CLI tool invoked via Python `subprocess` (`shell=False`), PIXELTRUTH does not statically link against ExifTool.
- If you choose to bundle ExifTool with a distribution of PIXELTRUTH, include ExifTool's original license notice and copyright attribution in your distribution.

## Discovery Order (No Homebrew Required)

PIXELTRUTH searches for ExifTool in the following order:

1. Explicit `configured_path` passed to `discover_exiftool()`.
2. `PIXELTRUTH_EXIFTOOL_PATH` environment variable.
3. System `PATH` (`shutil.which("exiftool")`).
4. Bundled binary inside the project:
   - macOS: `bin/macos/exiftool`
   - Windows: `bin/windows/exiftool.exe`
5. Standard platform install locations:
   - macOS: `/usr/local/bin/exiftool`, `/opt/homebrew/bin/exiftool`, `/usr/bin/exiftool`
   - Windows: `C:\Program Files\ExifTool\exiftool.exe`, `C:\ExifTool\exiftool.exe`

## Installing on Intel / Apple Silicon macOS

- Download the official macOS `.dmg` or `.tar.gz` from `https://exiftool.org/` (no Homebrew required), or install via package manager.
- Verify in Terminal:
  ```bash
  exiftool -ver
  ```
- Or point PIXELTRUTH directly to a standalone binary:
  ```bash
  export PIXELTRUTH_EXIFTOOL_PATH=/path/to/exiftool
  ```

## Installing on Windows

- Download the Windows executable zip from `https://exiftool.org/`.
- Extract and rename `exiftool(-k).exe` to `exiftool.exe` in `C:\Program Files\ExifTool\` (or add its folder to `PATH`).
- Or set `PIXELTRUTH_EXIFTOOL_PATH=C:\path\to\exiftool.exe`.
