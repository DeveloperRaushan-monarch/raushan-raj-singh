# PIXELTRUTH

PIXELTRUTH is a local-first image metadata inspection and digital forensics studio. It presents measured observations, explains methods and limitations, and avoids claiming that limited checks prove an image authentic or manipulated.

## Project status

Phases 1 and 2 are complete, with XMP/IPTC metadata extraction added as a Phase 2 metadata-support extension. The app validates uploaded images and their decodability, reports image properties and EXIF, XMP, and IPTC metadata with explicit statuses, and calculates SHA-256 from the original file bytes. It presents structured metadata validity and consistency findings; missing metadata by itself is informational and does not indicate manipulation. GPS details stay hidden until explicitly requested and can be cleared from the session. Two images can be compared by properties, hashes, and metadata, with a bounded sampled RGB difference indicator when the images can be compared; that indicator is descriptive and is not an authenticity score.

XMP extraction supports JPEG APP1 packets, PNG `XML:com.adobe.xmp` text chunks, WebP `XMP ` RIFF chunks, and TIFF tag 700. IPTC extraction supports IPTC-IIM data in JPEG Photoshop APP13 `8BIM` resource 0x0404 and TIFF tag 33723. Only common creator, date, description, software, rights, headline, caption, keyword, byline, copyright, and location fields are displayed. Other XMP/IPTC storage locations are not parsed, and may appear as missing when they cannot be detected; formats outside the supported list are marked unsupported. JPEG Extended XMP is detected but not reassembled. XMP packets with DTD/entity declarations are rejected; malformed packets are reported, and absence is not evidence of manipulation. ELA, histograms, assessment, and PDF reports remain for later authorized phases.

Read the project specifications before starting development:

- `prd.in` — product requirements
- `architecture.in` — proposed software boundaries and data flow
- `rule.in` — engineering, privacy, and phase rules
- `phases.in` — phase plan and current status
- `design.in` — UI/UX specification
- `memory.in` — durable project decisions and environment notes
- `requirements.txt` — Python dependency list

## Requirements

- Python 3.11
- Git
- macOS or Windows

## Set up a virtual environment

The current workspace already has a local `.venv`. For a fresh checkout, create one with Python 3.11.

### macOS

```sh
python3.11 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

Install packages from `requirements.txt` only after the project owner authorizes dependency installation:

```sh
python -m pip install -r requirements.txt
```

## Run the foundation app

After dependencies are installed and the environment is active:

```sh
streamlit run app.py
```

The current app supports the completed Phase 1 inspection and Phase 2 metadata intelligence workflows.

## Project structure

```text
app.py
pages/             Streamlit page entry points (to be added in authorized phases)
core/              Image inspection, metadata integrity, GPS, comparison, and orchestration
components/         Reusable interface components (not implemented)
utils/              Shared validation and formatting utilities
tests/              Validation, metadata, GPS privacy, comparison, and core tests
assets/             Local interface assets
sample_images/      Synthetic, non-sensitive test images only
```

## Git branches

- `main` — stable project foundation
- `develop` — integration branch

No remote is configured. Do not add private images, GPS-sensitive samples, secrets, virtual environments, caches, or generated reports to Git.

## License

The project license has not been selected. See `LICENSE`; choose a license before redistributing the project.
