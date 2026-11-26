# PIXELTRUTH

PIXELTRUTH is a local-first image metadata inspection and digital forensics studio. It presents measured observations, explains methods and limitations, and avoids claiming that limited checks prove an image authentic or manipulated.

## Project status

Phases 1 and 2 are complete, with XMP/IPTC metadata extraction added as a Phase 2 metadata-support extension. The app validates uploaded images and their decodability, reports image properties and EXIF, XMP, and IPTC metadata with explicit statuses, and calculates SHA-256 from the original file bytes. It presents structured metadata validity and consistency findings; missing metadata by itself is informational and does not indicate manipulation. GPS details stay hidden until explicitly requested and can be cleared from the session. Two images can be compared by properties, hashes, and metadata, with a bounded sampled RGB difference indicator when the images can be compared; that indicator is descriptive and is not an authenticity score.

XMP extraction supports JPEG APP1 packets, PNG `XML:com.adobe.xmp` text chunks, WebP `XMP ` RIFF chunks, and TIFF tag 700. IPTC extraction supports IPTC-IIM data in JPEG Photoshop APP13 `8BIM` resource 0x0404 and TIFF tag 33723. Only common creator, date, description, software, rights, headline, caption, keyword, byline, copyright, and location fields are displayed. Other XMP/IPTC storage locations are not parsed, and may appear as missing when they cannot be detected; formats outside the supported list are marked unsupported. JPEG Extended XMP is detected but not reassembled; if a standard packet is also present, its available fields are shown with that limitation. XMP packets with DTD/entity declarations are rejected; malformed packets are reported, and absence is not evidence of manipulation.

Phase 3.1 adds opt-in JPEG-only Error Level Analysis (ELA): a single recompression, adjustable quality and residual scale, and an original/residual view. ELA is limited to 20 megapixels and is a descriptive indicator, not proof of editing. Phase 3.2 adds opt-in RGB intensity histograms for supported images, including a pooled channel distribution and separate monochrome channel views. Histograms are descriptive and are not authenticity tests. Phase 3.3 adds the deterministic three-state evidence assessment engine (`PT-EA/1.0.0`) with `LOW CONCERN`, `NEEDS REVIEW`, and `INSUFFICIENT EVIDENCE` outcomes, full rule/evaluation provenance, and an Evidence Assessment tab in `app.py`. Phase 4 adds monochrome A4 PDF forensic report generation (`core/report.py`) and the `"Forensic Reports"` tab in `app.py`, with GPS coordinates excluded and local paths redacted by default. Phase 5 integration and quality assurance is complete across all supported formats, privacy defaults, and resource limits.

Phases 6A–6D add the comprehensive 7-stage metadata inventory (`core/metadata_models.py`, `core/metadata_inventory.py`) and dynamic Metadata Explorer UI (`server.py` + `frontend/`) with search, filters, MakerNotes raw preservation, ICC support, and strict GPS exclusion. Local ClamAV malware scanning (Phases B–D: `core/malware_models.py`, `core/malware_scanner.py`, [docs/CLAMAV_SETUP.md](docs/CLAMAV_SETUP.md)) scans validated uploads locally via `clamscan` (`shell=False`, no external uploads) and displays `NO_KNOWN_THREAT`, exact `MALWARE_DETECTED` signature names, or `SCAN_INCOMPLETE` inside the existing Image Analysis screen, completely separate from `PT-EA/1.0.0`. Phase E adds non-GPS JSON/CSV metadata exports (`GET /api/metadata/export`) with spreadsheet formula sanitization and optional ClamAV malware scan reporting in A4 PDF reports (`ReportOptions.include_malware_scan`).

Read the project specifications before starting development:

- `prd.in` — product requirements
- `architecture.in` — proposed software boundaries and data flow
- `rule.in` — engineering, privacy, and phase rules
- `phases.in` — phase plan and current status
- `assessment_spec.in` — approved Phase 3.3 evidence-assessment specification (`PT-EA/1.0.0`)
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

## Run the application

After dependencies are installed and the environment is active:

**Recommended — Stitch Monochrome Web Workspace (`server.py` + `frontend/`):**

```sh
.venv/bin/python server.py
```

Then open `http://127.0.0.1:8501` in your browser.

**Legacy Streamlit interface (`app.py`):**

```sh
.venv/bin/streamlit run app.py
```

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
