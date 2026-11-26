# PIXELTRUTH

PIXELTRUTH is planned as a local-first image metadata inspection and digital forensics studio. It will present measured observations, explain methods and limitations, and avoid claiming that limited checks prove an image authentic or manipulated.

## Project status

Phase 1 is complete. The app accepts one image per session, validates content and decoding, reports image properties and common EXIF fields, and calculates SHA-256. Metadata integrity findings, GPS disclosure, comparison, ELA, histograms, assessment, and PDF reports remain for later authorized phases. XMP/IPTC parsing is explicitly reported as unsupported in this phase.

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

The current app supports the Phase 1 inspection workflow only.

## Project structure

```text
app.py
pages/             Streamlit page entry points (to be added in authorized phases)
core/              Phase 1 image properties, metadata, hashing, models, and orchestration
components/         Reusable interface components (not implemented)
utils/              Shared validation and formatting utilities
tests/              Phase 1 validation, property, metadata, hash, and orchestration tests
assets/             Local interface assets
sample_images/      Synthetic, non-sensitive test images only
```

## Git branches

- `main` — stable project foundation
- `develop` — integration branch

No remote is configured. Do not add private images, GPS-sensitive samples, secrets, virtual environments, caches, or generated reports to Git.

## License

The project license has not been selected. See `LICENSE`; choose a license before redistributing the project.
