# PIXELTRUTH — ANTIGRAVITY PROJECT HANDOVER

**Purpose:** Transfer the existing PIXELTRUTH project from Codex to Google Antigravity for inspection and future development.

**Project status:** Phase 3.2 reported complete. Phase 3.3 and Phase 4 are not started. The assessment specification is a draft and is not approved for implementation.

---

## 1. Project overview

PIXELTRUTH is a local-first image metadata inspection and digital forensics education project for a Class 12 Computer Science science exhibition.

The application helps users inspect image properties, metadata, metadata consistency, and selected visual indicators. It must not claim to prove that an image is genuine or fake.

### Core assessment labels

- LOW CONCERN
- NEEDS REVIEW
- INSUFFICIENT EVIDENCE

### Scientific principles

- Missing metadata does not prove that metadata was deleted or manipulated.
- Metadata being present does not prove that an image is authentic.
- An editing-software field alone must not trigger suspicion.
- Unsupported or unavailable checks must not be treated as successful checks.
- Do not generate fake authenticity percentages, probabilities, or confidence scores.
- Clearly separate observations, interpretations, limitations, and recommended checks.
- GPS information must remain hidden unless the user explicitly requests it.
- GPS must be excluded from reports by default.
- ELA and RGB histograms are descriptive indicators, not proof of editing.

---

## 2. Technology stack

The project has used or planned the following:

- Python 3.11
- Streamlit
- Pillow
- ExifRead
- OpenCV Headless
- NumPy
- Pandas
- Plotly
- ReportLab
- Pytest
- Git and GitHub

Do not install, upgrade, remove, or change dependencies without explicit approval.

Use `python3` or the project's virtual-environment interpreter. The shell command `python` may not be available on the user's Mac.

---

## 3. User's development environment

Historically reported environment:

- Intel MacBook Pro
- macOS
- Python 3.11.0
- Project path: `/Users/raushan/Desktop/pixeltruth`
- Shell: zsh
- Homebrew is unavailable or unreliable; do not make it a prerequisite.

The project is intended to run locally on both the user's Mac and a collaborator's Windows PC.

The actual current workspace must be inspected. Do not assume that historical paths or repository state are still accurate.

---

## 4. Expected project structure

The originally planned structure was:

```text
pixeltruth/
├── app.py
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── prd.in
├── architecture.in
├── rule.in
├── phases.in
├── design.in
├── memory.in
├── assessment_spec.in
├── assets/
├── components/
├── core/
├── pages/
├── sample_images/
├── tests/
└── utils/
```

This is an expected structure, not confirmation of the current filesystem.

The `.in` document suffixes are intentional. Do not rename them.

---

## 5. Historical implementation status

The following describes work reported in the Codex conversation. Verify it against the actual repository before relying on it.

### Phase 0 — Foundation

Reported work:

- Project scaffold and Streamlit setup screen.
- README, .gitignore, and LICENSE files.
- Local Git repository.
- `main` and `develop` branches.
- Initial commit: `4438cfc`.
- Python 3.11.0 available.
- No dependencies installed during the original Phase 0 checkpoint.

### Phase 1 — Image inspection

Reported features:

- Content-based image validation and decoding.
- Upload, pixel, and frame limits.
- Image properties and preview.
- Common EXIF extraction.
- SHA-256 hash from original image bytes.
- EXIF orientation validation.
- PNG, WEBP, and TIFF metadata handling.
- Palette bit depth reported as unavailable when it cannot be reliably determined.
- Animated GIF transparency detection.
- Invalid numeric EXIF orientation values rejected.

Historical verification included 29 tests, dependency checks, AppTest checks, and Streamlit health checks.

Known commits:

- `ca60089` — Improve image metadata and bit depth accuracy
- `9c8a080` — Fix EXIF orientation validation
- `92283a7` — Complete Phase 1: image inspection workflow

### Phase 2 — Metadata forensics

Reported features:

- Metadata integrity and consistency findings.
- On-demand GPS reveal and clear.
- Two-image comparison.
- Bounded sampled pixel-difference indicator.
- XMP and IPTC extraction.

Reported XMP support:

- JPEG APP1
- PNG `XML:com.adobe.xmp` text chunks
- WebP `XMP ` RIFF chunks
- TIFF tag 700

Reported IPTC support:

- JPEG Photoshop APP13 resource `0x0404`
- TIFF tag 33723

Fields included creator, date, description, software, rights, headline, caption, keywords, byline, copyright, and location.

Security and limitations:

- XML parser rejects DTD/entity declarations.
- XML packet limit: 1 MB.
- JPEG Extended XMP is detected but not reassembled; the standard packet is retained with a limitation note.
- Other formats or storage locations may not be parsed.
- Unrecognised storage locations may appear to have missing metadata.
- GPS stays hidden until explicit reveal.

Historical tests included 65 full-suite tests and AppTest interaction coverage.

Known commits:

- `04746d7` — Complete Phase 2: metadata forensics and comparison
- `6d3ac6e` — Implement XMP and IPTC metadata extraction
- `3bea11b` — Fix Extended XMP handling and update documentation
- `5c00cff` — Add Streamlit AppTest interaction coverage

### Phase 3.1 — JPEG Error Level Analysis

Reported features:

- Opt-in JPEG-only ELA.
- JPEG quality and residual scale controls.
- Original and residual views.
- Measurements and limitations.
- 20-megapixel cap.
- EXIF orientation applied consistently.
- Boolean parameters rejected for `max_pixels`, `quality`, and `error_scale`.

Reported tests covered grayscale JPEG, exact pixel limit, one pixel over the limit, boolean parameters, and asymmetric orientation images.

Historical verification:

- ELA tests: 16 passed.
- AppTest: 8 passed.
- Full suite: 82 passed.
- Dependency and diff checks passed.
- No dependencies added.

Known commit:

- `1c04952` — Complete Phase 3.1: JPEG error level analysis

### Phase 3.2 — RGB histograms

Reported features:

- Opt-in pooled RGB distribution.
- Separate monochrome channel charts.
- Bounded tiled processing.
- Transparency alpha discarded during RGB conversion, documented.
- Embedded colour profiles not applied, documented.
- Results cleared when the upload changes or is removed.
- Plotly was already in requirements.

#### Multi-page TIFF correction

An earlier issue used first-frame dimensions for all TIFF pages. This could produce inaccurate pixel counts and bypass per-page or cumulative resource limits.

Reported corrections:

- Inspect each page's dimensions independently.
- Enforce per-page and cumulative pixel limits using actual page dimensions.
- Reject excess frame count before decoding.
- Process each frame using its own dimensions.
- Count actual pixels across processed frames.
- Preserve bounded tile processing.
- Test differently sized TIFF pages, accurate pixel counts, per-page and cumulative limit failures, and oversized later pages rejected before histogram processing.

Reported compatibility detail:

- `ValidatedImage.width` and `height` still describe the first page.
- `frame_dimensions` provides per-page sizes for histogram processing.

Reported latest verification:

- Histogram tests: 8 passed.
- AppTest: 10 passed.
- Full suite: 92 passed.
- Dependency check passed.
- `git diff --check` passed.
- No dependencies added.
- Browser-rendered Plotly appearance was not visually verified.
- AppTest does not verify actual browser tab switching.

Known commit:

- `1c5dcc0` — Complete Phase 3.2: RGB image histograms

---

## 6. Phase 3.3 — Assessment specification

**NOT STARTED. DO NOT IMPLEMENT WITHOUT EXPLICIT USER APPROVAL.**

The file `assessment_spec.in` is a draft. It is not an approved implementation specification.

Proposed outcomes:

- LOW CONCERN
- NEEDS REVIEW
- INSUFFICIENT EVIDENCE

Candidate deterministic review triggers include:

- Invalid metadata value that fails a documented format or range validation.
- Comparable EXIF timestamps both present and parseable but different.
- EXIF pixel dimensions disagree with decoded dimensions after documented orientation allowances.

These are candidates only, not approved rules.

### Observations that must not independently trigger NEEDS REVIEW

- Missing metadata.
- Unsupported metadata.
- Unavailable, failed, or unrun checks.
- Software tag alone.
- Filename extension mismatch alone.
- Hash or similarity alone.
- ELA residual patterns.
- RGB histogram shapes.
- Ordinary properties without an explicitly registered comparison rule.

### Issues requiring resolution before implementation

1. Separate `rule_id` from `finding_id`.
2. Every finding must reference a registered rule ID and an originating check that verifies the evaluated rule.
3. Define substantive coverage states:
   - `EVALUATED_WITH_FINDING`
   - `EVALUATED_WITHOUT_FINDING`
   - `NOT_EVALUABLE`
4. Clarify applicability versus completion, including not applicable versus unsupported.
5. Define rule registry applicability and coverage criticality by supported format.
6. Explain timestamp disagreement rationale and use cautious wording.
7. Define exact EXIF dimension comparison, orientation values 1–8, and missing or partial tags.
8. Define rule-set version compatibility.
9. Define deterministic duplicate and conflict handling.
10. Define allowed relevance values.
11. Handle null, empty, and malformed values.
12. Preserve original observed values and source provenance.
13. Disclose which rules actually ran.
14. Define noncritical unavailable checks.
15. Ensure repeatability: same input and version must produce identical output.

### Suggested assessment test matrix

- Missing metadata only → INSUFFICIENT EVIDENCE.
- Valid metadata and sufficient substantive checks with no findings → LOW CONCERN, only if coverage requirements are satisfied.
- Registered review finding → NEEDS REVIEW.
- Review finding plus reassuring observations → NEEDS REVIEW.
- Review finding plus unavailable checks → NEEDS REVIEW with gaps disclosed.
- ELA or histogram alone → INSUFFICIENT EVIDENCE.
- SHA-256 alone → INSUFFICIENT EVIDENCE.
- Unknown review rule → INSUFFICIENT EVIDENCE.
- Contradictory states → INSUFFICIENT EVIDENCE.
- Conflicting duplicate finding ID → INSUFFICIENT EVIDENCE.
- Critical check unavailable → INSUFFICIENT EVIDENCE.
- Noncritical unavailable check with sufficient coverage → LOW CONCERN may be allowed with disclosure.
- Same input and version repeated → identical result.

Do not change the phase status or implement any assessment logic without approval.

---

## 7. Phase 4 — Reporting

**NOT STARTED. DO NOT IMPLEMENT WITHOUT EXPLICIT USER APPROVAL.**

PDF reports and reporting functionality must not be treated as completed.

GPS must be excluded from reports by default. Any future reporting implementation must clearly disclose limitations and the checks actually performed.

---

## 8. Google Stitch UI/UX exports

A previous Codex inspection reported a sibling export folder:

`/Users/raushan/Desktop/stitch_pixeltruth_monochrome_forensic_workspace`

It reportedly contained:

- `pixeltruth_design_system.md`
- Eight Stitch HTML screen exports.

No screenshots were found in that inspection. The repository's `design.in` could not be located in that workspace, so a direct comparison was not possible.

Reported visual design:

- Desktop-first layout.
- 256px dark sidebar.
- Black main canvas.
- 1280px maximum content width.
- Responsive sidebar menu toggle on narrow screens.
- Columns collapse on smaller screens.
- Monochrome black, charcoal, white, and grey.
- Thin graphite borders.
- No gradients or prominent shadows.
- 4px spacing base, with typical 8, 16, 24, and 32px spacing.
- Inter UI font.
- Source Code Pro for technical values.
- Semantic labels, navigation landmarks, and focus styles.

### Eight exported screens

1. Dashboard — local upload, six module cards, session history.
2. Image Analysis — preview, file properties, SHA-256.
3. Metadata Explorer — grouped disclosures and explicit GPS reveal.
4. Image Comparison — reference and suspect images, comparison table.
5. ELA — quality/error-scale controls, original/result panels, explanations.
6. RGB Histogram — combined and per-channel charts.
7. Forensic Reports — section choices, privacy options, PDF preview.
8. About Project — privacy, geolocation, evidence, visual principles.

### Design concerns

- GPS appears as a separate navigation link and also inside Metadata Explorer. Resolve this duplication in a future design plan.
- Some HTML prototype controls may be visual-only.
- Prototype screens may contain sample values.
- Export HTML reportedly loads Tailwind, fonts, and icons through external CDNs. Do not introduce unnecessary external CDN dependencies into a local-first application without explaining the privacy and availability implications.
- Do not implement screens or controls that the application does not actually support.

The actual Stitch export folder must be inspected before making design decisions.

---

## 9. UI/UX preferences

The user prefers:

- Clean, professional, Apple-like design.
- Monochrome black, white, charcoal, and grey for PIXELTRUTH.
- Clear readable typography.
- Consistent spacing and alignment.
- Practical, understandable navigation.
- Responsive layouts.
- Restrained borders and visual effects.

Avoid:

- 3D elements.
- Neon colours.
- Excessive gradients.
- Glossy effects.
- Cluttered screens.
- Generic stereotypical AI styling.

---

## 10. Historical Git information

Historical commit list:

- `4438cfc` — Initialize PIXELTRUTH project foundation
- `ca60089` — Improve image metadata and bit depth accuracy
- `9c8a080` — Fix EXIF orientation validation
- `92283a7` — Complete Phase 1: image inspection workflow
- `04746d7` — Complete Phase 2: metadata forensics and comparison
- `6d3ac6e` — Implement XMP and IPTC metadata extraction
- `3bea11b` — Fix Extended XMP handling and update documentation
- `5c00cff` — Add Streamlit AppTest interaction coverage
- `1c04952` — Complete Phase 3.1: JPEG error level analysis
- `1c5dcc0` — Complete Phase 3.2: RGB image histograms

The latest reported checkpoint was on branch `develop` with a clean working tree. Verify actual Git history and status; these details are historical, not guaranteed current.

### Git safety rules

- Do not run destructive reset, clean, or restore commands.
- Never discard uncommitted changes.
- Do not use `git add .` automatically.
- Stage only explicitly reviewed files.
- Never commit or push without explicit permission.
- Do not connect or alter GitHub settings without explicit permission.
- Do not let Codex and Antigravity edit the same local repository simultaneously.

---

## 11. Important workspace discrepancy

Historical Codex reports conflict:

- Earlier reports describe a populated `~/Desktop/pixeltruth` repository with Phases 1–3.2.
- A later design inspection reported that `/Users/raushan/Desktop/pixeltruth` was empty in that Codex workspace.
- That inspection found the Stitch export in a sibling folder.

This may reflect different workspace or filesystem mappings.

**Do not guess which report is correct.**

Antigravity must inspect the actual folder selected by the user.

If the folder is empty, stop and report that fact. Do not rebuild the repository, copy sibling exports, initialise Git, or create replacement files unless explicitly instructed.

If populated, compare the actual source, documentation, and Git history with this handover.

---

## 12. Antigravity first task — read-only audit

Before changing anything, inspect the selected project folder.

### Audit checklist

1. Report the exact workspace path.
2. Confirm whether the expected project files are present.
3. Report Git branch, status, recent commits, remotes, modified files, and untracked files.
4. Show the actual directory structure.
5. Inspect the real source code and tests to verify the reported phases.
6. Inspect the Python environment and dependency status without installing anything.
7. Identify missing or conflicting documentation.
8. Inspect the actual Stitch export files, including HTML, CSS, images, and screenshots if present.
9. List the eight screens and identify their components and interactions.
10. Review design tokens, responsiveness, accessibility, and prototype-only controls.
11. Compare the actual design with `design.in` if that file exists.
12. Report discrepancies between the actual repository, this handover, and historical Codex reports.
13. List security, privacy, scientific, and technical limitations.
14. Recommend one next step, but do not execute it.

### Required final audit report

Use these headings:

- Workspace verification
- Repository and Git status
- Actual file structure
- Phase-by-phase verification
- Tests and dependency status
- Documentation audit
- Stitch design audit
- Discrepancies and uncertainties
- Risks and limitations
- Recommended next step

Finish by explicitly confirming:

- No files were modified.
- No packages were installed, upgraded, or removed.
- No Git changes were made.
- Phase 3.3 was not implemented.
- Phase 4 was not implemented.
- No commits or pushes were made.

**Stop after the audit and wait for the user's approval.**

---

## 13. General operating instructions

- Treat this handover as historical context, not proof of the current filesystem state.
- Inspect before acting.
- Ask before making consequential changes.
- Explain technical decisions in clear language.
- Preserve existing architecture unless an approved change requires otherwise.
- Prefer small, targeted, testable changes.
- Do not claim a test passed unless it was actually run.
- Clearly distinguish verified facts, historical reports, assumptions, and unknowns.
- Protect the local-first privacy design.
- Never claim an image is authentic or fake based solely on metadata, ELA, or histograms.

**Current authorised task: read-only audit only. Do not begin implementation until the user explicitly approves the next task.**
