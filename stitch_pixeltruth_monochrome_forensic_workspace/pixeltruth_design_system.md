---
name: "PIXELTRUTH — Black & White Forensic Studio"
description: "Strict monochrome digital image-forensics design system built on pure black, deep charcoal, graphite surfaces, crisp 1px borders, and high-contrast white typography."
---

## Overview

PIXELTRUTH is a digital image-forensics workspace engineered for investigators, photo analysts, and security practitioners. The visual identity combines the precision of professional photo-analysis software with the restraint of a minimalist desktop workstation.

The system enforces a **strict Black & White Monochrome** aesthetic: pure black primary canvas, deep charcoal navigation chrome, dark grey analytical cards, and graphite active states, paired with razor-sharp `1px` borders and zero chromatic decoration. Every visual element serves evidentiary clarity—nothing is ornamental.

## Colors

All colour tokens are strictly achromatic (black, white, and neutral greys). Blue, purple, green, orange, red, and multicolour gradients are prohibited. Data visualisations and comparison states distinguish series through line styles, patterns, luminance steps, and explicit text labels rather than hue.

- **Background (`#000000`):** Primary application canvas.
- **Surface / Secondary Background (`#111111`):** Persistent sidebar and secondary structural panels.
- **Surface Container (`#181818`):** Standard analytical cards, upload dropzones, and table containers.
- **Surface Container High (`#222222`):** Active sidebar items, elevated toolbars, and hover states.
- **Primary (`#FFFFFF`) & On-Primary (`#111111`):** High-contrast primary actions, active icons, and key metric values.
- **Light Surface (`#F5F5F5`) & On-Surface-Light (`#111111`):** Printable forensic report preview pages and inverted callout surfaces.
- **On-Surface-Variant (`#B3B3B3`):** Secondary descriptions, table body text, and inactive navigation labels.
- **Outline (`#777777`) & Outline-Variant (`#303030`):** Muted metadata labels and crisp `1px` structural borders.

```yaml
colors:
  background: "#000000"
  on-background: "#FFFFFF"
  primary: "#FFFFFF"
  on-primary: "#111111"
  secondary: "#B3B3B3"
  on-secondary: "#111111"
  surface: "#111111"
  on-surface: "#FFFFFF"
  surface-container-low: "#111111"
  surface-container: "#181818"
  surface-container-high: "#222222"
  surface-light: "#F5F5F5"
  on-surface-light: "#111111"
  on-surface-variant: "#B3B3B3"
  outline: "#777777"
  outline-variant: "#303030"
```

## Typography

PIXELTRUTH pairs **Inter** for interface hierarchy, metrics, and forensic prose with **Source Code Pro** for SHA-256 fingerprints, hex offsets, EXIF raw tags, and tabular telemetry. Numeric values use `tabular-nums` so dimensions, file sizes, and histogram coordinates align cleanly.

```yaml
typography:
  display-lg:
    fontFamily: "Inter"
    fontSize: 36px
    fontWeight: 700
    lineHeight: 44px
    letterSpacing: -0.75px
  display-lg-mobile:
    fontFamily: "Inter"
    fontSize: 28px
    fontWeight: 700
    lineHeight: 34px
    letterSpacing: -0.5px
  headline-lg:
    fontFamily: "Inter"
    fontSize: 28px
    fontWeight: 700
    lineHeight: 36px
    letterSpacing: -0.5px
  headline-md:
    fontFamily: "Inter"
    fontSize: 20px
    fontWeight: 600
    lineHeight: 28px
    letterSpacing: -0.25px
  title-lg:
    fontFamily: "Inter"
    fontSize: 16px
    fontWeight: 600
    lineHeight: 24px
    letterSpacing: 0px
  title-md:
    fontFamily: "Inter"
    fontSize: 14px
    fontWeight: 500
    lineHeight: 20px
    letterSpacing: 0px
  body-md:
    fontFamily: "Inter"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 22px
    letterSpacing: 0px
  body-sm:
    fontFamily: "Inter"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 20px
    letterSpacing: 0px
  label-lg:
    fontFamily: "Inter"
    fontSize: 13px
    fontWeight: 500
    lineHeight: 18px
    letterSpacing: 0.1px
  label-sm:
    fontFamily: "Inter"
    fontSize: 11px
    fontWeight: 500
    lineHeight: 16px
    letterSpacing: 0.4px
  mono-md:
    fontFamily: "Source Code Pro"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 20px
    letterSpacing: 0px
  mono-sm:
    fontFamily: "Source Code Pro"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 18px
    letterSpacing: 0px
```

## Layout & Spacing

The application uses a **Desktop-First Persistent Sidebar Shell**: a fixed `256px` left sidebar (`#111111` with `1px` right border `#303030`) paired with a fluid main workspace (`#000000`) bounded to a `1280px` max content width. On tablet (`<1024px`) and mobile (`<768px`), the sidebar collapses behind a top bar toggle and multi-column grids collapse to a single column. Spacing follows a strict `4px` base unit (`8px`, `16px`, `24px`, `32px`).

```yaml
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  2xl: 48px
```

## Elevation & Depth

PIXELTRUTH uses **Crisp Hairline Borders & Tonal Layering** rather than drop shadows or glassmorphism. Depth is communicated strictly by stepping surface luminance (`#000000` -> `#111111` -> `#181818` -> `#222222`) separated by `1px solid #303030` borders. Backdrop blur and decorative shadows are prohibited.

## Shapes

Restrained, technical corner radii keep the workstation feeling precise and analytical—never pill-heavy or overly rounded.

```yaml
rounded:
  sm: 2px
  DEFAULT: 4px
  md: 6px
  lg: 8px
  full: 9999px
```

## Motion & Micro-interaction

Interactions are immediate and mechanical: subtle brightness/surface shifts on hover (`100ms ease-out`), crisp focus rings (`2px solid #FFFFFF`), and zero decorative or looping animations.

```yaml
motion:
  state-change:
    duration: 100ms
    delay: 0ms
    timingFunction: ease-out
  surface-enter:
    duration: 180ms
    delay: 0ms
    timingFunction: cubic-bezier(0.2, 0, 0, 1)
```

## Voice & Content Strategy

- **Tone of voice:** Clinical, objective, and transparent. State what is observed and its technical limitations; never exaggerate certainty or use marketing buzzwords.
- **Capitalisation:** Sentence case for descriptions and button labels; concise title case for navigation items and section headings.
- **Empty & unavailable states:** Never invent fake statistics or recent history. Unavailable metadata explicitly reads `"Not available"`.
- **Privacy clarity:** Reinforce local-only processing where files are ingested (`"Images are processed locally. They are not automatically uploaded to external servers."`).

## Components

Component implementations live as individual HTML sticker sheet files in
`components/`. Each file contains the canonical, styled HTML components with
`<!-- COMPONENT: name -->` comment markers. Read each file before use.

- **Button** → `@components/button.html` — `button-primary`, `button-icon`, `button-with-icon`
- **Card** → `@components/card.html` — `card-elevated`, `card-action`, `card-interactive`, `card-interactive-2`
- **Table** → `@components/table.html` — `table-standard`, `table-interactive`, `table-selectable`
- **Typography** → `@components/typography.html` — `typography-display`, `typography-body`, `typography-label`
