# GARUDA Design System (DESIGN.md)

This document specifies the design tokens, typography, color harmony, visual rhythm, component standards, and motion specifications for the **GARUDA v4 Autonomous Threat Containment System**.

---

## 1. Palette & Surface Tokens

GARUDA operates with dual high-contrast themes: **Dark Cyber-Ops (Default/Night)** and **Light Architectural Minimalist (Day)**.

### Dark Theme (`.theme-dark`)
- `--bg`: `#12151B` (Deep obsidian backdrop)
- `--surface`: `#1A1E26` (Card and panel surface)
- `--surface-alt`: `#222733` (Elevated pills and toolbars)
- `--border`: `rgba(236, 234, 228, 0.12)` (Hairline architectural division)
- `--border-focus`: `#6394F2` (Cyan-blue focus accent)
- `--text`: `#ECEAE4` (High-legibility primary text)
- `--text-muted`: `#8E95A5` (Secondary metadata and timestamps)
- `--brand`: `#6394F2` (GARUDA primary operational blue)
- `--brand-glow`: `rgba(99, 148, 242, 0.22)`
- `--safe`: `#3EB488` (Verified device emerald)
- `--warn`: `#E2A343` (Unverified / Untrusted amber)
- `--danger`: `#E36050` (Active alert / Critical ML risk crimson)

### Light Theme
- `--bg`: `#F3F0EA` (Warm bone/architectural concrete)
- `--surface`: `#FAF8F4` (Clean card background)
- `--surface-alt`: `#ECE7DE` (Elevated controls)
- `--border`: `rgba(22, 24, 29, 0.12)`
- `--text`: `#16181D` (Charcoal primary)
- `--text-muted`: `#686E7B` (Muted labels)
- `--brand`: `#1E4FD6` (Deep cobalt)
- `--safe`: `#157F56` (Deep forest emerald)
- `--warn`: `#B96B08` (Dark amber)
- `--danger`: `#C53624` (Crimson alarm)

---

## 2. Typography & Hierarchy

- **Primary Typeface**: `Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- **Monospace Typeface**: `"JetBrains Mono", SFMono-Regular, Menlo, Monaco, Consolas, monospace`
- **Scale**:
  - Hero Titles: `32px / 1.15`, weight `700`, letter-spacing `-0.025em`
  - Section Headers: `18px / 1.3`, weight `700`, letter-spacing `-0.015em`
  - Card Titles: `14px / 1.4`, weight `600`, letter-spacing `-0.01em`
  - Body Text: `13px / 1.5`, weight `400`
  - Micro-metadata & Badges: `11px / 1.3`, weight `600`, uppercase, letter-spacing `+0.04em`

---

## 3. Spatial Layout & Radar Architecture

### Trust Bands Invariant
- **Band A (Inner)**: Safe Devices (`#3EB488` / `#157F56`)
- **Band B (Middle)**: Unverified Devices (`#E2A343` / `#B96B08`)
- **Band C (Outer)**: Active Alert / Critical ML Devices (`#E36050` / `#C53624`)

### Collision-Free Invariants
- Minimum Euclidean node spacing:
  $$\text{dist}(p_i, p_j) \ge \text{minNodeSpacing}$$
- Ring capacity formula:
  $$\text{cap}(r) = \max\left(1, \left\lfloor \frac{\pi}{\arcsin\left(\frac{s}{2r}\right)} \right\rfloor\right)$$
- Interlocking angular offset on alternating concentric rings:
  $$\theta_{\text{offset}} = (j \pmod 2) \times \frac{\pi}{N_{\text{ring}}}$$
- AABB Label Clearance: Labels never overlap node circles, router circle, or adjacent labels.
