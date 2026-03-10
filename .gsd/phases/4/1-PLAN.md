---
phase: 4
plan: 1
wave: 1
---

# Plan 4.1: Visual Refinement & Design System

## Objective
Refine the core design system (typography, colors, card styles) to create a premium "cyber-defense" aesthetic using glassmorphism and modern hierarchy.

## Context
- .gsd/SPEC.md
- index.html
- index.css

## Tasks

<task type="auto">
  <name>Implement modern typography and color palette</name>
  <files>index.html, index.css</files>
  <action>
    - Import "Inter" or "Outfit" from Google Fonts in `index.html`.
    - Update CSS variables in `index.css` for a better "Cyber Dark" palette:
      - `--bg-primary: #050b15;`
      - `--bg-secondary: rgba(15, 23, 42, 0.7);`
      - `--accent-cyan: #22d3ee;`
      - `--accent-amber: #f59e0b;`
      - `--accent-red: #ef4444;`
    - Standardize font hierarchy (h1, h2, h3, labels) with `font-weight` and `letter-spacing`.
  </action>
  <verify>Check index.css for updated variables and Google Font import in index.html.</verify>
  <done>Modern font and variables are correctly applied to the root.</done>
</task>

<task type="auto">
  <name>Apply glassmorphism to panels and cards</name>
  <files>index.css</files>
  <action>
    - Add `backdrop-filter: blur(12px);` to `.card` and panels.
    - Update `.card` styling with subtle translucent backgrounds and thin borders (`1px solid rgba(255,255,255,0.08)`).
    - Add smooth box-shadows to panels to create depth.
    - Polish the "Kill Chain" visual: make it look like a connected pipeline with chevrons or lines.
  </action>
  <verify>Visual check of .card and .kill-chain-stage styles in index.css.</verify>
  <done>Glassmorphism and depth effects are applied to all major structural elements.</done>
</task>

## Success Criteria
- [ ] Typography is modern and consistent.
- [ ] Cards have a glassmorphic/premium look.
- [ ] Kill chain layout is visually connected.
