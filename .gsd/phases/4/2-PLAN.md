---
phase: 4
plan: 2
wave: 1
---

# Plan 4.2: Micro-animations & Interaction

## Objective
Enhance user engagement with subtle micro-animations, smooth transitions, and refined interactive feedback.

## Context
- index.css
- js/app.js

## Tasks

<task type="auto">
  <name>Implement interactive transitions and hover effects</name>
  <files>index.css</files>
  <action>
    - Add `transition: all 0.2s ease-out;` to all buttons and interactive cards.
    - Implement hover scales or glow effects for buttons.
    - Add dynamic list animations: using `@keyframes` for items to fade and slide into view when rendered (e.g., in `.prediction-item` and `.action-item`).
    - Smooth the belief bar updates: add `transition: width 0.5s cubic-bezier(0.165, 0.84, 0.44, 1);` to `.belief-bar-fill`.
  </action>
  <verify>Check index.css for transitions and anim-in keyframes.</verify>
  <done>Smoothing is applied to both bars and list entry animations.</done>
</task>

<task type="auto">
  <name>Polish tab switching and badge states</name>
  <files>index.css, js/app.js</files>
  <action>
    - Add a fade-in transition when switching between "Simulation" and "Live" tabs.
    - Update badge designs (threat levels, status) with more polished colors and pill-shaped layouts.
    - Add a subtle pulse animation to the "Running" state badge.
  </action>
  <verify>Check setStatus and switchTab logic for transition classes; verify badge CSS.</verify>
  <done>Transitions and badges feel professional and active.</done>
</task>

## Success Criteria
- [ ] Belief bars animate smoothly when updated.
- [ ] List items slide in gracefully.
- [ ] Running state is visually distinct with a pulse effect.
