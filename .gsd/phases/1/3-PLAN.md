---
phase: 1
plan: 3
wave: 2
---

# Plan 1.3: CTI Layer Tests + Server Route Tests

## Objective
Write tests for the IOC-to-ATT&CK mapping logic and Express server API routes. These verify that CTI data is correctly processed and the backend proxy handles requests properly. Wave 2 because these build on the test infrastructure from wave 1.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- js/engine/ioc-mapper.js
- js/engine/cti-manager.js
- server.js

## Tasks

<task type="auto">
  <name>Unit test ioc-mapper.js</name>
  <files>tests/ioc-mapper.test.mjs (NEW)</files>
  <action>
    Test the IOC-to-ATT&CK mapping logic:
    1. `mapIOCToAttack()` with OTX data containing attack_ids — extracts direct ATT&CK IDs
    2. `mapIOCToAttack()` with VT data containing mitre_attack — extracts technique IDs
    3. `mapIOCToAttack()` with AbuseIPDB categories — maps each category to expected techniques
    4. Contextual inference: IP with high abuse score → brute force / scanning techniques
    5. Contextual inference: domain IOC type → suggests phishing / C2 techniques
    6. `inferKillChainStage()` — reconnaissance techniques → early stage
    7. `inferKillChainStage()` — exfiltration techniques → late stage
    8. Empty enrichment data → returns empty technique list (no crash)
    9. Confidence scores are in [0, 1] range
    10. No duplicate techniques in output
  </action>
  <verify>npm test — all ioc-mapper tests pass</verify>
  <done>≥10 test cases pass for ioc-mapper with zero failures</done>
</task>

<task type="auto">
  <name>Test cti-manager.js parsing + server health endpoint</name>
  <files>tests/cti-manager.test.mjs (NEW)</files>
  <action>
    Test client-side CTI parsing and IOC type detection:
    1. `parseIOCInput()` — single IP returns [{ioc, type: 'ip'}]
    2. `parseIOCInput()` — multi-line input returns correct number of IOCs
    3. `parseIOCInput()` — empty/whitespace input returns []
    4. `parseIOCInput()` — detects domain type correctly
    5. `parseIOCInput()` — detects hash type (MD5, SHA1, SHA256)
    6. `parseIOCInput()` — detects URL type
    7. `parseIOCInput()` — skips blank lines
    8. `extractAttackTechniques()` — extracts from mock OTX response
    9. `assessThreatLevel()` — high score returns CRITICAL/HIGH
    10. `assessThreatLevel()` — zero score returns NONE/LOW
    
    For server test: Start server on a test port, verify GET /api/health returns 200.
    Note: Server tests may need to start/stop the Express app, or test the health endpoint logic directly.
  </action>
  <verify>npm test — all cti-manager tests pass</verify>
  <done>≥10 test cases pass for cti-manager with zero failures</done>
</task>

<task type="checkpoint:human-verify">
  <name>Verify full test suite</name>
  <files>all test files</files>
  <action>
    Run `npm test` and verify:
    - Total test count ≥ 40
    - Zero failures
    - All 5 test files execute
    Report results to user for review.
  </action>
  <verify>npm test — full suite passes</verify>
  <done>≥40 total tests across 5 files, zero failures</done>
</task>

## Success Criteria
- [ ] ≥10 ioc-mapper tests pass
- [ ] ≥10 cti-manager tests pass
- [ ] Full test suite: ≥40 tests, zero failures
- [ ] All engine modules have test coverage
