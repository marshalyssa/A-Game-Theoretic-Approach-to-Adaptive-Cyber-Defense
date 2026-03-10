/**
 * Unit Tests — IOC Mapper
 * 
 * Tests the mapping heuristics from IOC type and CTI enrichment
 * to MITRE ATT&CK techniques, and subsequent Kill Chain stage inference.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    mapIOCToTechniques,
    inferTacticStage
} from '../js/engine/ioc-mapper.js';

// ─── mapIOCToTechniques ────────────────────────────────────────────────────

describe('mapIOCToTechniques', () => {
    it('maps AbuseIPDB categories correctly', () => {
        const enrichment = {
            type: 'ip',
            results: {
                abuseipdb: { categories: [14] } // 14 = Port Scan
            }
        };
        const techniques = mapIOCToTechniques(enrichment);

        // Category 14 maps to T1046, T1595
        const t1595 = techniques.find(t => t.techniqueId === 'T1595');
        assert.ok(t1595, 'Should map to T1595 (Active Scanning)');
        // Contextual rule 'Scanning activity' boosts confidence from 0.7 to 0.9
        assert.equal(t1595.confidence, 0.9);

        // Also checks baseline IP inference
        const t1071 = techniques.find(t => t.techniqueId === 'T1071');
        assert.ok(t1071, 'Should include base IP inference (C2)');
    });

    it('maps OTX discrete attack IDs directly', () => {
        const enrichment = {
            type: 'domain',
            results: {
                otx: { attackIds: ['T1071.001'] }
            }
        };
        const techniques = mapIOCToTechniques(enrichment);
        const t1071 = techniques.find(t => t.techniqueId === 'T1071');

        assert.ok(t1071);
        assert.equal(t1071.confidence, 0.85); // OTX direct mapping confidence
        assert.ok(t1071.sources.includes('OTX Direct'));
    });

    it('applies contextual tracking rule (Ransomware flag)', () => {
        const enrichment = {
            type: 'hash',
            results: {
                virustotal: { tags: ['ransomware', 'win32'] }
            }
        };
        const techniques = mapIOCToTechniques(enrichment);
        const t1486 = techniques.find(t => t.techniqueId === 'T1486');

        assert.ok(t1486, 'Should identify ransomware technique T1486');
        assert.equal(t1486.confidence, 0.9);
        assert.ok(t1486.sources.includes('Ransomware indicator'));
    });

    it('combines overlapping sources correctly', () => {
        const enrichment = {
            type: 'ip',
            results: {
                otx: { attackIds: ['T1595'] },
                abuseipdb: { categories: [14] } // T1595
            }
        };
        const techniques = mapIOCToTechniques(enrichment);
        const t1595 = techniques.find(t => t.techniqueId === 'T1595');

        assert.ok(t1595);
        // OTX gives 0.85, Contextual rule gives 0.9. Max wins.
        assert.equal(t1595.confidence, 0.9);
        assert.ok(t1595.sources.includes('OTX Direct'));
        assert.ok(t1595.sources.includes('AbuseIPDB Cat 14'));
    });
});

// ─── inferTacticStage ──────────────────────────────────────────────────────

describe('inferTacticStage', () => {
    it('determines the correct max Kill Chain stage phase', () => {
        const mappedTechniques = [
            { techniqueId: 'T1595', confidence: 0.9 }, // Reconnaissance (Phase 0)
            { techniqueId: 'T1059', confidence: 0.8 }, // Execution (Phase 3)
            { techniqueId: 'T1071', confidence: 0.2 }  // Command and Control (Phase 11) - Low confidence
        ];

        const inference = inferTacticStage(mappedTechniques);

        // T1059 has confidence > 0.5, so Phase should be 3 (Execution, TA0002)
        assert.equal(inference.tacticId, 'TA0002');
        assert.equal(inference.tacticName, 'Execution');
        assert.equal(inference.currentPhase, 3);
        assert.ok(inference.coverage['TA0043']); // Recon
        assert.ok(inference.coverage['TA0002']); // Execution
        assert.ok(inference.coverage['TA0011']); // C2 included in coverage dict despite low conf
    });

    it('defaults to Recon if no high confidence later stages', () => {
        const mappedTechniques = [
            { techniqueId: 'T1595', confidence: 0.9 }, // Recon (Phase 0)
        ];
        const inference = inferTacticStage(mappedTechniques);

        // Recon is Phase 0
        assert.equal(inference.tacticId, 'TA0043');
        assert.equal(inference.currentPhase, 0);
    });
});
