/**
 * Unit Tests — CTI Manager
 * 
 * Tests CTI string parsing, input detection, and severity assessment.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    detectIOCType,
    parseIOCInput,
    extractAttackTechniques,
    assessThreatLevel
} from '../js/engine/cti-manager.js';

// ─── detectIOCType ─────────────────────────────────────────────────────────

describe('detectIOCType', () => {
    it('detects IPv4 addresses', () => {
        assert.equal(detectIOCType('192.168.1.1'), 'ip');
        assert.equal(detectIOCType('8.8.8.8'), 'ip');
    });

    it('detects domains', () => {
        assert.equal(detectIOCType('example.com'), 'domain');
        assert.equal(detectIOCType('malicious-site.net'), 'domain');
    });

    it('detects hashes (MD5, SHA1, SHA256)', () => {
        assert.equal(detectIOCType('d41d8cd98f00b204e9800998ecf8427e'), 'hash'); // md5
        assert.equal(detectIOCType('da39a3ee5e6b4b0d3255bfef95601890afd80709'), 'hash'); // sha1
        assert.equal(detectIOCType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'hash'); // sha256
    });

    it('detects URLs', () => {
        assert.equal(detectIOCType('http://evil.com/payload.exe'), 'url');
        assert.equal(detectIOCType('https://secure-login.com'), 'url');
    });

    it('falls back to ip for unknown formats', () => {
        assert.equal(detectIOCType('random_string'), 'ip');
    });
});

// ─── parseIOCInput ─────────────────────────────────────────────────────────

describe('parseIOCInput', () => {
    it('splits multi-line input and removes duplicates', () => {
        const input = `
            1.1.1.1
            example.com
            1.1.1.1
            # this is a comment
            // also comment
        `;
        const result = parseIOCInput(input);
        assert.equal(result.length, 2);
        assert.equal(result[0].ioc, '1.1.1.1');
        assert.equal(result[0].type, 'ip');
        assert.equal(result[1].ioc, 'example.com');
        assert.equal(result[1].type, 'domain');
    });
});

// ─── extractAttackTechniques ───────────────────────────────────────────────

describe('extractAttackTechniques', () => {
    it('extracts unique ATT&CK IDs from OTX and VT', () => {
        const mockLookup = {
            results: {
                otx: { attackIds: ['T1595', 'T1059.001'] },
                virustotal: { mitreAttack: [{ id: 'T1595' }, { id: 'T1071' }] }
            }
        };
        const techniques = extractAttackTechniques(mockLookup);
        assert.equal(techniques.length, 3);
        assert.ok(techniques.includes('T1595'));
        assert.ok(techniques.includes('T1059')); // Base ID extracted
        assert.ok(techniques.includes('T1071'));
    });
});

// ─── assessThreatLevel ─────────────────────────────────────────────────────

describe('assessThreatLevel', () => {
    it('calculates CRITICAL severity correctly', () => {
        const mockLookup = {
            results: {
                abuseipdb: { abuseConfidenceScore: 100 },
                virustotal: { malicious: 15 },
                otx: { pulseCount: 10 }
            }
        };
        const assessment = assessThreatLevel(mockLookup);
        assert.equal(assessment.level, 'CRITICAL');
        assert.ok(assessment.score > 80);
        assert.ok(assessment.reasons.length > 0);
    });

    it('calculates LOW severity for benign indicators', () => {
        const mockLookup = {
            results: {
                abuseipdb: { abuseConfidenceScore: 0 },
                virustotal: { malicious: 0 }
            }
        };
        const assessment = assessThreatLevel(mockLookup);
        assert.equal(assessment.level, 'LOW');
        assert.equal(assessment.score, 0);
    });
});
