/**
 * CTI Manager — Client-side CTI Feed Integration
 * 
 * Calls the backend proxy to query CTI feeds and normalizes responses.
 * Handles feed selection, error recovery, and result merging.
 */

// ─── API Base URL ──────────────────────────────────────────────────────────
const API_BASE = window.location.origin;

/**
 * Check which CTI feeds are configured on the server
 * @returns {Object} { otx: bool, virustotal: bool, abuseipdb: bool }
 */
export async function checkFeedStatus() {
    try {
        const resp = await fetch(`${API_BASE}/api/health`);
        const data = await resp.json();
        return data.feeds || { otx: false, virustotal: false, abuseipdb: false };
    } catch (e) {
        return { otx: false, virustotal: false, abuseipdb: false };
    }
}

/**
 * Lookup an IOC across selected CTI feeds
 * @param {string} ioc - The indicator (IP, domain, hash, URL)
 * @param {string} type - IOC type: 'ip', 'domain', 'hash', 'url'
 * @param {string[]} feeds - Array of feed names to query
 * @returns {Object} { ioc, type, results, errors, timestamp }
 */
export async function lookupIOC(ioc, type, feeds = ['otx', 'virustotal', 'abuseipdb']) {
    try {
        const resp = await fetch(`${API_BASE}/api/cti/lookup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc, type, feeds })
        });

        if (!resp.ok) {
            throw new Error(`Server returned ${resp.status}`);
        }

        return await resp.json();
    } catch (e) {
        return {
            ioc, type,
            results: {},
            errors: { general: e.message },
            timestamp: new Date().toISOString()
        };
    }
}

/**
 * Auto-detect IOC type from string
 * @param {string} ioc - The indicator string
 * @returns {string} type: 'ip', 'domain', 'hash', 'url'
 */
export function detectIOCType(ioc) {
    const trimmed = ioc.trim();

    // URL
    if (/^https?:\/\//i.test(trimmed)) return 'url';

    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return 'ip';

    // IPv6
    if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(trimmed)) return 'ip';

    // MD5 hash (32 hex chars)
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return 'hash';

    // SHA1 hash (40 hex chars)
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return 'hash';

    // SHA256 hash (64 hex chars)
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return 'hash';

    // Domain (has dots, no path)
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(trimmed)) return 'domain';

    return 'ip'; // Default fallback
}

/**
 * Parse a multi-line IOC input into individual IOCs with types
 * @param {string} input - Multi-line text with IOCs
 * @returns {Array<{ioc: string, type: string}>}
 */
export function parseIOCInput(input) {
    const lines = input.split(/[\n,;]+/).map(l => l.trim()).filter(l => l.length > 0);
    const iocs = [];
    const seen = new Set();

    for (const line of lines) {
        // Skip comments
        if (line.startsWith('#') || line.startsWith('//')) continue;

        const ioc = line;
        if (seen.has(ioc.toLowerCase())) continue;
        seen.add(ioc.toLowerCase());

        iocs.push({
            ioc,
            type: detectIOCType(ioc)
        });
    }

    return iocs;
}

/**
 * Extract all MITRE ATT&CK technique IDs from a unified lookup response
 * @param {Object} lookupResult - Result from lookupIOC()
 * @returns {string[]} Array of technique IDs like ['T1595', 'T1071']
 */
export function extractAttackTechniques(lookupResult) {
    const techniques = new Set();
    const results = lookupResult.results || {};

    // OTX: attack_ids directly from pulses
    if (results.otx && results.otx.attackIds) {
        for (const id of results.otx.attackIds) {
            // OTX returns full IDs like "T1595" or "T1059.001"
            const baseId = id.split('.')[0]; // Use parent technique
            if (/^T\d{4}$/.test(baseId)) {
                techniques.add(baseId);
            }
        }
    }

    // VirusTotal: mitreAttack from sandbox behavior
    if (results.virustotal && results.virustotal.mitreAttack) {
        for (const tech of results.virustotal.mitreAttack) {
            const baseId = tech.id.split('.')[0];
            if (/^T\d{4}$/.test(baseId)) {
                techniques.add(baseId);
            }
        }
    }

    return [...techniques];
}

/**
 * Get a threat severity level from enrichment data
 * @param {Object} lookupResult - Result from lookupIOC()
 * @returns {{ level: string, score: number, reasons: string[] }}
 */
export function assessThreatLevel(lookupResult) {
    const results = lookupResult.results || {};
    let score = 0;
    const reasons = [];

    // AbuseIPDB confidence
    if (results.abuseipdb) {
        const conf = results.abuseipdb.abuseConfidenceScore || 0;
        score += conf * 0.4; // 40% weight
        if (conf >= 80) reasons.push(`AbuseIPDB: High confidence (${conf}%)`);
        else if (conf >= 40) reasons.push(`AbuseIPDB: Medium confidence (${conf}%)`);
        if (results.abuseipdb.totalReports > 10) reasons.push(`${results.abuseipdb.totalReports} abuse reports`);
    }

    // VirusTotal malicious detections
    if (results.virustotal) {
        const mal = results.virustotal.malicious || 0;
        const suspic = results.virustotal.suspicious || 0;
        const vtScore = Math.min(100, (mal * 3 + suspic) * 2);
        score += vtScore * 0.35; // 35% weight
        if (mal >= 5) reasons.push(`VirusTotal: ${mal} engines flagged malicious`);
        if (results.virustotal.mitreAttack?.length > 0) {
            reasons.push(`${results.virustotal.mitreAttack.length} ATT&CK techniques observed`);
        }
    }

    // OTX pulse count
    if (results.otx) {
        const pulses = results.otx.pulseCount || 0;
        const otxScore = Math.min(100, pulses * 5);
        score += otxScore * 0.25; // 25% weight
        if (pulses >= 5) reasons.push(`OTX: Found in ${pulses} threat pulses`);
        if (results.otx.attackIds?.length > 0) {
            reasons.push(`${results.otx.attackIds.length} ATT&CK mappings from OTX`);
        }
    }

    score = Math.round(Math.min(100, score));

    let level = 'LOW';
    if (score >= 70) level = 'CRITICAL';
    else if (score >= 50) level = 'HIGH';
    else if (score >= 25) level = 'MEDIUM';

    return { level, score, reasons };
}
