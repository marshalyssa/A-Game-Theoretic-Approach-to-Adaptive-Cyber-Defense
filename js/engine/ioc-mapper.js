/**
 * IOC-to-ATT&CK Mapper — Heuristic Technique Inference
 * 
 * Maps IOC enrichment data to MITRE ATT&CK techniques using:
 * 1. Direct ATT&CK IDs from OTX/VT feeds
 * 2. Heuristic rules based on AbuseIPDB categories
 * 3. Contextual inference from IOC type and metadata
 */

import { TECHNIQUE_BY_ID, TECHNIQUES } from '../data/mitre-catalog.js';

// ─── AbuseIPDB Category → ATT&CK Technique Mapping ────────────────────────
// AbuseIPDB categories: https://www.abuseipdb.com/categories
const ABUSE_CATEGORY_MAP = {
    1: ['T1595'],             // DNS Compromise → Active Scanning
    2: ['T1595'],             // DNS Poisoning → Active Scanning
    3: ['T1110'],             // Fraud Orders → Brute Force (credential abuse)
    4: ['T1190', 'T1059'],    // DDoS Attack → Exploit Public App / Execution
    5: ['T1190'],             // FTP Brute-Force → Exploit Public App
    6: ['T1046'],             // Ping of Death → Network Service Scan
    7: ['T1566'],             // Phishing → Phishing
    8: ['T1190'],             // Fraud VoIP → Exploit Public App
    9: ['T1595', 'T1190'],    // Open Proxy → Active Scanning / Exploit
    10: ['T1071'],             // Web Spam → Application Layer Protocol
    11: ['T1566'],             // Email Spam → Phishing
    12: ['T1595'],             // Blog Spam → Active Scanning
    13: ['T1190'],             // VPN IP → Exploit
    14: ['T1046', 'T1595'],    // Port Scan → Network Scan / Active Scanning
    15: ['T1190'],             // Hacking → Exploit Public App
    16: ['T1190', 'T1059'],    // SQL Injection → Exploit / Execution
    17: ['T1190'],             // Spoofing → Exploit
    18: ['T1110'],             // Brute-Force → Brute Force
    19: ['T1190'],             // Bad Web Bot → Exploit
    20: ['T1190'],             // Exploited Host → Exploit
    21: ['T1059', 'T1190'],    // Web App Attack → Execution / Exploit
    22: ['T1110', 'T1078'],    // SSH → Brute Force / Valid Accounts
    23: ['T1190'],             // IoT Targeted → Exploit
};

// ─── IOC Type → Likely Techniques ──────────────────────────────────────────
const IOC_TYPE_TECHNIQUES = {
    'ip': ['T1595', 'T1071'],          // IP indicators → scanning, C2
    'domain': ['T1568', 'T1071'],      // Domain → dynamic resolution, C2
    'hash': ['T1204', 'T1059'],        // File hash → user execution, scripting
    'url': ['T1566', 'T1190'],         // URL → phishing, exploit
};

// ─── Contextual Inference Rules ────────────────────────────────────────────
const CONTEXT_RULES = [
    {
        name: 'High-confidence C2',
        condition: (enrichment) => {
            const otx = enrichment.results?.otx;
            const abuse = enrichment.results?.abuseipdb;
            return (otx?.pulseCount >= 3) && (abuse?.abuseConfidenceScore >= 60);
        },
        techniques: ['T1071', 'T1573', 'T1041'],
        confidence: 0.8
    },
    {
        name: 'Scanning activity',
        condition: (enrichment) => {
            const cats = enrichment.results?.abuseipdb?.categories || [];
            return cats.includes(14) || cats.includes(6);
        },
        techniques: ['T1595', 'T1046'],
        confidence: 0.9
    },
    {
        name: 'Brute force attack',
        condition: (enrichment) => {
            const cats = enrichment.results?.abuseipdb?.categories || [];
            return cats.includes(18) || cats.includes(22) || cats.includes(5);
        },
        techniques: ['T1110', 'T1078'],
        confidence: 0.85
    },
    {
        name: 'Phishing campaign',
        condition: (enrichment) => {
            const cats = enrichment.results?.abuseipdb?.categories || [];
            const otx = enrichment.results?.otx;
            const hasPhishTag = otx?.pulses?.some(p =>
                p.tags?.some(t => /phish/i.test(t))
            );
            return cats.includes(7) || cats.includes(11) || hasPhishTag;
        },
        techniques: ['T1566', 'T1204', 'T1059'],
        confidence: 0.85
    },
    {
        name: 'Malware-associated IP',
        condition: (enrichment) => {
            const vt = enrichment.results?.virustotal;
            return vt && vt.malicious >= 5;
        },
        techniques: ['T1071', 'T1059', 'T1027'],
        confidence: 0.75
    },
    {
        name: 'Ransomware indicator',
        condition: (enrichment) => {
            const vt = enrichment.results?.virustotal;
            const tags = vt?.tags || [];
            return tags.some(t => /ransom/i.test(t));
        },
        techniques: ['T1486', 'T1489', 'T1059'],
        confidence: 0.9
    },
    {
        name: 'Data center / hosting origin',
        condition: (enrichment) => {
            const abuse = enrichment.results?.abuseipdb;
            return abuse?.usageType && /data center|hosting/i.test(abuse.usageType);
        },
        techniques: ['T1583', 'T1071'],
        confidence: 0.5
    },
];

/**
 * Map IOC enrichment data to MITRE ATT&CK techniques
 * Returns techniques with confidence scores and sources
 * 
 * @param {Object} enrichment - Result from lookupIOC()
 * @returns {Array<{techniqueId: string, name: string, confidence: number, sources: string[]}>}
 */
export function mapIOCToTechniques(enrichment) {
    const techniqueMap = {}; // techniqueId → { confidence, sources }

    function addTechnique(techId, confidence, source) {
        if (!TECHNIQUE_BY_ID[techId]) return; // Only add known techniques
        if (!techniqueMap[techId]) {
            techniqueMap[techId] = { confidence: 0, sources: [] };
        }
        // Combine confidence (max of all sources)
        techniqueMap[techId].confidence = Math.max(techniqueMap[techId].confidence, confidence);
        if (!techniqueMap[techId].sources.includes(source)) {
            techniqueMap[techId].sources.push(source);
        }
    }

    // 1. Direct ATT&CK IDs from OTX
    const otx = enrichment.results?.otx;
    if (otx?.attackIds) {
        for (const id of otx.attackIds) {
            const baseId = id.split('.')[0];
            addTechnique(baseId, 0.85, 'OTX Direct');
        }
    }

    // 2. Direct ATT&CK IDs from VirusTotal sandbox
    const vt = enrichment.results?.virustotal;
    if (vt?.mitreAttack) {
        for (const tech of vt.mitreAttack) {
            const baseId = tech.id.split('.')[0];
            addTechnique(baseId, 0.9, 'VT Sandbox');
        }
    }

    // 3. AbuseIPDB category mapping
    const abuse = enrichment.results?.abuseipdb;
    if (abuse?.categories) {
        for (const cat of abuse.categories) {
            const techs = ABUSE_CATEGORY_MAP[cat];
            if (techs) {
                for (const techId of techs) {
                    addTechnique(techId, 0.7, `AbuseIPDB Cat ${cat}`);
                }
            }
        }
    }

    // 4. IOC type baseline techniques
    const typeTechs = IOC_TYPE_TECHNIQUES[enrichment.type] || [];
    for (const techId of typeTechs) {
        addTechnique(techId, 0.3, 'IOC Type Heuristic');
    }

    // 5. Contextual inference rules
    for (const rule of CONTEXT_RULES) {
        try {
            if (rule.condition(enrichment)) {
                for (const techId of rule.techniques) {
                    addTechnique(techId, rule.confidence, rule.name);
                }
            }
        } catch (e) { /* Rule evaluation failed, skip */ }
    }

    // Convert to sorted array
    return Object.entries(techniqueMap)
        .map(([techniqueId, data]) => ({
            techniqueId,
            name: TECHNIQUE_BY_ID[techniqueId]?.name || techniqueId,
            tacticId: TECHNIQUE_BY_ID[techniqueId]?.tacticId || 'unknown',
            confidence: Math.round(data.confidence * 100) / 100,
            sources: data.sources
        }))
        .sort((a, b) => b.confidence - a.confidence);
}

/**
 * Infer the current kill chain stage from mapped techniques
 * Returns the highest tactic phase observed
 * 
 * @param {Array} mappedTechniques - Result from mapIOCToTechniques()
 * @returns {{ currentPhase: number, tacticId: string, tacticName: string, coverage: Object }}
 */
export function inferTacticStage(mappedTechniques) {
    const phases = {};

    for (const tech of mappedTechniques) {
        const fullTech = TECHNIQUE_BY_ID[tech.techniqueId];
        if (fullTech) {
            const tacticId = fullTech.tacticId;
            if (!phases[tacticId]) {
                phases[tacticId] = { count: 0, maxConfidence: 0, techniques: [] };
            }
            phases[tacticId].count++;
            phases[tacticId].maxConfidence = Math.max(phases[tacticId].maxConfidence, tech.confidence);
            phases[tacticId].techniques.push(tech.techniqueId);
        }
    }

    // Find the most advanced tactic stage with high-confidence techniques
    const TACTIC_ORDER = [
        'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
        'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011',
        'TA0010', 'TA0040'
    ];

    let maxPhase = 0;
    let maxTacticId = 'TA0043';

    for (const [tacticId, data] of Object.entries(phases)) {
        const phase = TACTIC_ORDER.indexOf(tacticId);
        if (phase > maxPhase && data.maxConfidence >= 0.5) {
            maxPhase = phase;
            maxTacticId = tacticId;
        }
    }

    const TACTIC_NAMES = {
        'TA0043': 'Reconnaissance', 'TA0042': 'Resource Development',
        'TA0001': 'Initial Access', 'TA0002': 'Execution',
        'TA0003': 'Persistence', 'TA0004': 'Privilege Escalation',
        'TA0005': 'Defense Evasion', 'TA0006': 'Credential Access',
        'TA0007': 'Discovery', 'TA0008': 'Lateral Movement',
        'TA0009': 'Collection', 'TA0011': 'Command and Control',
        'TA0010': 'Exfiltration', 'TA0040': 'Impact'
    };

    return {
        currentPhase: maxPhase,
        tacticId: maxTacticId,
        tacticName: TACTIC_NAMES[maxTacticId] || 'Unknown',
        coverage: phases
    };
}
