/**
 * MITRE ATT&CK Enterprise Catalog — Techniques, Tactics, and Transition Matrix
 * 
 * Contains:
 * - 14 Enterprise tactics with ordering
 * - ~40 curated representative techniques spanning all tactics
 * - Pre-computed technique transition probability matrix (based on co-occurrence research)
 * - Technique metadata: detection difficulty, execution cost, stealth rating
 */

// ─── Tactics (Kill Chain Order) ────────────────────────────────────────────
export const TACTICS = [
    { id: 'TA0043', name: 'Reconnaissance',        phase: 0, description: 'Gathering information to plan future operations' },
    { id: 'TA0042', name: 'Resource Development',   phase: 1, description: 'Establishing resources to support operations' },
    { id: 'TA0001', name: 'Initial Access',         phase: 2, description: 'Trying to get into the network' },
    { id: 'TA0002', name: 'Execution',              phase: 3, description: 'Trying to run malicious code' },
    { id: 'TA0003', name: 'Persistence',            phase: 4, description: 'Trying to maintain foothold' },
    { id: 'TA0004', name: 'Privilege Escalation',   phase: 5, description: 'Trying to gain higher-level permissions' },
    { id: 'TA0005', name: 'Defense Evasion',        phase: 6, description: 'Trying to avoid being detected' },
    { id: 'TA0006', name: 'Credential Access',      phase: 7, description: 'Stealing credentials' },
    { id: 'TA0007', name: 'Discovery',              phase: 8, description: 'Trying to figure out the environment' },
    { id: 'TA0008', name: 'Lateral Movement',       phase: 9, description: 'Moving through the environment' },
    { id: 'TA0009', name: 'Collection',             phase: 10, description: 'Gathering data of interest' },
    { id: 'TA0011', name: 'Command and Control',    phase: 11, description: 'Communicating with compromised systems' },
    { id: 'TA0010', name: 'Exfiltration',           phase: 12, description: 'Stealing data' },
    { id: 'TA0040', name: 'Impact',                 phase: 13, description: 'Manipulate, interrupt, or destroy systems' }
];

export const TACTIC_BY_ID = Object.fromEntries(TACTICS.map(t => [t.id, t]));
export const TACTIC_PHASES = TACTICS.map(t => t.id);

// ─── Techniques ────────────────────────────────────────────────────────────
// Each technique includes:
//   detectionDifficulty: [0,1] — higher = harder to detect
//   executionCost:       [0,1] — higher = more expensive/complex to execute
//   stealthRating:       [0,1] — higher = stealthier
export const TECHNIQUES = [
    // Reconnaissance (TA0043)
    { id: 'T1595', name: 'Active Scanning',                    tacticId: 'TA0043', detectionDifficulty: 0.3, executionCost: 0.1, stealthRating: 0.2 },
    { id: 'T1592', name: 'Gather Victim Host Information',     tacticId: 'TA0043', detectionDifficulty: 0.7, executionCost: 0.1, stealthRating: 0.8 },
    { id: 'T1589', name: 'Gather Victim Identity Information', tacticId: 'TA0043', detectionDifficulty: 0.8, executionCost: 0.2, stealthRating: 0.9 },

    // Resource Development (TA0042)
    { id: 'T1583', name: 'Acquire Infrastructure',             tacticId: 'TA0042', detectionDifficulty: 0.9, executionCost: 0.3, stealthRating: 0.9 },
    { id: 'T1588', name: 'Obtain Capabilities',                tacticId: 'TA0042', detectionDifficulty: 0.9, executionCost: 0.4, stealthRating: 0.9 },

    // Initial Access (TA0001)
    { id: 'T1566', name: 'Phishing',                           tacticId: 'TA0001', detectionDifficulty: 0.4, executionCost: 0.2, stealthRating: 0.5 },
    { id: 'T1190', name: 'Exploit Public-Facing Application',  tacticId: 'TA0001', detectionDifficulty: 0.5, executionCost: 0.6, stealthRating: 0.4 },
    { id: 'T1078', name: 'Valid Accounts',                     tacticId: 'TA0001', detectionDifficulty: 0.8, executionCost: 0.5, stealthRating: 0.9 },

    // Execution (TA0002)
    { id: 'T1059', name: 'Command and Scripting Interpreter',  tacticId: 'TA0002', detectionDifficulty: 0.3, executionCost: 0.2, stealthRating: 0.3 },
    { id: 'T1204', name: 'User Execution',                     tacticId: 'TA0002', detectionDifficulty: 0.5, executionCost: 0.1, stealthRating: 0.4 },
    { id: 'T1203', name: 'Exploitation for Client Execution',  tacticId: 'TA0002', detectionDifficulty: 0.6, executionCost: 0.7, stealthRating: 0.5 },

    // Persistence (TA0003)
    { id: 'T1547', name: 'Boot or Logon Autostart Execution',  tacticId: 'TA0003', detectionDifficulty: 0.4, executionCost: 0.3, stealthRating: 0.4 },
    { id: 'T1053', name: 'Scheduled Task/Job',                 tacticId: 'TA0003', detectionDifficulty: 0.3, executionCost: 0.2, stealthRating: 0.3 },
    { id: 'T1136', name: 'Create Account',                     tacticId: 'TA0003', detectionDifficulty: 0.4, executionCost: 0.3, stealthRating: 0.3 },

    // Privilege Escalation (TA0004)
    { id: 'T1055', name: 'Process Injection',                  tacticId: 'TA0004', detectionDifficulty: 0.6, executionCost: 0.5, stealthRating: 0.7 },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', tacticId: 'TA0004', detectionDifficulty: 0.5, executionCost: 0.7, stealthRating: 0.5 },
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism',  tacticId: 'TA0004', detectionDifficulty: 0.5, executionCost: 0.4, stealthRating: 0.6 },

    // Defense Evasion (TA0005)
    { id: 'T1027', name: 'Obfuscated Files or Information',    tacticId: 'TA0005', detectionDifficulty: 0.7, executionCost: 0.3, stealthRating: 0.8 },
    { id: 'T1070', name: 'Indicator Removal',                  tacticId: 'TA0005', detectionDifficulty: 0.8, executionCost: 0.3, stealthRating: 0.9 },
    { id: 'T1562', name: 'Impair Defenses',                    tacticId: 'TA0005', detectionDifficulty: 0.4, executionCost: 0.4, stealthRating: 0.5 },

    // Credential Access (TA0006)
    { id: 'T1003', name: 'OS Credential Dumping',              tacticId: 'TA0006', detectionDifficulty: 0.4, executionCost: 0.4, stealthRating: 0.3 },
    { id: 'T1110', name: 'Brute Force',                        tacticId: 'TA0006', detectionDifficulty: 0.2, executionCost: 0.2, stealthRating: 0.1 },
    { id: 'T1558', name: 'Steal or Forge Kerberos Tickets',    tacticId: 'TA0006', detectionDifficulty: 0.7, executionCost: 0.6, stealthRating: 0.7 },

    // Discovery (TA0007)
    { id: 'T1046', name: 'Network Service Scanning',           tacticId: 'TA0007', detectionDifficulty: 0.2, executionCost: 0.1, stealthRating: 0.2 },
    { id: 'T1083', name: 'File and Directory Discovery',       tacticId: 'TA0007', detectionDifficulty: 0.6, executionCost: 0.1, stealthRating: 0.7 },
    { id: 'T1057', name: 'Process Discovery',                  tacticId: 'TA0007', detectionDifficulty: 0.6, executionCost: 0.1, stealthRating: 0.7 },

    // Lateral Movement (TA0008)
    { id: 'T1021', name: 'Remote Services',                    tacticId: 'TA0008', detectionDifficulty: 0.5, executionCost: 0.3, stealthRating: 0.5 },
    { id: 'T1570', name: 'Lateral Tool Transfer',              tacticId: 'TA0008', detectionDifficulty: 0.5, executionCost: 0.3, stealthRating: 0.5 },
    { id: 'T1550', name: 'Use Alternate Authentication Material', tacticId: 'TA0008', detectionDifficulty: 0.7, executionCost: 0.5, stealthRating: 0.7 },

    // Collection (TA0009)
    { id: 'T1005', name: 'Data from Local System',             tacticId: 'TA0009', detectionDifficulty: 0.6, executionCost: 0.2, stealthRating: 0.6 },
    { id: 'T1074', name: 'Data Staged',                        tacticId: 'TA0009', detectionDifficulty: 0.5, executionCost: 0.2, stealthRating: 0.5 },
    { id: 'T1119', name: 'Automated Collection',               tacticId: 'TA0009', detectionDifficulty: 0.5, executionCost: 0.3, stealthRating: 0.5 },

    // Command and Control (TA0011)
    { id: 'T1071', name: 'Application Layer Protocol',         tacticId: 'TA0011', detectionDifficulty: 0.6, executionCost: 0.3, stealthRating: 0.6 },
    { id: 'T1573', name: 'Encrypted Channel',                  tacticId: 'TA0011', detectionDifficulty: 0.7, executionCost: 0.3, stealthRating: 0.8 },
    { id: 'T1568', name: 'Dynamic Resolution',                 tacticId: 'TA0011', detectionDifficulty: 0.6, executionCost: 0.4, stealthRating: 0.7 },

    // Exfiltration (TA0010)
    { id: 'T1041', name: 'Exfiltration Over C2 Channel',       tacticId: 'TA0010', detectionDifficulty: 0.6, executionCost: 0.3, stealthRating: 0.6 },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tacticId: 'TA0010', detectionDifficulty: 0.5, executionCost: 0.4, stealthRating: 0.5 },
    { id: 'T1567', name: 'Exfiltration Over Web Service',      tacticId: 'TA0010', detectionDifficulty: 0.7, executionCost: 0.3, stealthRating: 0.7 },

    // Impact (TA0040)
    { id: 'T1486', name: 'Data Encrypted for Impact',          tacticId: 'TA0040', detectionDifficulty: 0.2, executionCost: 0.5, stealthRating: 0.1 },
    { id: 'T1489', name: 'Service Stop',                       tacticId: 'TA0040', detectionDifficulty: 0.3, executionCost: 0.3, stealthRating: 0.2 },
    { id: 'T1529', name: 'System Shutdown/Reboot',             tacticId: 'TA0040', detectionDifficulty: 0.1, executionCost: 0.2, stealthRating: 0.1 }
];

export const TECHNIQUE_BY_ID = Object.fromEntries(TECHNIQUES.map(t => [t.id, t]));
export const TECHNIQUE_IDS = TECHNIQUES.map(t => t.id);

// Group techniques by tactic
export const TECHNIQUES_BY_TACTIC = {};
for (const t of TECHNIQUES) {
    if (!TECHNIQUES_BY_TACTIC[t.tacticId]) TECHNIQUES_BY_TACTIC[t.tacticId] = [];
    TECHNIQUES_BY_TACTIC[t.tacticId].push(t);
}

// ─── Technique Transition Matrix ───────────────────────────────────────────
// P(next_technique | current_technique)
// Rows = current technique, Columns = next technique
// Based on co-occurrence analysis from published CTI research (arXiv:2211.06495)
// Transitions primarily follow kill chain progression with some lateral/retry loops
// Only significant transitions are stored (sparse); missing = low probability (~0.01 uniform)

const SPARSE_TRANSITIONS = {
    // Reconnaissance → Resource Dev / Initial Access
    'T1595': { 'T1592': 0.30, 'T1583': 0.25, 'T1566': 0.20, 'T1190': 0.15, 'T1589': 0.10 },
    'T1592': { 'T1589': 0.25, 'T1583': 0.20, 'T1566': 0.25, 'T1190': 0.20, 'T1078': 0.10 },
    'T1589': { 'T1583': 0.20, 'T1566': 0.30, 'T1078': 0.30, 'T1588': 0.20 },

    // Resource Development → Initial Access
    'T1583': { 'T1566': 0.30, 'T1190': 0.25, 'T1588': 0.25, 'T1078': 0.20 },
    'T1588': { 'T1566': 0.25, 'T1190': 0.35, 'T1078': 0.15, 'T1203': 0.25 },

    // Initial Access → Execution
    'T1566': { 'T1204': 0.35, 'T1059': 0.30, 'T1203': 0.15, 'T1547': 0.10, 'T1071': 0.10 },
    'T1190': { 'T1059': 0.35, 'T1203': 0.25, 'T1078': 0.15, 'T1055': 0.15, 'T1071': 0.10 },
    'T1078': { 'T1059': 0.25, 'T1021': 0.25, 'T1083': 0.20, 'T1057': 0.15, 'T1071': 0.15 },

    // Execution → Persistence / Priv Esc / Defense Evasion
    'T1059': { 'T1547': 0.20, 'T1053': 0.15, 'T1055': 0.20, 'T1027': 0.15, 'T1083': 0.15, 'T1071': 0.15 },
    'T1204': { 'T1059': 0.35, 'T1547': 0.20, 'T1027': 0.15, 'T1053': 0.15, 'T1071': 0.15 },
    'T1203': { 'T1055': 0.30, 'T1068': 0.25, 'T1059': 0.20, 'T1027': 0.15, 'T1071': 0.10 },

    // Persistence → Priv Esc / Defense Evasion
    'T1547': { 'T1055': 0.25, 'T1068': 0.20, 'T1027': 0.20, 'T1059': 0.15, 'T1083': 0.20 },
    'T1053': { 'T1059': 0.30, 'T1055': 0.20, 'T1027': 0.20, 'T1083': 0.15, 'T1070': 0.15 },
    'T1136': { 'T1078': 0.30, 'T1021': 0.25, 'T1070': 0.20, 'T1083': 0.15, 'T1057': 0.10 },

    // Privilege Escalation → Defense Evasion / Credential Access
    'T1055': { 'T1027': 0.25, 'T1003': 0.25, 'T1070': 0.15, 'T1083': 0.15, 'T1562': 0.20 },
    'T1068': { 'T1055': 0.20, 'T1003': 0.25, 'T1027': 0.20, 'T1070': 0.15, 'T1562': 0.20 },
    'T1548': { 'T1055': 0.25, 'T1003': 0.20, 'T1562': 0.20, 'T1027': 0.20, 'T1083': 0.15 },

    // Defense Evasion → Credential Access / Discovery
    'T1027': { 'T1003': 0.20, 'T1083': 0.20, 'T1057': 0.15, 'T1071': 0.20, 'T1070': 0.15, 'T1562': 0.10 },
    'T1070': { 'T1083': 0.25, 'T1057': 0.20, 'T1003': 0.20, 'T1021': 0.15, 'T1071': 0.20 },
    'T1562': { 'T1003': 0.25, 'T1083': 0.20, 'T1046': 0.20, 'T1027': 0.15, 'T1070': 0.20 },

    // Credential Access → Discovery / Lateral Movement
    'T1003': { 'T1021': 0.25, 'T1550': 0.20, 'T1083': 0.15, 'T1046': 0.15, 'T1057': 0.10, 'T1570': 0.15 },
    'T1110': { 'T1078': 0.30, 'T1021': 0.25, 'T1046': 0.20, 'T1083': 0.15, 'T1059': 0.10 },
    'T1558': { 'T1550': 0.30, 'T1021': 0.25, 'T1083': 0.15, 'T1057': 0.15, 'T1070': 0.15 },

    // Discovery → Lateral Movement / Collection
    'T1046': { 'T1021': 0.30, 'T1570': 0.20, 'T1083': 0.15, 'T1005': 0.15, 'T1057': 0.20 },
    'T1083': { 'T1005': 0.30, 'T1074': 0.20, 'T1021': 0.15, 'T1046': 0.15, 'T1119': 0.20 },
    'T1057': { 'T1055': 0.20, 'T1083': 0.20, 'T1046': 0.20, 'T1021': 0.20, 'T1005': 0.20 },

    // Lateral Movement → Collection / C2
    'T1021': { 'T1005': 0.25, 'T1083': 0.15, 'T1570': 0.20, 'T1074': 0.15, 'T1071': 0.15, 'T1046': 0.10 },
    'T1570': { 'T1059': 0.25, 'T1005': 0.20, 'T1083': 0.20, 'T1074': 0.15, 'T1021': 0.20 },
    'T1550': { 'T1021': 0.30, 'T1083': 0.20, 'T1005': 0.15, 'T1057': 0.15, 'T1570': 0.20 },

    // Collection → C2 / Exfiltration
    'T1005': { 'T1074': 0.30, 'T1041': 0.25, 'T1071': 0.20, 'T1119': 0.15, 'T1573': 0.10 },
    'T1074': { 'T1041': 0.30, 'T1048': 0.20, 'T1567': 0.15, 'T1071': 0.20, 'T1573': 0.15 },
    'T1119': { 'T1074': 0.30, 'T1005': 0.20, 'T1041': 0.20, 'T1071': 0.15, 'T1573': 0.15 },

    // Command and Control → Exfiltration / Impact
    'T1071': { 'T1041': 0.25, 'T1573': 0.20, 'T1568': 0.15, 'T1005': 0.15, 'T1074': 0.15, 'T1059': 0.10 },
    'T1573': { 'T1041': 0.30, 'T1048': 0.20, 'T1071': 0.15, 'T1568': 0.15, 'T1005': 0.20 },
    'T1568': { 'T1071': 0.30, 'T1573': 0.25, 'T1041': 0.20, 'T1059': 0.15, 'T1005': 0.10 },

    // Exfiltration → Impact / C2
    'T1041': { 'T1486': 0.25, 'T1489': 0.15, 'T1071': 0.20, 'T1048': 0.15, 'T1567': 0.15, 'T1074': 0.10 },
    'T1048': { 'T1486': 0.25, 'T1041': 0.20, 'T1489': 0.15, 'T1071': 0.20, 'T1567': 0.20 },
    'T1567': { 'T1041': 0.25, 'T1486': 0.20, 'T1048': 0.20, 'T1071': 0.20, 'T1489': 0.15 },

    // Impact → terminal (self-loops / re-attack)
    'T1486': { 'T1489': 0.30, 'T1529': 0.25, 'T1070': 0.25, 'T1041': 0.20 },
    'T1489': { 'T1486': 0.25, 'T1529': 0.30, 'T1070': 0.25, 'T1041': 0.20 },
    'T1529': { 'T1486': 0.30, 'T1489': 0.30, 'T1070': 0.20, 'T1041': 0.20 }
};

/**
 * Get the transition probability P(next | current)
 * Returns full distribution over all techniques for a given current technique
 */
export function getTransitionDistribution(currentTechniqueId) {
    const sparse = SPARSE_TRANSITIONS[currentTechniqueId] || {};
    const dist = {};
    let explicitSum = 0;

    // Set explicit probabilities
    for (const [tid, prob] of Object.entries(sparse)) {
        dist[tid] = prob;
        explicitSum += prob;
    }

    // Distribute remaining probability uniformly over non-specified techniques
    const remaining = Math.max(0, 1.0 - explicitSum);
    const unspecified = TECHNIQUE_IDS.filter(id => !(id in sparse) && id !== currentTechniqueId);
    const uniformProb = unspecified.length > 0 ? remaining / unspecified.length : 0;

    for (const tid of unspecified) {
        dist[tid] = uniformProb;
    }

    // Self-transition gets zero unless explicitly defined
    if (!(currentTechniqueId in sparse)) {
        dist[currentTechniqueId] = 0;
    }

    return dist;
}

/**
 * Get techniques for a specific tactic stage
 */
export function getTechniquesForTactic(tacticId) {
    return TECHNIQUES_BY_TACTIC[tacticId] || [];
}

/**
 * Get the tactic phase (0-13) for a technique
 */
export function getTacticPhase(techniqueId) {
    const tech = TECHNIQUE_BY_ID[techniqueId];
    if (!tech) return -1;
    const tactic = TACTIC_BY_ID[tech.tacticId];
    return tactic ? tactic.phase : -1;
}
