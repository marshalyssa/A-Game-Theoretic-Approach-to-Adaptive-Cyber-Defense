/**
 * Attacker Profiles — 4 Archetypes with Strategy Distributions
 * 
 * Each profile defines:
 * - strategyWeights: technique preference weights per tactic stage
 * - riskTolerance: [0,1] willingness to use detectable techniques
 * - persistence: [0,1] tendency to retry vs pivot after failure
 * - adaptability: [0,1] responsiveness to defender actions
 * - typicalChain: characteristic ATT&CK technique chain
 * - description: behavioral profile for UI display
 */

export const ATTACKER_TYPES = ['script_kiddie', 'organized_crime', 'apt_state', 'insider_threat'];

export const ATTACKER_PROFILES = {
    script_kiddie: {
        name: 'Script Kiddie',
        description: 'Low-skill attacker using publicly available tools. Noisy, opportunistic, low persistence.',
        riskTolerance: 0.8,    // Will use obvious, detectable techniques
        persistence: 0.2,      // Gives up quickly
        adaptability: 0.1,     // Doesn't adapt to defender response
        speed: 0.9,            // Acts fast, no patience
        // Prefers easy, low-cost techniques; avoids complex ones
        techniquePreferences: {
            'T1595': 0.9,   // Active Scanning
            'T1566': 0.7,   // Phishing
            'T1190': 0.8,   // Exploit Public-Facing App
            'T1059': 0.8,   // Command/Scripting
            'T1204': 0.7,   // User Execution
            'T1110': 0.9,   // Brute Force
            'T1046': 0.9,   // Network Scanning
            'T1053': 0.6,   // Scheduled Task
            'T1547': 0.5,   // Autostart
            'T1486': 0.7,   // Ransomware
            'T1489': 0.6,   // Service Stop
            'T1529': 0.5,   // System Shutdown
            'T1041': 0.4,   // Exfil over C2
        },
        // Typical attack chain
        typicalChain: ['T1595', 'T1190', 'T1059', 'T1046', 'T1110', 'T1486'],
        // Tactic stage probabilities (where they tend to stop or skip)
        tacticProgression: {
            'TA0043': 0.9,  // Often scans
            'TA0042': 0.1,  // Rarely preps infrastructure
            'TA0001': 0.9,  // Always tries initial access
            'TA0002': 0.8,  // Usually executes
            'TA0003': 0.3,  // Rarely persists
            'TA0004': 0.2,  // Rarely escalates
            'TA0005': 0.1,  // Almost never evades
            'TA0006': 0.5,  // Sometimes creds
            'TA0007': 0.6,  // Some discovery
            'TA0008': 0.2,  // Rarely lateral
            'TA0009': 0.3,  // Rarely collects
            'TA0011': 0.4,  // Basic C2
            'TA0010': 0.3,  // Sometimes exfil
            'TA0040': 0.7,  // Often impacts (ransomware)
        }
    },

    organized_crime: {
        name: 'Organized Crime',
        description: 'Financially motivated group. Moderate skill, good tooling, focused on data theft and ransomware.',
        riskTolerance: 0.5,
        persistence: 0.6,
        adaptability: 0.5,
        speed: 0.6,
        techniquePreferences: {
            'T1566': 0.9,   // Phishing (primary vector)
            'T1190': 0.7,   // Exploit public apps
            'T1059': 0.8,   // Scripting
            'T1204': 0.8,   // User execution
            'T1547': 0.7,   // Persistence
            'T1053': 0.6,   // Scheduled task
            'T1055': 0.6,   // Process injection
            'T1027': 0.7,   // Obfuscation
            'T1003': 0.8,   // Credential dumping
            'T1021': 0.7,   // Remote services
            'T1005': 0.8,   // Data from local
            'T1074': 0.7,   // Data staged
            'T1071': 0.7,   // C2 protocol
            'T1041': 0.8,   // Exfil over C2
            'T1486': 0.9,   // Ransomware
            'T1070': 0.5,   // Indicator removal
        },
        typicalChain: ['T1566', 'T1204', 'T1059', 'T1547', 'T1003', 'T1021', 'T1005', 'T1041', 'T1486'],
        tacticProgression: {
            'TA0043': 0.5,
            'TA0042': 0.4,
            'TA0001': 0.95,
            'TA0002': 0.9,
            'TA0003': 0.7,
            'TA0004': 0.5,
            'TA0005': 0.5,
            'TA0006': 0.8,
            'TA0007': 0.6,
            'TA0008': 0.7,
            'TA0009': 0.8,
            'TA0011': 0.7,
            'TA0010': 0.8,
            'TA0040': 0.9,
        }
    },

    apt_state: {
        name: 'APT / State Actor',
        description: 'Highly skilled, well-resourced, patient. Prioritizes stealth, long-term access, and intelligence gathering.',
        riskTolerance: 0.2,    // Very cautious
        persistence: 0.9,      // Extremely persistent
        adaptability: 0.9,     // Highly adaptive to defenses
        speed: 0.2,            // Patient, slow and methodical
        techniquePreferences: {
            'T1589': 0.8,   // Gather identity info
            'T1583': 0.9,   // Acquire infrastructure
            'T1588': 0.8,   // Obtain capabilities
            'T1566': 0.7,   // Spearphishing
            'T1078': 0.9,   // Valid accounts
            'T1203': 0.7,   // Client exploitation
            'T1055': 0.8,   // Process injection
            'T1068': 0.7,   // Priv esc exploit
            'T1027': 0.9,   // Obfuscation
            'T1070': 0.9,   // Indicator removal
            'T1562': 0.7,   // Impair defenses
            'T1558': 0.8,   // Kerberos tickets
            'T1003': 0.8,   // Credential dumping
            'T1550': 0.8,   // Alternate auth
            'T1005': 0.8,   // Data from local
            'T1119': 0.7,   // Automated collection
            'T1573': 0.9,   // Encrypted channel
            'T1568': 0.7,   // Dynamic resolution
            'T1567': 0.8,   // Exfil web service
            'T1048': 0.7,   // Alt protocol exfil
        },
        typicalChain: ['T1589', 'T1583', 'T1078', 'T1203', 'T1055', 'T1027', 'T1070', 'T1558', 'T1550', 'T1005', 'T1573', 'T1567'],
        tacticProgression: {
            'TA0043': 0.9,
            'TA0042': 0.9,
            'TA0001': 0.95,
            'TA0002': 0.85,
            'TA0003': 0.9,
            'TA0004': 0.85,
            'TA0005': 0.95,
            'TA0006': 0.9,
            'TA0007': 0.85,
            'TA0008': 0.8,
            'TA0009': 0.9,
            'TA0011': 0.95,
            'TA0010': 0.9,
            'TA0040': 0.2,  // Rarely destroys (wants stealth)
        }
    },

    insider_threat: {
        name: 'Insider Threat',
        description: 'Authorized user abusing access. Skips early kill chain stages. Focuses on collection and exfiltration.',
        riskTolerance: 0.4,
        persistence: 0.5,
        adaptability: 0.3,
        speed: 0.4,
        techniquePreferences: {
            'T1078': 0.95,  // Already has valid accounts
            'T1083': 0.9,   // File discovery
            'T1057': 0.7,   // Process discovery
            'T1005': 0.9,   // Data from local
            'T1074': 0.8,   // Data staging
            'T1119': 0.7,   // Automated collection
            'T1041': 0.7,   // Exfil over C2
            'T1567': 0.9,   // Exfil web service
            'T1048': 0.8,   // Alt protocol exfil
            'T1136': 0.6,   // Create account (backup access)
            'T1070': 0.7,   // Cover tracks
            'T1021': 0.5,   // Remote services
            'T1548': 0.6,   // Elevation abuse
        },
        typicalChain: ['T1078', 'T1083', 'T1005', 'T1074', 'T1567'],
        tacticProgression: {
            'TA0043': 0.2,  // Already inside
            'TA0042': 0.1,  // Already has access
            'TA0001': 0.3,  // Sometimes phishes others
            'TA0002': 0.4,  // Legitimate tools
            'TA0003': 0.5,  // Sometimes persists
            'TA0004': 0.4,  // Sometimes escalates
            'TA0005': 0.6,  // Covers tracks
            'TA0006': 0.3,  // Already has creds
            'TA0007': 0.9,  // Heavy discovery
            'TA0008': 0.4,  // Some lateral
            'TA0009': 0.95, // Primary goal
            'TA0011': 0.3,  // May not need C2
            'TA0010': 0.9,  // Primary goal
            'TA0040': 0.2,  // Rarely destructive
        }
    }
};

/**
 * Get the likelihood of an attacker type using a specific technique
 * P(technique | attacker_type) — used as likelihood in Bayesian update
 */
export function getTechniqueLikelihood(attackerType, techniqueId) {
    const profile = ATTACKER_PROFILES[attackerType];
    if (!profile) return 0.1;
    return profile.techniquePreferences[techniqueId] || 0.05; // Low baseline for unlisted techniques
}

/**
 * Select a technique for an attacker given their type and current tactic stage
 * Uses technique preferences weighted by risk tolerance and detection difficulty
 */
export function selectAttackerTechnique(attackerType, availableTechniques, defenderActions = []) {
    const profile = ATTACKER_PROFILES[attackerType];
    if (!profile || availableTechniques.length === 0) return null;

    // Calculate selection weights
    const weights = availableTechniques.map(tech => {
        const preference = profile.techniquePreferences[tech.id] || 0.05;
        // Risk-averse attackers avoid high-detection techniques
        const riskFactor = 1 - (1 - profile.riskTolerance) * (1 - tech.detectionDifficulty);
        // Adaptive attackers modify based on defender actions (simplified)
        let adaptFactor = 1.0;
        if (profile.adaptability > 0.5 && defenderActions.length > 0) {
            // If defender recently deployed EDR, prefer stealthier techniques
            const hasEdr = defenderActions.some(a => a === 'deploy_edr');
            const hasHunt = defenderActions.some(a => a === 'hunt_threat');
            if (hasEdr || hasHunt) {
                adaptFactor = 0.5 + 0.5 * tech.stealthRating;
            }
        }
        return preference * riskFactor * adaptFactor;
    });

    // Normalize and sample
    const totalWeight = weights.reduce((s, w) => s + w, 0);
    if (totalWeight === 0) return availableTechniques[0];

    const probs = weights.map(w => w / totalWeight);
    const rand = Math.random();
    let cumulative = 0;
    for (let i = 0; i < probs.length; i++) {
        cumulative += probs[i];
        if (rand <= cumulative) return availableTechniques[i];
    }
    return availableTechniques[availableTechniques.length - 1];
}

/**
 * Determine if attacker should progress to next tactic or retry current
 */
export function shouldProgress(attackerType, currentTacticId, wasDetected) {
    const profile = ATTACKER_PROFILES[attackerType];
    if (!profile) return true;

    const progressProb = profile.tacticProgression[currentTacticId] || 0.5;

    // If detected, persistent attackers retry, others might bail
    if (wasDetected) {
        const retryProb = profile.persistence;
        if (Math.random() < retryProb) return false; // Retry current tactic
        // Otherwise, skip forward (evasion)
        return true;
    }

    return Math.random() < progressProb;
}
