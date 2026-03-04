/**
 * Defender Actions — 15 defensive actions with costs, effects, and effectiveness
 * 
 * Each action has:
 * - cost: [0,1] operational cost to execute
 * - disruption: [0,1] impact on legitimate operations
 * - falsePositiveRate: [0,1] probability of false positive from this action
 * - effectiveness: { tacticId: probability_of_preventing } mapping of effectiveness per tactic
 * - detectionBonus: [0,1] how much this improves detection coverage
 * - description: for UI display
 */

export const DEFENDER_ACTIONS = {
    monitor: {
        name: 'Monitor',
        description: 'Passive monitoring — observe and log without intervention',
        cost: 0.05,
        disruption: 0.0,
        falsePositiveRate: 0.0,
        detectionBonus: 0.1,
        effectiveness: {
            'TA0043': 0.05, 'TA0042': 0.02, 'TA0001': 0.05, 'TA0002': 0.05,
            'TA0003': 0.05, 'TA0004': 0.05, 'TA0005': 0.03, 'TA0006': 0.05,
            'TA0007': 0.05, 'TA0008': 0.05, 'TA0009': 0.05, 'TA0011': 0.05,
            'TA0010': 0.05, 'TA0040': 0.05
        }
    },
    block_ip: {
        name: 'Block IP',
        description: 'Block specific source IP addresses at firewall',
        cost: 0.1,
        disruption: 0.1,
        falsePositiveRate: 0.15,
        detectionBonus: 0.0,
        effectiveness: {
            'TA0043': 0.6, 'TA0042': 0.1, 'TA0001': 0.5, 'TA0002': 0.1,
            'TA0003': 0.05, 'TA0004': 0.05, 'TA0005': 0.05, 'TA0006': 0.3,
            'TA0007': 0.1, 'TA0008': 0.2, 'TA0009': 0.1, 'TA0011': 0.4,
            'TA0010': 0.3, 'TA0040': 0.05
        }
    },
    isolate_host: {
        name: 'Isolate Host',
        description: 'Network-isolate a compromised endpoint',
        cost: 0.3,
        disruption: 0.5,
        falsePositiveRate: 0.1,
        detectionBonus: 0.0,
        effectiveness: {
            'TA0043': 0.1, 'TA0042': 0.05, 'TA0001': 0.2, 'TA0002': 0.3,
            'TA0003': 0.2, 'TA0004': 0.2, 'TA0005': 0.1, 'TA0006': 0.3,
            'TA0007': 0.3, 'TA0008': 0.8, 'TA0009': 0.5, 'TA0011': 0.7,
            'TA0010': 0.8, 'TA0040': 0.4
        }
    },
    patch_vuln: {
        name: 'Patch Vulnerability',
        description: 'Apply security patches to known vulnerabilities',
        cost: 0.25,
        disruption: 0.15,
        falsePositiveRate: 0.02,
        detectionBonus: 0.0,
        effectiveness: {
            'TA0043': 0.1, 'TA0042': 0.05, 'TA0001': 0.7, 'TA0002': 0.4,
            'TA0003': 0.1, 'TA0004': 0.6, 'TA0005': 0.1, 'TA0006': 0.2,
            'TA0007': 0.05, 'TA0008': 0.2, 'TA0009': 0.05, 'TA0011': 0.05,
            'TA0010': 0.05, 'TA0040': 0.1
        }
    },
    deploy_edr: {
        name: 'Deploy EDR',
        description: 'Deploy or upgrade endpoint detection and response agents',
        cost: 0.4,
        disruption: 0.1,
        falsePositiveRate: 0.12,
        detectionBonus: 0.35,
        effectiveness: {
            'TA0043': 0.1, 'TA0042': 0.05, 'TA0001': 0.2, 'TA0002': 0.5,
            'TA0003': 0.4, 'TA0004': 0.4, 'TA0005': 0.3, 'TA0006': 0.4,
            'TA0007': 0.3, 'TA0008': 0.3, 'TA0009': 0.3, 'TA0011': 0.2,
            'TA0010': 0.3, 'TA0040': 0.4
        }
    },
    hunt_threat: {
        name: 'Threat Hunt',
        description: 'Proactive threat hunting by security analysts',
        cost: 0.5,
        disruption: 0.05,
        falsePositiveRate: 0.08,
        detectionBonus: 0.4,
        effectiveness: {
            'TA0043': 0.2, 'TA0042': 0.1, 'TA0001': 0.3, 'TA0002': 0.4,
            'TA0003': 0.6, 'TA0004': 0.3, 'TA0005': 0.4, 'TA0006': 0.4,
            'TA0007': 0.3, 'TA0008': 0.5, 'TA0009': 0.4, 'TA0011': 0.5,
            'TA0010': 0.4, 'TA0040': 0.3
        }
    },
    deceive_honeypot: {
        name: 'Deploy Honeypot',
        description: 'Deploy deceptive honeypot systems to attract and identify attackers',
        cost: 0.3,
        disruption: 0.02,
        falsePositiveRate: 0.05,
        detectionBonus: 0.3,
        effectiveness: {
            'TA0043': 0.5, 'TA0042': 0.05, 'TA0001': 0.3, 'TA0002': 0.2,
            'TA0003': 0.1, 'TA0004': 0.1, 'TA0005': 0.05, 'TA0006': 0.3,
            'TA0007': 0.5, 'TA0008': 0.6, 'TA0009': 0.4, 'TA0011': 0.2,
            'TA0010': 0.2, 'TA0040': 0.1
        }
    },
    restrict_network: {
        name: 'Restrict Network',
        description: 'Tighten network segmentation and firewall rules',
        cost: 0.25,
        disruption: 0.3,
        falsePositiveRate: 0.1,
        detectionBonus: 0.05,
        effectiveness: {
            'TA0043': 0.3, 'TA0042': 0.05, 'TA0001': 0.3, 'TA0002': 0.1,
            'TA0003': 0.1, 'TA0004': 0.1, 'TA0005': 0.05, 'TA0006': 0.1,
            'TA0007': 0.2, 'TA0008': 0.7, 'TA0009': 0.2, 'TA0011': 0.5,
            'TA0010': 0.6, 'TA0040': 0.2
        }
    },
    update_siem_rules: {
        name: 'Update SIEM Rules',
        description: 'Update SIEM detection rules and correlation logic',
        cost: 0.2,
        disruption: 0.02,
        falsePositiveRate: 0.15,
        detectionBonus: 0.25,
        effectiveness: {
            'TA0043': 0.2, 'TA0042': 0.1, 'TA0001': 0.3, 'TA0002': 0.3,
            'TA0003': 0.3, 'TA0004': 0.2, 'TA0005': 0.2, 'TA0006': 0.3,
            'TA0007': 0.2, 'TA0008': 0.3, 'TA0009': 0.3, 'TA0011': 0.3,
            'TA0010': 0.3, 'TA0040': 0.2
        }
    },
    rotate_credentials: {
        name: 'Rotate Credentials',
        description: 'Force credential rotation across affected systems',
        cost: 0.2,
        disruption: 0.2,
        falsePositiveRate: 0.03,
        detectionBonus: 0.0,
        effectiveness: {
            'TA0043': 0.05, 'TA0042': 0.05, 'TA0001': 0.4, 'TA0002': 0.1,
            'TA0003': 0.3, 'TA0004': 0.2, 'TA0005': 0.05, 'TA0006': 0.7,
            'TA0007': 0.05, 'TA0008': 0.5, 'TA0009': 0.1, 'TA0011': 0.1,
            'TA0010': 0.1, 'TA0040': 0.05
        }
    },
    backup: {
        name: 'Backup Systems',
        description: 'Create and verify system backups for recovery',
        cost: 0.15,
        disruption: 0.05,
        falsePositiveRate: 0.0,
        detectionBonus: 0.0,
        effectiveness: {
            'TA0043': 0.0, 'TA0042': 0.0, 'TA0001': 0.0, 'TA0002': 0.0,
            'TA0003': 0.0, 'TA0004': 0.0, 'TA0005': 0.0, 'TA0006': 0.0,
            'TA0007': 0.0, 'TA0008': 0.0, 'TA0009': 0.0, 'TA0011': 0.0,
            'TA0010': 0.0, 'TA0040': 0.7
        }
    },
    incident_response: {
        name: 'Incident Response',
        description: 'Activate full incident response procedures',
        cost: 0.7,
        disruption: 0.4,
        falsePositiveRate: 0.05,
        detectionBonus: 0.3,
        effectiveness: {
            'TA0043': 0.3, 'TA0042': 0.2, 'TA0001': 0.5, 'TA0002': 0.6,
            'TA0003': 0.6, 'TA0004': 0.5, 'TA0005': 0.4, 'TA0006': 0.5,
            'TA0007': 0.4, 'TA0008': 0.6, 'TA0009': 0.5, 'TA0011': 0.6,
            'TA0010': 0.6, 'TA0040': 0.5
        }
    },
    educate_users: {
        name: 'Educate Users',
        description: 'Deploy security awareness training for end users',
        cost: 0.15,
        disruption: 0.1,
        falsePositiveRate: 0.0,
        detectionBonus: 0.05,
        effectiveness: {
            'TA0043': 0.1, 'TA0042': 0.05, 'TA0001': 0.5, 'TA0002': 0.3,
            'TA0003': 0.05, 'TA0004': 0.05, 'TA0005': 0.05, 'TA0006': 0.3,
            'TA0007': 0.1, 'TA0008': 0.05, 'TA0009': 0.1, 'TA0011': 0.05,
            'TA0010': 0.1, 'TA0040': 0.1
        }
    },
    accept_risk: {
        name: 'Accept Risk',
        description: 'Acknowledge the risk and take no action (lowest cost, no protection)',
        cost: 0.0,
        disruption: 0.0,
        falsePositiveRate: 0.0,
        detectionBonus: 0.0,
        effectiveness: {
            'TA0043': 0.0, 'TA0042': 0.0, 'TA0001': 0.0, 'TA0002': 0.0,
            'TA0003': 0.0, 'TA0004': 0.0, 'TA0005': 0.0, 'TA0006': 0.0,
            'TA0007': 0.0, 'TA0008': 0.0, 'TA0009': 0.0, 'TA0011': 0.0,
            'TA0010': 0.0, 'TA0040': 0.0
        }
    },
    full_lockdown: {
        name: 'Full Lockdown',
        description: 'Maximum security posture — severely restricts all operations',
        cost: 0.9,
        disruption: 0.9,
        falsePositiveRate: 0.3,
        detectionBonus: 0.1,
        effectiveness: {
            'TA0043': 0.7, 'TA0042': 0.3, 'TA0001': 0.8, 'TA0002': 0.7,
            'TA0003': 0.5, 'TA0004': 0.5, 'TA0005': 0.3, 'TA0006': 0.6,
            'TA0007': 0.4, 'TA0008': 0.9, 'TA0009': 0.6, 'TA0011': 0.8,
            'TA0010': 0.9, 'TA0040': 0.6
        }
    }
};

export const DEFENDER_ACTION_IDS = Object.keys(DEFENDER_ACTIONS);

/**
 * Get effectiveness of a defender action against a specific tactic
 */
export function getActionEffectiveness(actionId, tacticId) {
    const action = DEFENDER_ACTIONS[actionId];
    if (!action) return 0;
    return action.effectiveness[tacticId] || 0;
}

/**
 * Get the full action object for a given action ID
 */
export function getAction(actionId) {
    return DEFENDER_ACTIONS[actionId] || null;
}
