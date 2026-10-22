/**
 * Database Manager — Persistent Storage for Simulations & IOC Analyses (CJS)
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '../../data');
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'results.db');

let db = null;

/**
 * Initialize the database and create tables
 */
function initDB() {
    if (db) return db;

    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');

    // Create Tables
    db.exec(`
        CREATE TABLE IF NOT EXISTS simulations (
            id TEXT PRIMARY KEY,
            attacker_type TEXT,
            detection_coverage REAL,
            use_rl INTEGER,
            use_gt INTEGER,
            log_loss REAL,
            top3_hit_rate REAL,
            detection_rate REAL,
            prevention_rate REAL,
            total_steps INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS simulation_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sim_id TEXT,
            step INTEGER,
            tactic_id TEXT,
            technique_id TEXT,
            detected INTEGER,
            defender_action_id TEXT,
            reward REAL,
            FOREIGN KEY(sim_id) REFERENCES simulations(id)
        );

        CREATE TABLE IF NOT EXISTS ioc_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            ioc TEXT NOT NULL,
            type TEXT,
            threat_level TEXT,
            threat_score INTEGER DEFAULT 0,
            tactic_stage TEXT,
            tactic_phase INTEGER DEFAULT 0,
            most_probable_type TEXT,
            belief_entropy REAL DEFAULT 0,
            techniques_json TEXT,
            enrichment_json TEXT,
            feeds_used TEXT,
            defender_action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ioc_rl_experiences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            step INTEGER DEFAULT 0,
            state_key TEXT NOT NULL,
            action_idx INTEGER NOT NULL,
            reward REAL NOT NULL,
            next_state_key TEXT,
            done INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    return db;
}

// ═══════════════════════════════════════════════════════════════════════════
//  IOC ANALYSIS PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Save a single IOC analysis entry
 * @param {Object} entry - Analysis result from live-monitor
 * @returns {number} Inserted row ID
 */
function saveIOCAnalysis(entry) {
    if (!db) initDB();

    const stmt = db.prepare(`
        INSERT INTO ioc_analyses (
            session_id, ioc, type, threat_level, threat_score,
            tactic_stage, tactic_phase, most_probable_type, belief_entropy,
            techniques_json, enrichment_json, feeds_used, defender_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
        entry.sessionId || 'default',
        entry.ioc,
        entry.type || '',
        entry.threat?.level || 'NONE',
        entry.threat?.score || 0,
        entry.tacticStage?.tacticName || '',
        entry.tacticStage?.phase || 0,
        entry.mostProbableType?.type || '',
        entry.beliefEntropy || 0,
        JSON.stringify(entry.mappedTechniques?.map(t => t.techniqueId) || []),
        JSON.stringify(entry.enrichment || {}),
        JSON.stringify(entry.feedsUsed || []),
        entry.topAction || ''
    );

    return result.lastInsertRowid;
}

/**
 * Get recent IOC analyses
 */
function getIOCHistory(limit = 50) {
    if (!db) initDB();
    return db.prepare('SELECT * FROM ioc_analyses ORDER BY timestamp DESC LIMIT ?').all(limit);
}

/**
 * Get aggregate IOC statistics
 */
function getIOCStats() {
    if (!db) initDB();

    const total = db.prepare('SELECT COUNT(*) as count FROM ioc_analyses').get();
    const byThreat = db.prepare(
        'SELECT threat_level, COUNT(*) as count FROM ioc_analyses GROUP BY threat_level'
    ).all();
    const byType = db.prepare(
        'SELECT type, COUNT(*) as count FROM ioc_analyses GROUP BY type'
    ).all();
    const recentSessions = db.prepare(
        'SELECT DISTINCT session_id, COUNT(*) as ioc_count, MAX(timestamp) as last_active FROM ioc_analyses GROUP BY session_id ORDER BY last_active DESC LIMIT 10'
    ).all();

    return {
        totalIOCs: total.count,
        byThreatLevel: Object.fromEntries(byThreat.map(r => [r.threat_level, r.count])),
        byIOCType: Object.fromEntries(byType.map(r => [r.type, r.count])),
        recentSessions
    };
}

// ═══════════════════════════════════════════════════════════════════════════
//  RL EXPERIENCE REPLAY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Save an RL experience tuple (s, a, r, s', done)
 */
function saveRLExperience(exp) {
    if (!db) initDB();

    const stmt = db.prepare(`
        INSERT INTO ioc_rl_experiences (
            session_id, step, state_key, action_idx, reward, next_state_key, done
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
        exp.sessionId || 'default',
        exp.step || 0,
        exp.stateKey,
        exp.actionIdx,
        exp.reward,
        exp.nextStateKey || '',
        exp.done ? 1 : 0
    );
}

/**
 * Get RL experiences for replay training
 * @param {number} limit - Max experiences to retrieve
 * @returns {Array} Experience tuples
 */
function getRLExperiences(limit = 500) {
    if (!db) initDB();
    return db.prepare(
        'SELECT * FROM ioc_rl_experiences ORDER BY timestamp DESC LIMIT ?'
    ).all(limit);
}

/**
 * Get count of stored RL experiences
 */
function getRLExperienceCount() {
    if (!db) initDB();
    return db.prepare('SELECT COUNT(*) as count FROM ioc_rl_experiences').get().count;
}

// ═══════════════════════════════════════════════════════════════════════════
//  HISTORY DASHBOARD QUERIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Get combined history summary for dashboard
 */
function getHistorySummary() {
    if (!db) initDB();

    const iocStats = getIOCStats();
    const rlCount = getRLExperienceCount();

    // Recent IOC analyses (last 20)
    const recentIOCs = db.prepare(
        'SELECT id, ioc, type, threat_level, threat_score, most_probable_type, tactic_stage, defender_action, timestamp FROM ioc_analyses ORDER BY timestamp DESC LIMIT 20'
    ).all();

    return {
        iocs: {
            ...iocStats,
            recent: recentIOCs
        },
        rlExperiences: rlCount
    };
}

module.exports = {
    initDB,
    saveIOCAnalysis,
    getIOCHistory,
    getIOCStats,
    saveRLExperience,
    getRLExperiences,
    getRLExperienceCount,
    getHistorySummary
};
