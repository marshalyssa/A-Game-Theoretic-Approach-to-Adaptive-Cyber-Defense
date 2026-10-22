/**
 * Express Backend — CTI API Proxy Server
 * 
 * Serves static files + proxies requests to CTI APIs (AlienVault OTX, VirusTotal, AbuseIPDB)
 * to bypass browser CORS restrictions. API keys are stored in .env, never sent to client.
$env:PATH = "C:\Program Files\nodejs;" + $env:PATH; node server.js 
*/

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ─── Database Manager ──────────────────────────────────────────────────────
const db = require('./js/engine/db-manager.cjs');
db.initDB();

// ─── History Dashboard Endpoints ───────────────────────────────────────────

app.get('/api/history/summary', (req, res) => {
    try {
        const summary = db.getHistorySummary();
        res.json(summary);
    } catch (err) {
        console.error('DB Error:', err);
        res.status(500).json({ error: 'Failed to fetch history summary' });
    }
});

// ─── IOC Analysis Persistence ──────────────────────────────────────────────
app.post('/api/ioc/save', (req, res) => {
    try {
        const rowId = db.saveIOCAnalysis(req.body);
        res.json({ success: true, id: rowId });
    } catch (err) {
        console.error('IOC DB Error:', err);
        res.status(500).json({ error: 'Failed to save IOC analysis' });
    }
});

app.get('/api/ioc/history', (req, res) => {
    try {
        const results = db.getIOCHistory(parseInt(req.query.limit) || 50);
        res.json(results);
    } catch (err) {
        console.error('IOC DB Error:', err);
        res.status(500).json({ error: 'Failed to fetch IOC history' });
    }
});

app.get('/api/ioc/stats', (req, res) => {
    try {
        const stats = db.getIOCStats();
        res.json(stats);
    } catch (err) {
        console.error('IOC DB Error:', err);
        res.status(500).json({ error: 'Failed to fetch IOC stats' });
    }
});

// ─── RL Experience Replay ──────────────────────────────────────────────────
app.post('/api/ioc/rl-experience', (req, res) => {
    try {
        db.saveRLExperience(req.body);
        res.json({ success: true });
    } catch (err) {
        console.error('RL DB Error:', err);
        res.status(500).json({ error: 'Failed to save RL experience' });
    }
});

app.get('/api/ioc/rl-experiences', (req, res) => {
    try {
        const exps = db.getRLExperiences(parseInt(req.query.limit) || 500);
        res.json({ count: exps.length, experiences: exps });
    } catch (err) {
        console.error('RL DB Error:', err);
        res.status(500).json({ error: 'Failed to fetch RL experiences' });
    }
});

app.post('/api/ioc/rl-replay', (req, res) => {
    try {
        const exps = db.getRLExperiences(parseInt(req.body.limit) || 500);
        if (exps.length === 0) {
            return res.json({ success: false, message: 'No experiences stored yet', trained: 0 });
        }
        // Return experiences for client-side RL replay
        // The client will apply these to its own Q-table
        res.json({
            success: true,
            trained: exps.length,
            experiences: exps.map(e => ({
                stateKey: e.state_key,
                actionIdx: e.action_idx,
                reward: e.reward,
                nextStateKey: e.next_state_key,
                done: !!e.done
            }))
        });
    } catch (err) {
        console.error('RL Replay Error:', err);
        res.status(500).json({ error: 'Failed to run RL replay' });
    }
});

// ─── Rate Limiting ─────────────────────────────────────────────────────────
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window`
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP' }
});
app.use('/api/cti', apiLimiter);

// ─── CTI Cache ─────────────────────────────────────────────────────────────
const ctiCache = new Map();
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

function getCachedCTI(feed, ioc, type) {
    const key = `${feed}:${type}:${ioc}`;
    const cached = ctiCache.get(key);
    if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
        return cached.data;
    }
    return null;
}

function setCachedCTI(feed, ioc, type, data) {
    const key = `${feed}:${type}:${ioc}`;
    ctiCache.set(key, { data, timestamp: Date.now() });
    
    if (ctiCache.size > 2000) { // Larger limit for granular cache
        const oldestKey = ctiCache.keys().next().value;
        ctiCache.delete(oldestKey);
    }
}

// ─── Input Validation Helper ───────────────────────────────────────────────
function validateInput(ioc, type, requireType = true) {
    if (!ioc) return 'Missing ioc parameter';
    if (requireType && !type) return 'Missing type parameter';
    if (typeof ioc !== 'string' || ioc.length > 256) return 'Invalid ioc parameter: must be string <= 256 chars';
    if (type !== undefined && (typeof type !== 'string' || type.length > 32)) return 'Invalid type parameter';
    return null;
}

// ─── Health Check ──────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        feeds: {
            otx: !!process.env.OTX_API_KEY,
            virustotal: !!process.env.VT_API_KEY,
            abuseipdb: !!process.env.ABUSEIPDB_API_KEY
        }
    });
});

// ─── Unified IOC Lookup ────────────────────────────────────────────────────
app.post('/api/cti/lookup', async (req, res) => {
    const { ioc, type, feeds } = req.body;

    const validationError = validateInput(ioc, type);
    if (validationError) {
        return res.status(400).json({ error: validationError });
    }

    const results = {};
    const errors = {};
    const selectedFeeds = feeds || ['otx', 'virustotal', 'abuseipdb', 'threatfox', 'malwarebazaar', 'ipapi'];

    // Run all feed lookups in parallel, checking cache for each
    const promises = selectedFeeds.map(async (feed) => {
        try {
            // 1. Check Cache first
            const cached = getCachedCTI(feed, ioc, type);
            if (cached) {
                results[feed] = cached;
                return;
            }

            // 2. Choose lookup function
            let data = null;
            if (feed === 'otx') data = await lookupOTX(ioc, type);
            else if (feed === 'virustotal') data = await lookupVirusTotal(ioc, type);
            else if (feed === 'abuseipdb' && (type === 'ip' || type === 'ipv4' || type === 'ipv6')) data = await lookupAbuseIPDB(ioc);
            else if (feed === 'threatfox') data = await lookupThreatFox(ioc);
            else if (feed === 'malwarebazaar' && (type === 'hash' || type === 'md5' || type === 'sha1' || type === 'sha256')) data = await lookupMalwareBazaar(ioc);
            else if (feed === 'ipapi' && (type === 'ip' || type === 'ipv4' || type === 'ipv6')) data = await lookupIPAPI(ioc);

            if (data) {
                results[feed] = data;
                setCachedCTI(feed, ioc, type, data);
            }
        } catch (err) {
            errors[feed] = err.message;
        }
    });

    await Promise.all(promises);

    res.json({ 
        ioc, 
        type, 
        results, 
        errors, 
        timestamp: new Date().toISOString() 
    });
});

// ─── AlienVault OTX ────────────────────────────────────────────────────────
app.post('/api/cti/otx', async (req, res) => {
    try {
        const { ioc, type } = req.body;
        const validationError = validateInput(ioc, type);
        if (validationError) return res.status(400).json({ error: validationError });
        const data = await lookupOTX(ioc, type);
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

async function lookupOTX(ioc, type) {
    const apiKey = process.env.OTX_API_KEY;
    if (!apiKey) throw new Error('OTX_API_KEY not configured');

    // Map our types to OTX indicator types
    const otxTypeMap = {
        'ip': 'IPv4', 'ipv4': 'IPv4', 'ipv6': 'IPv6',
        'domain': 'domain', 'hostname': 'hostname',
        'url': 'url',
        'hash': 'file', 'md5': 'file', 'sha1': 'file', 'sha256': 'file'
    };

    const otxType = otxTypeMap[type.toLowerCase()] || 'IPv4';
    
    // OTX supports different sections for different indicator types
    // reputation is only valid for IPv4/IPv6
    const sections = ['general'];
    if (otxType === 'IPv4' || otxType === 'IPv6') {
        sections.push('reputation');
    }

    const results = {};
    const sectionErrors = [];

    for (const section of sections) {
        const url = `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/${section}`;
        let attempts = 0;
        const maxAttempts = 3;
        let success = false;

        // Use longer timeout for reputation section (30s) vs others (15s)
        const timeoutMs = section === 'reputation' ? 30000 : 15000;

        while (attempts < maxAttempts && !success) {
            attempts++;
            try {
                const response = await fetch(url, {
                    headers: { 'X-OTX-API-KEY': apiKey, 'Accept': 'application/json' },
                    signal: AbortSignal.timeout(timeoutMs)
                });

                if (response.ok) {
                    results[section] = await response.json();
                    success = true;
                } else if (response.status === 404) {
                    results[section] = null;
                    success = true;
                } else if (response.status >= 500 && attempts < maxAttempts) {
                    // Retry on server errors
                    await new Promise(resolve => setTimeout(resolve, 1000 * attempts));
                    continue;
                } else {
                    const errorBody = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorBody} (URL: ${url})`);
                }
            } catch (e) {
                const isTimeout = e.name === 'TimeoutError' || e.name === 'AbortError';
                if (isTimeout && attempts < maxAttempts) {
                    console.warn(`OTX ${section} timeout (attempt ${attempts}), retrying…`);
                    continue;
                }
                sectionErrors.push(`${section}: ${e.message}`);
                console.error(`OTX Error [${section}]:`, e.message);
                break;
            }
        }
    }

    // If both sections failed, throw consolidated error
    if (Object.keys(results).length === 0 && sectionErrors.length > 0) {
        throw new Error(`OTX lookup failed: ${sectionErrors.join(', ')}`);
    }

    // Extract ATT&CK technique IDs from pulse data
    const attackIds = [];
    const pulses = [];
    if (results.general && results.general.pulse_info) {
        const pulseList = results.general.pulse_info.pulses || [];
        for (const pulse of pulseList.slice(0, 10)) { // Top 10 pulses
            pulses.push({
                id: pulse.id,
                name: pulse.name,
                description: (pulse.description || '').substring(0, 200),
                created: pulse.created,
                tags: pulse.tags || [],
                attack_ids: pulse.attack_ids || []
            });
            if (pulse.attack_ids) {
                for (const aid of pulse.attack_ids) {
                    if (aid.id && !attackIds.includes(aid.id)) {
                        attackIds.push(aid.id);
                    }
                }
            }
        }
    }

    return {
        source: 'otx',
        ioc,
        type: otxType,
        reputation: results.reputation,
        pulseCount: results.general?.pulse_info?.count || 0,
        pulses,
        attackIds, // MITRE ATT&CK technique IDs
        country: results.general?.country_code || null,
        asn: results.general?.asn || null
    };
}

// ─── VirusTotal ────────────────────────────────────────────────────────────
app.post('/api/cti/virustotal', async (req, res) => {
    try {
        const { ioc, type } = req.body;
        const validationError = validateInput(ioc, type);
        if (validationError) return res.status(400).json({ error: validationError });
        const data = await lookupVirusTotal(ioc, type);
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

async function lookupVirusTotal(ioc, type) {
    const apiKey = process.env.VT_API_KEY;
    if (!apiKey) throw new Error('VT_API_KEY not configured');

    // Map types to VT endpoints
    const vtEndpoints = {
        'ip': 'ip_addresses', 'ipv4': 'ip_addresses', 'ipv6': 'ip_addresses',
        'domain': 'domains', 'hostname': 'domains',
        'url': 'urls',
        'hash': 'files', 'md5': 'files', 'sha1': 'files', 'sha256': 'files'
    };

    const endpoint = vtEndpoints[type.toLowerCase()] || 'ip_addresses';

    // For URLs, VirusTotal needs a base64-encoded URL identifier
    let identifier = ioc;
    if (endpoint === 'urls') {
        identifier = Buffer.from(ioc).toString('base64').replace(/=+$/, '');
    }

    const url = `https://www.virustotal.com/api/v3/${endpoint}/${identifier}`;
    try {
        const response = await fetch(url, {
            headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok) {
            throw new Error(`VirusTotal: HTTP ${response.status}`);
        }

        const json = await response.json();
        const attrs = json.data?.attributes || {};
        const stats = attrs.last_analysis_stats || {};

        // Extract MITRE ATT&CK from sandbox results if file hash
        let mitreAttack = [];
        if (endpoint === 'files' && json.data?.id) {
            try {
                const mitreUrl = `https://www.virustotal.com/api/v3/files/${json.data.id}/behaviour_mitre_trees`;
                const mitreResp = await fetch(mitreUrl, {
                    headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
                    signal: AbortSignal.timeout(5000)
                });
                if (mitreResp.ok) {
                    const mitreData = await mitreResp.json();
                    mitreAttack = parseMitreTree(mitreData);
                }
            } catch (e) { /* MITRE data optional, ignore timeouts here */ }
        }

        return {
            source: 'virustotal',
            ioc,
            type: endpoint,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            reputation: attrs.reputation,
            country: attrs.country || null,
            asn: attrs.asn || null,
            asOwner: attrs.as_owner || null,
            tags: attrs.tags || [],
            mitreAttack,
            lastAnalysisDate: attrs.last_analysis_date
                ? new Date(attrs.last_analysis_date * 1000).toISOString()
                : null
        };
    } catch (e) {
        if (e.name === 'TimeoutError' || e.name === 'AbortError') throw new Error('VirusTotal API timed out after 15s');
        throw e;
    }
}

function parseMitreTree(data) {
    const techniques = [];
    const trees = data.data || [];
    for (const sandbox of trees) {
        const tactics = sandbox.tactics || [];
        for (const tactic of tactics) {
            const techs = tactic.techniques || [];
            for (const tech of techs) {
                if (tech.id && !techniques.find(t => t.id === tech.id)) {
                    techniques.push({
                        id: tech.id,
                        name: tech.name || tech.id,
                        tactic: tactic.id || ''
                    });
                }
            }
        }
    }
    return techniques;
}

// ─── AbuseIPDB ─────────────────────────────────────────────────────────────
app.post('/api/cti/abuseipdb', async (req, res) => {
    try {
        const { ioc } = req.body;
        const validationError = validateInput(ioc, undefined, false);
        if (validationError) return res.status(400).json({ error: validationError });
        
        const cached = getCachedCTI('abuseipdb', ioc, 'ip');
        if (cached) return res.json(cached);

        const data = await lookupAbuseIPDB(ioc);
        if (data) setCachedCTI('abuseipdb', ioc, 'ip', data);
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

async function lookupAbuseIPDB(ioc) {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) throw new Error('ABUSEIPDB_API_KEY not configured');

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90&verbose`;
    try {
        const response = await fetch(url, {
            headers: { 'Key': apiKey, 'Accept': 'application/json' },
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok) {
            throw new Error(`AbuseIPDB: HTTP ${response.status}`);
        }

        const json = await response.json();
        const d = json.data || {};

        // Extract abuse categories from recent reports
        const categories = new Set();
        if (d.reports) {
            for (const report of d.reports.slice(0, 20)) {
                if (report.categories) {
                    for (const cat of report.categories) {
                        categories.add(cat);
                    }
                }
            }
        }

        return {
            source: 'abuseipdb',
            ioc,
            abuseConfidenceScore: d.abuseConfidenceScore || 0,
            totalReports: d.totalReports || 0,
            numDistinctUsers: d.numDistinctUsers || 0,
            isWhitelisted: d.isWhitelisted || false,
            isp: d.isp || null,
            domain: d.domain || null,
            country: d.countryCode || null,
            usageType: d.usageType || null,
            categories: [...categories], // Abuse category IDs
            lastReportedAt: d.lastReportedAt || null
        };
    } catch (e) {
        if (e.name === 'TimeoutError' || e.name === 'AbortError') throw new Error('AbuseIPDB timed out after 15s');
        throw e;
    }
}

// ─── No-Auth TI Feeds ──────────────────────────────────────────────────────
async function lookupThreatFox(ioc) {
    const url = 'https://threatfox-api.abuse.ch/api/v1/';
    try {
        const response = await fetch(url, {
            method: 'POST',
            body: JSON.stringify({ query: 'search_ioc', search_term: ioc }),
            signal: AbortSignal.timeout(15000)
        });
        if (!response.ok) return null;
        const data = await response.json();
        if (data.query_status !== 'ok') return null;
        
        const results = data.data || [];
        return {
            source: 'threatfox',
            ioc,
            results: results.slice(0, 5).map(r => ({
                id: r.id,
                threat_type: r.threat_type,
                threat_type_desc: r.threat_type_desc,
                malware: r.malware_printable,
                confidence: r.confidence_level,
                tags: r.tags || [],
                first_seen: r.first_seen,
                last_seen: r.last_seen
            })),
            malicious_count: results.length
        };
    } catch (e) {
        console.warn('ThreatFox lookup error:', e.message);
        return null;
    }
}

async function lookupMalwareBazaar(hash) {
    const url = 'https://mb-api.abuse.ch/api/v1/';
    try {
        const response = await fetch(url, {
            method: 'POST',
            body: JSON.stringify({ query: 'get_info', hash: hash }),
            signal: AbortSignal.timeout(15000)
        });
        if (!response.ok) return null;
        const data = await response.json();
        if (data.query_status !== 'ok') return null;

        const d = data.data?.[0] || {};
        return {
            source: 'malwarebazaar',
            hash,
            file_name: d.file_name,
            file_type: d.file_type,
            signature: d.signature,
            malware_family: d.intelligence?.malware_family,
            tags: d.tags || [],
            delivery_method: d.intelligence?.delivery_method,
            origin_country: d.origin_country,
            sha1: d.sha1,
            sha256: d.sha256,
            md5: d.md5
        };
    } catch (e) {
        console.warn('MalwareBazaar lookup error:', e.message);
        return null;
    }
}

async function lookupIPAPI(ip) {
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`;
    try {
        const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
        if (!response.ok) return null;
        const data = await response.json();
        if (data.status !== 'success') return null;
        return {
            source: 'ip-api',
            ioc: ip,
            country: data.country,
            countryCode: data.countryCode,
            city: data.city,
            isp: data.isp,
            org: data.org,
            as: data.as,
            lat: data.lat,
            lon: data.lon,
            timezone: data.timezone
        };
    } catch (e) {
        console.warn('IP-API lookup error:', e.message);
        return null;
    }
}

// ─── RL Agent Q-Table Persistence ──────────────────────────────────────────
const QTABLE_FILE = path.join(__dirname, 'data', 'q-table.json');

app.get('/api/rl/q-table', (req, res) => {
    try {
        if (fs.existsSync(QTABLE_FILE)) {
            const data = fs.readFileSync(QTABLE_FILE, 'utf-8');
            res.json(JSON.parse(data));
        } else {
            res.status(404).json({ error: 'No saved Q-table found' });
        }
    } catch (err) {
        console.error('Error reading Q-table:', err);
        res.status(500).json({ error: 'Failed to read Q-table' });
    }
});

app.post('/api/rl/q-table', (req, res) => {
    try {
        fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
        fs.writeFileSync(QTABLE_FILE, JSON.stringify(req.body, null, 2));
        res.json({ success: true });
    } catch (err) {
        console.error('Error saving Q-table:', err);
        res.status(500).json({ error: 'Failed to save Q-table' });
    }
});

// ─── Start Server ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n  ⚔️  Cybersecurity Decision Agent Server`);
    console.log(`  ─────────────────────────────────────────`);
    console.log(`  🌐 http://localhost:${PORT}`);
    console.log(`  📡 CTI Feeds:`);
    console.log(`     OTX:       ${process.env.OTX_API_KEY ? '✓ configured' : '✗ no key'}`);
    console.log(`     VirusTotal: ${process.env.VT_API_KEY ? '✓ configured' : '✗ no key'}`);
    console.log(`     AbuseIPDB:  ${process.env.ABUSEIPDB_API_KEY ? '✓ configured' : '✗ no key'}`);
    console.log('');
});
