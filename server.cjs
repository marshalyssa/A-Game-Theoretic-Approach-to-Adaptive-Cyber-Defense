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
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ─── Rate Limiting ─────────────────────────────────────────────────────────
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window`
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP' }
});
app.use('/api/cti', apiLimiter);

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
    const selectedFeeds = feeds || ['otx', 'virustotal', 'abuseipdb'];

    // Run all feed lookups in parallel
    const promises = [];

    if (selectedFeeds.includes('otx')) {
        promises.push(
            lookupOTX(ioc, type)
                .then(data => { results.otx = data; })
                .catch(err => { errors.otx = err.message; })
        );
    }

    if (selectedFeeds.includes('virustotal')) {
        promises.push(
            lookupVirusTotal(ioc, type)
                .then(data => { results.virustotal = data; })
                .catch(err => { errors.virustotal = err.message; })
        );
    }

    if (selectedFeeds.includes('abuseipdb') && (type === 'ip' || type === 'ipv4' || type === 'ipv6')) {
        promises.push(
            lookupAbuseIPDB(ioc)
                .then(data => { results.abuseipdb = data; })
                .catch(err => { errors.abuseipdb = err.message; })
        );
    }

    await Promise.all(promises);

    res.json({ ioc, type, results, errors, timestamp: new Date().toISOString() });
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
    const sections = ['general', 'reputation'];
    const results = {};

    for (const section of sections) {
        const url = `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/${section}`;
        try {
            const response = await fetch(url, {
                headers: { 'X-OTX-API-KEY': apiKey, 'Accept': 'application/json' },
                signal: AbortSignal.timeout(8000)
            });

            if (!response.ok) {
                if (response.status === 404) {
                    results[section] = null;
                    continue;
                }
                throw new Error(`OTX ${section}: HTTP ${response.status}`);
            }
            results[section] = await response.json();
        } catch (e) {
            if (e.name === 'TimeoutError' || e.name === 'AbortError') {
                throw new Error(`OTX lookup timed out after 8s`);
            }
            throw e;
        }
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
        if (e.name === 'TimeoutError' || e.name === 'AbortError') throw new Error('VirusTotal API timed out after 8s');
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
        const data = await lookupAbuseIPDB(ioc);
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
        if (e.name === 'TimeoutError' || e.name === 'AbortError') throw new Error('AbuseIPDB timed out after 8s');
        throw e;
    }
}

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
