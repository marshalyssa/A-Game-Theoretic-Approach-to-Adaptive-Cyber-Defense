/**
 * Integration Tests — Express CTI Server
 * 
 * Tests the backend proxy endpoints (`/api/health`, `/api/cti/lookup`)
 * by spawning the server as a child process and making HTTP requests.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';

const PORT = 3003; // Use a different port to avoid conflicts
const BASE_URL = `http://localhost:${PORT}`;
let serverProcess;

// ─── Setup & Teardown ──────────────────────────────────────────────────────

before(async () => {
    return new Promise((resolve, reject) => {
        // Spawn server with custom port and clear API keys to avoid network requests
        serverProcess = spawn('node', ['server.cjs'], {
            env: {
                ...process.env,
                PORT: PORT.toString(),
                OTX_API_KEY: '',
                VT_API_KEY: '',
                ABUSEIPDB_API_KEY: ''
            },
            stdio: 'ignore' // Ignore stdout/stderr to keep test output clean
        });

        serverProcess.on('error', (err) => {
            reject(new Error(`Failed to start server: ${err.message}`));
        });

        // Wait a short moment for server to bind to port
        setTimeout(() => {
            // Verify it's up
            http.get(`${BASE_URL}/api/health`, (res) => {
                if (res.statusCode === 200) resolve();
                else reject(new Error(`Server returned ${res.statusCode} on startup`));
            }).on('error', (err) => {
                reject(new Error(`Server not reachable: ${err.message}`));
            });
        }, 1000); // 1s boot time
    });
});

after(() => {
    if (serverProcess) {
        serverProcess.kill('SIGINT');
    }
});

// ─── Health Endpoint ───────────────────────────────────────────────────────

describe('GET /api/health', () => {
    it('returns status ok and feed configuration', async () => {
        const response = await fetch(`${BASE_URL}/api/health`);
        assert.equal(response.status, 200);

        const data = await response.json();
        assert.equal(data.status, 'ok');
        assert.ok(typeof data.feeds === 'object');
        assert.ok('otx' in data.feeds);
        assert.ok('virustotal' in data.feeds);
        assert.ok('abuseipdb' in data.feeds);
    });
});

// ─── Unified Lookup Endpoint ───────────────────────────────────────────────

describe('POST /api/cti/lookup', () => {
    it('rejects missing ioc or type', async () => {
        const response = await fetch(`${BASE_URL}/api/cti/lookup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc: '1.1.1.1' }) // Missing type
        });

        assert.equal(response.status, 400);
        const data = await response.json();
        assert.ok(data.error.includes('Missing type parameter'));
    });

    it('returns empty results if no feeds configured (graceful error handling)', async () => {
        const response = await fetch(`${BASE_URL}/api/cti/lookup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ioc: '8.8.8.8',
                type: 'ip',
                feeds: ['otx'] // Request OTX specifically
            })
        });

        assert.equal(response.status, 200);
        const data = await response.json();

        assert.equal(data.ioc, '8.8.8.8');
        assert.equal(data.type, 'ip');
        assert.ok('timestamp' in data);

        // Since we didn't pass API keys to the spawned process (or they might be invalid),
        // the server should return errors for the feeds rather than crashing.
        // E.g., { errors: { otx: "OTX_API_KEY not configured" } }
        assert.ok(typeof data.errors === 'object');
        if (data.errors.otx) {
            assert.ok(data.errors.otx.includes('OTX'));
        }
    });

    it('handles multiple feeds gracefully', async () => {
        const response = await fetch(`${BASE_URL}/api/cti/lookup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ioc: '1.1.1.1',
                type: 'ip',
                feeds: ['otx', 'virustotal', 'abuseipdb']
            })
        });

        assert.equal(response.status, 200);
        const data = await response.json();

        // Either the results or errors object must have keys for the requested feeds
        assert.ok(data.results.otx || data.errors.otx);
        assert.ok(data.results.virustotal || data.errors.virustotal);
        assert.ok(data.results.abuseipdb || data.errors.abuseipdb);
    });
});
