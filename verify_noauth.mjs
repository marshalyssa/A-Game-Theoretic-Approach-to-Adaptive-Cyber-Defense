async function testNoAuth() {
    const iocs = [
        { ioc: "139.162.19.123", type: "ip", name: "IP (ThreatFox/IP-API)" },
        { ioc: "acfd59afbb50331925cc3980e7c40044807e0a8bf44e0c38f9f0af9988ea060e", type: "sha256", name: "Hash (MalwareBazaar)" }
    ];

    for (const item of iocs) {
        console.log(`\n--- Testing ${item.name}: ${item.ioc} ---`);
        const start = Date.now();
        const res = await fetch('http://127.0.0.1:3000/api/cti/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                ioc: item.ioc, 
                type: item.type,
                feeds: ['threatfox', 'malwarebazaar', 'ipapi'] 
            })
        });
        const data = await res.json();
        console.log(`Duration: ${Date.now() - start}ms`);
        console.log('Feeds Found:', Object.keys(data.results || {}));
        if (data.results.ipapi) console.log('IP-API Country:', data.results.ipapi.country);
        if (data.results.threatfox) console.log('ThreatFox Results:', data.results.threatfox.malicious_count);
        if (data.results.malwarebazaar) console.log('MalwareBazaar Signature:', data.results.malwarebazaar.signature);
    }
}
testNoAuth();
