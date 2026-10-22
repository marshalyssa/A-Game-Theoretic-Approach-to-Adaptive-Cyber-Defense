async function test() {
    const payload = {
        ioc: "1.1.1.1",
        type: "ip",
        feeds: ["otx"]
    };

    console.log('--- Phase 1: Initial Lookup (Network) ---');
    const start1 = Date.now();
    const res1 = await fetch('http://127.0.0.1:3000/api/cti/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data1 = await res1.json();
    console.log(`Duration: ${Date.now() - start1}ms`);
    console.log(`Cached: ${data1.cached || false}`);

    console.log('\n--- Phase 2: Cached Lookup ---');
    const start2 = Date.now();
    const res2 = await fetch('http://127.0.0.1:3000/api/cti/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data2 = await res2.json();
    console.log(`Duration: ${Date.now() - start2}ms`);
    console.log(`Cached: ${data2.cached || false}`);
}
test();
