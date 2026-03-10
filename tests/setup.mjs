/**
 * Test setup — shared helpers for all test files
 * 
 * All engine source files use ES module exports.
 * Test files use .mjs extension to enable ES module imports.
 */

// Helper: check value is a valid probability distribution
export function assertValidDistribution(dist, tolerance = 0.01) {
    const values = typeof dist === 'object' && !Array.isArray(dist)
        ? Object.values(dist)
        : dist;

    const sum = values.reduce((s, v) => s + v, 0);
    if (Math.abs(sum - 1.0) > tolerance) {
        throw new Error(`Distribution sums to ${sum}, expected ~1.0`);
    }
    for (const v of values) {
        if (v < -tolerance) {
            throw new Error(`Distribution has negative value: ${v}`);
        }
    }
    return true;
}

// Helper: check all values are finite numbers
export function assertAllFinite(obj) {
    const values = typeof obj === 'object' ? Object.values(obj) : [obj];
    for (const v of values) {
        if (typeof v !== 'number' || !isFinite(v)) {
            throw new Error(`Expected finite number, got: ${v}`);
        }
    }
    return true;
}
