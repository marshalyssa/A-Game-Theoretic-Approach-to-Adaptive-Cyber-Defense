/**
 * Statistical Utilities for Experiment Analysis
 * Pure JS implementation with no external dependencies.
 */

/**
 * Compute arithmetic mean
 * @param {number[]} arr 
 * @returns {number|null}
 */
export function mean(arr) {
    if (!arr || arr.length === 0) return null;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

/**
 * Compute sample standard deviation
 * @param {number[]} arr 
 * @returns {number|null}
 */
export function std(arr) {
    if (!arr || arr.length < 2) return 0;
    const m = mean(arr);
    const variance = arr.reduce((a, b) => a + Math.pow(b - m, 2), 0) / (arr.length - 1);
    return Math.sqrt(variance);
}

/**
 * Compute 95% Confidence Interval
 * @param {number[]} arr 
 * @returns {object|null}
 */
export function ci95(arr) {
    if (!arr || arr.length === 0) return null;
    const m = mean(arr);
    const s = std(arr);
    const n = arr.length;
    // Critical value for 95% CI (z-score for large n, or t-score approximation)
    // For n=50, t is ~2.009. Using 1.96 as standard approximation.
    const margin = 1.96 * (s / Math.sqrt(n));
    return {
        mean: m,
        margin: margin,
        lower: m - margin,
        upper: m + margin,
        n: n
    };
}

/**
 * Cohen's d Effect Size
 * @param {number[]} a 
 * @param {number[]} b 
 * @returns {number|null}
 */
export function cohensD(a, b) {
    if (!a || !b || a.length < 2 || b.length < 2) return null;
    const ma = mean(a);
    const mb = mean(b);
    const sa = std(a);
    const sb = std(b);

    const pooledStd = Math.sqrt((Math.pow(sa, 2) + Math.pow(sb, 2)) / 2);
    if (pooledStd === 0) return 0;
    return (ma - mb) / pooledStd;
}

/**
 * Basic Paired T-Test (Simplified)
 * Returns t-statistic and approximate p-value
 * @param {number[]} a 
 * @param {number[]} b 
 * @returns {object|null}
 */
export function pairedTTest(a, b) {
    if (!a || !b || a.length !== b.length || a.length < 2) return null;

    const diffs = a.map((val, i) => val - b[i]);
    const mDiff = mean(diffs);
    const sDiff = std(diffs);
    const n = diffs.length;

    if (sDiff === 0) return { t: 0, p: 1, df: n - 1 };

    const t = mDiff / (sDiff / Math.sqrt(n));
    const df = n - 1;

    // Very simplified p-value approximation for t-distribution
    // This is a rough estimation for n=50
    const p = 2 * (1 - normalCDF(Math.abs(t)));

    return { t, p, df };
}

/**
 * Normal Cumulative Distribution Function approximation
 */
function normalCDF(x) {
    const t = 1 / (1 + 0.2316419 * Math.abs(x));
    const d = 0.3989423 * Math.exp(-x * x / 2);
    const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    return x > 0 ? 1 - p : p;
}
