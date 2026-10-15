export function summarize(values) {
  const v = [...values].sort((a, b) => a - b);
  const n = v.length;
  if (!n) return { n: 0 };
  const q = (p) => v[Math.min(n - 1, Math.max(0, Math.ceil(p * n) - 1))];
  const mean = v.reduce((s, x) => s + x, 0) / n;
  const sd = Math.sqrt(v.reduce((s, x) => s + (x - mean) ** 2, 0) / Math.max(1, n - 1));
  const r = (x) => Math.round(x * 100) / 100;
  return { n, mean: r(mean), sd: r(sd), min: r(v[0]), p50: r(q(0.5)), p90: r(q(0.9)), p99: r(q(0.99)), max: r(v[n - 1]) };
}
