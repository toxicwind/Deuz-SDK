// ml-audit.ts — anomaly-detection helpers over the cell-files dataframe.
// Pure TypeScript, zero dependencies. Each audit returns ranked findings:
// { row, score, reason }. Scores are 0..1 (higher = weirder).
import { CellFile, groupBy, median, where } from "./dataframe.js";

export interface Finding { row: CellFile; score: number; reason: string; }

function quantile(sorted: number[], q: number): number {
  if (!sorted.length) return 0;
  const i = (sorted.length - 1) * q;
  const lo = Math.floor(i), hi = Math.ceil(i);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
}

/** IQR size outliers within each extension group (files way bigger/smaller than peers). */
export function sizeOutliersIQR(rows: CellFile[], k = 1.5): Finding[] {
  const out: Finding[] = [];
  for (const [, g] of groupBy(rows, (r) => r.ext || "(noext)")) {
    if (g.length < 10) continue;
    const sizes = g.map((r) => r.size).sort((a, b) => a - b);
    const q1 = quantile(sizes, 0.25), q3 = quantile(sizes, 0.75);
    const iqr = q3 - q1 || 1;
    const hi = q3 + k * iqr, lo = q1 - k * iqr;
    for (const r of g) {
      if (r.size > hi) out.push({ row: r, score: Math.min(1, (r.size - hi) / hi / 8), reason: `size ${r.size} >> ext .${r.ext} IQR ceiling ${Math.round(hi)}` });
      else if (r.size < lo && r.size > 0) out.push({ row: r, score: 0.3, reason: `size ${r.size} << ext .${r.ext} IQR floor ${Math.round(lo)}` });
    }
  }
  return out.sort((a, b) => b.score - a.score);
}

/** Z-score outliers on log(size+1) — catches globally absurd files. */
export function sizeZScore(rows: CellFile[], threshold = 4): Finding[] {
  const logs = rows.map((r) => Math.log(r.size + 1));
  const mean = logs.reduce((a, b) => a + b, 0) / logs.length;
  const sd = Math.sqrt(logs.reduce((a, b) => a + (b - mean) ** 2, 0) / logs.length) || 1;
  const out: Finding[] = [];
  rows.forEach((r, i) => {
    const z = (logs[i] - mean) / sd;
    if (Math.abs(z) >= threshold) out.push({ row: r, score: Math.min(1, Math.abs(z) / 10), reason: `log-size z=${z.toFixed(2)} (size ${r.size})` });
  });
  return out.sort((a, b) => b.score - a.score);
}

/** Shannon entropy of a string, bits per char. */
export function nameEntropy(name: string): number {
  if (!name.length) return 0;
  const freq = new Map<string, number>();
  for (const c of name) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / name.length; h -= p * Math.log2(p); }
  return h;
}

/** Random-looking / hostile names: high entropy, non-ascii, control chars, leading dash, trailing space, double extensions. */
export function weirdNames(rows: CellFile[], entropyCut = 4.2): Finding[] {
  const out: Finding[] = [];
  for (const r of rows) {
    const reasons: string[] = [];
    if (r.nonAscii) reasons.push("non-ascii chars");
    if (/[^\x20-\x7E]/.test(r.name)) reasons.push("control/non-printable chars");
    if (r.name.startsWith("-")) reasons.push("leading dash (flag-injection smell)");
    if (r.name !== r.name.trim()) reasons.push("leading/trailing whitespace");
    if ((r.name.match(/\./g) ?? []).length >= 3) reasons.push("3+ dots (double-extension smell)");
    const ent = nameEntropy(r.name);
    if (ent >= entropyCut && r.name.length >= 12) reasons.push(`high entropy ${ent.toFixed(2)} bits/char`);
    if (reasons.length) out.push({ row: r, score: Math.min(1, 0.25 * reasons.length + (ent >= entropyCut ? 0.3 : 0)), reason: reasons.join("; ") });
  }
  return out.sort((a, b) => b.score - a.score);
}

/** Permission anomalies: world-writable, setuid/setgid, sensitive names with loose perms. */
export function permAnomalies(rows: CellFile[]): Finding[] {
  const out: Finding[] = [];
  const sensitive = /\.(pem|key|p12|pfx|kdbx|env|secret|token|passwd|shadow)$/i;
  for (const r of rows) {
    const mode = parseInt(r.mode, 8);
    if (mode & 0o002) out.push({ row: r, score: 0.8, reason: `world-writable (${r.mode})` });
    if (mode & 0o4000) out.push({ row: r, score: 0.9, reason: `setuid bit (${r.mode})` });
    if (mode & 0o2000) out.push({ row: r, score: 0.7, reason: `setgid bit (${r.mode})` });
    if (sensitive.test(r.name) && (mode & 0o077)) out.push({ row: r, score: 0.85, reason: `sensitive name with group/other perms (${r.mode})` });
  }
  return out.sort((a, b) => b.score - a.score);
}

/** mtime outliers: future dates, epoch-zero, or far from the bulk median. */
export function mtimeOutliers(rows: CellFile[]): Finding[] {
  const out: Finding[] = [];
  const now = Date.now();
  const times = rows.map((r) => r.mtime.getTime()).filter((t) => t > 0);
  const med = median(times);
  const spread = quantile([...times].sort((a, b) => a - b), 0.9) - quantile([...times].sort((a, b) => a - b), 0.1) || 1;
  for (const r of rows) {
    const t = r.mtime.getTime();
    if (t > now + 60000) out.push({ row: r, score: 0.9, reason: `mtime in the future (${r.mtime.toISOString()})` });
    else if (t === 0) out.push({ row: r, score: 0.2, reason: "mtime is epoch zero" });
    else if (Math.abs(t - med) > 10 * spread) out.push({ row: r, score: 0.6, reason: `mtime far from bulk (${r.mtime.toISOString().slice(0, 10)})` });
  }
  return out.sort((a, b) => b.score - a.score);
}

/** Extension/directory mismatch: risky extensions sitting in odd places. */
export function extDirMismatch(rows: CellFile[]): Finding[] {
  const out: Finding[] = [];
  const risky = new Set(["pem", "key", "p12", "pfx", "sh", "bin", "exe", "so", "dylib", "env"]);
  for (const r of rows) {
    if (!risky.has(r.ext)) continue;
    const oddDirs = ["/tmp", "/var/tmp", "/dev/shm"];
    if (oddDirs.some((d) => r.parent.startsWith(d))) {
      out.push({ row: r, score: 0.75, reason: `risky .${r.ext} in ${r.parent}` });
    }
    if (r.ext === "env" && r.parent.includes("workspace")) {
      out.push({ row: r, score: 0.5, reason: `.env under workspace ${r.parent}` });
    }
  }
  return out.sort((a, b) => b.score - a.score);
}

/** Broken symlinks: target does not resolve (checked lazily — caller provides exists fn). */
export function brokenSymlinks(rows: CellFile[], exists: (p: string) => boolean): Finding[] {
  const out: Finding[] = [];
  for (const r of where(rows, (x) => x.isSymlink)) {
    const t = r.linkTarget.startsWith("/") ? r.linkTarget : `${r.parent}/${r.linkTarget}`;
    if (!exists(t)) out.push({ row: r, score: 0.65, reason: `dangling symlink -> ${r.linkTarget}` });
  }
  return out;
}

/** Run every audit, merge + dedupe by path, rank by max score. */
export function auditReport(
  rows: CellFile[],
  opts: { exists?: (p: string) => boolean } = {},
): Array<Finding & { audits: string[] }> {
  const buckets: Array<[string, Finding[]]> = [
    ["size-iqr", sizeOutliersIQR(rows)],
    ["size-z", sizeZScore(rows)],
    ["names", weirdNames(rows)],
    ["perms", permAnomalies(rows)],
    ["mtime", mtimeOutliers(rows)],
    ["ext-dir", extDirMismatch(rows)],
  ];
  if (opts.exists) buckets.push(["symlink", brokenSymlinks(rows, opts.exists)]);
  const merged = new Map<string, Finding & { audits: string[] }>();
  for (const [audit, findings] of buckets) {
    for (const f of findings) {
      const e = merged.get(f.row.path);
      if (e) { e.audits.push(audit); if (f.score > e.score) { e.score = f.score; e.reason = f.reason; } }
      else merged.set(f.row.path, { ...f, audits: [audit] });
    }
  }
  // Calibrate: a lone audit caps at 0.8; each corroborating audit adds 0.15.
  // A perfect 1.00 needs multiple independent audits agreeing.
  for (const e of merged.values()) {
    e.score = Math.min(1, Math.min(e.score, 0.8) + 0.15 * (e.audits.length - 1));
  }
  return [...merged.values()].sort((a, b) => b.score - a.score);
}
