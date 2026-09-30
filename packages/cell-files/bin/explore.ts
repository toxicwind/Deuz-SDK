// explore.ts — maximal exploration pass over the cell-files dataframe.
// Usage: bun bin/explore.ts [profile|top|audit] [--limit N]
import { loadAll, groupBy, topGroups, sum, where, defaultCsvPath } from "../src/dataframe.js";
import { auditReport } from "../src/ml-audit.js";
import { existsSync } from "fs";

const GZ = defaultCsvPath();
const cmd = process.argv[2] ?? "profile";
const limit = Number(process.argv.find((a) => a.startsWith("--limit="))?.split("=")[1] ?? 25);

const fmtMB = (b: number) => `${(b / 1048576).toFixed(1)}MB`;

if (cmd === "profile") {
  const rows = await loadAll(GZ);
  console.log(`rows: ${rows.length}  total: ${fmtMB(sum(rows))}`);
  console.log("\n-- top extensions by count --");
  for (const [e, n] of topGroups(groupBy(rows, (r) => r.ext || "(noext)"), limit)) console.log(`  .${e}: ${n}`);
  console.log("\n-- top extensions by bytes --");
  const byBytes = [...groupBy(rows, (r) => r.ext || "(noext)").entries()]
    .map(([e, g]) => [e, sum(g)] as [string, number]).sort((a, b) => b[1] - a[1]).slice(0, limit);
  for (const [e, b] of byBytes) console.log(`  .${e}: ${fmtMB(b)}`);
  console.log("\n-- top parent dirs by count --");
  for (const [d, n] of topGroups(groupBy(rows, (r) => r.parent), limit)) console.log(`  ${d}: ${n}`);
  console.log("\n-- misc --");
  console.log(`  hidden: ${where(rows, (r) => r.isHidden).length}`);
  console.log(`  symlinks: ${where(rows, (r) => r.isSymlink).length}`);
  console.log(`  non-ascii names: ${where(rows, (r) => r.nonAscii).length}`);
  console.log(`  world-writable: ${where(rows, (r) => (parseInt(r.mode, 8) & 0o002) !== 0).length}`);
  console.log(`  empty files: ${where(rows, (r) => r.size === 0).length}`);
} else if (cmd === "audit") {
  const rows = await loadAll(GZ);
  const findings = auditReport(rows, { exists: existsSync });
  console.log(`findings: ${findings.length} (top ${limit} shown)`);
  for (const f of findings.slice(0, limit)) {
    console.log(`\n[${f.score.toFixed(2)}] [${f.audits.join(",")}] ${f.row.path}`);
    console.log(`  ${f.reason}  size=${f.row.size} mode=${f.row.mode} mtime=${f.row.mtime.toISOString().slice(0, 10)}`);
  }
} else if (cmd === "top") {
  const rows = await loadAll(GZ);
  const biggest = [...rows].sort((a, b) => b.size - a.size).slice(0, limit);
  for (const r of biggest) console.log(`  ${fmtMB(r.size).padStart(9)}  ${r.path}`);
} else {
  console.log("usage: bun bin/explore.ts [profile|top|audit] [--limit=N]");
}
