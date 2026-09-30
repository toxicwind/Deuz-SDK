// ui/server.ts — hot-reload web UI for the cell-files explorer.
// Run:  bun --hot ui/server.ts        (or: mise run up-cellfiles-ui)
// Edit anything (server or app.html) -> bun --hot restarts -> the page
// auto-reloads via the /api/events SSE stream. That's the hot-reload loop.
import { loadAll, where, groupBy, topGroups, sum, defaultCsvPath, type CellFile } from "../src/dataframe.js";
import { auditReport } from "../src/ml-audit.js";
import { existsSync } from "fs";

const PORT = Number(process.env.BUN_DEV_PORT ?? 25142);
const CSV = defaultCsvPath();

console.log(`[cellfiles-ui] loading ${CSV} ...`);
const rows: CellFile[] = await loadAll(CSV);
console.log(`[cellfiles-ui] ${rows.length} rows loaded`);

let auditCache: ReturnType<typeof auditReport> | null = null;
const audit = () => (auditCache ??= auditReport(rows, { exists: existsSync }));

function profile() {
  const extGroups = groupBy(rows, (r) => r.ext || "(noext)");
  const byCount = [...extGroups.entries()]
    .map(([ext, g]) => ({ ext, count: g.length }))
    .sort((a, b) => b.count - a.count).slice(0, 12);
  const byBytes = [...extGroups.entries()]
    .map(([ext, g]) => ({ ext, bytes: sum(g) }))
    .sort((a, b) => b.bytes - a.bytes).slice(0, 12);
  return {
    rows: rows.length,
    totalBytes: sum(rows),
    hidden: where(rows, (r) => r.isHidden).length,
    symlinks: where(rows, (r) => r.isSymlink).length,
    nonAscii: where(rows, (r) => r.nonAscii).length,
    empty: where(rows, (r) => r.size === 0).length,
    byCount,
    byBytes,
    topDirs: topGroups(groupBy(rows, (r) => r.parent), 10),
  };
}

const sseClients = new Set<ReadableStreamDefaultController>();

const server = Bun.serve({  port: PORT,
  hostname: "0.0.0.0",
  routes: {
    "/": async () =>
      new Response(Bun.file(new URL("./app.html", import.meta.url)), {
        headers: { "content-type": "text/html; charset=utf-8" },
      }),
    "/api/profile": () => Response.json(profile()),
    "/api/top": (req) => {
      const limit = Math.min(Number(new URL(req.url).searchParams.get("limit") ?? 25), 100);
      return Response.json(
        [...rows].sort((a, b) => b.size - a.size).slice(0, limit)
          .map((r) => ({ path: r.path, size: r.size, mode: r.mode, mtime: r.mtime })),
      );
    },
    "/api/audit": (req) => {
      const limit = Math.min(Number(new URL(req.url).searchParams.get("limit") ?? 50), 200);
      return Response.json(
        audit().slice(0, limit).map((f) => ({
          path: f.row.path, score: +f.score.toFixed(3), audits: f.audits,
          reason: f.reason, size: f.row.size, mode: f.row.mode, mtime: f.row.mtime,
        })),
      );
    },
    "/api/query": (req) => {
      const q = new URL(req.url).searchParams;
      const ext = q.get("ext") ?? "", name = q.get("name") ?? "",
        parent = q.get("parent") ?? "", minSize = Number(q.get("minSize") ?? 0);
      const out = where(
        rows,
        (r) => !ext || r.ext === ext,
        (r) => !name || r.name.includes(name),
        (r) => !parent || r.parent.includes(parent),
        (r) => r.size >= minSize,
      ).slice(0, 200);
      return Response.json({
        count: out.length,
        files: out.map((r) => ({ path: r.path, size: r.size, mode: r.mode })),
      });
    },
    "/api/events": () => {
      // SSE hot-reload channel. Two triggers:
      //  1. bun --hot restarts on server.ts edits -> stream drops -> client reloads.
      //  2. fs.watch on app.html below -> "reload" broadcast -> client reloads.
      let timer: ReturnType<typeof setInterval>;
      const stream = new ReadableStream({
        start(c) {
          sseClients.add(c);
          c.enqueue("data: alive\n\n");
          timer = setInterval(() => { try { c.enqueue("data: ping\n\n"); } catch { /* dead */ } }, 15000);
        },
        cancel(c) { clearInterval(timer); sseClients.delete(c); },
      });
      return new Response(stream, {
        headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      });
    },
  },
  fetch: () => new Response("not found", { status: 404 }),
});

console.log(`[cellfiles-ui] live at http://0.0.0.0:${server.port}/`);

// Watch app.html directly (bun --hot only tracks the module graph, not
// Bun.file assets): any edit broadcasts a reload to all SSE clients.
import { watch } from "fs";
const htmlPath = new URL("./app.html", import.meta.url).pathname;
watch(htmlPath, () => {
  console.log("[cellfiles-ui] app.html changed -> reloading clients");
  for (const c of sseClients) {
    try { c.enqueue("data: reload\n\n"); } catch { /* dead */ }
  }
});
