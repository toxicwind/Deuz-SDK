// ui/server.ts — hot-reload web UI for the cell-files explorer.
// Run:  bun --hot ui/server.ts
//
// Hot-reload loop (event-driven, no polling):
//   * The page holds a WebSocket to /api/hmr. On every connect the server
//     sends {boot, v}; on every (debounced) app.html change it broadcasts
//     the new {boot, v} to all connected clients.
//   * bun --hot restarts change `boot`; app.html edits bump `v`.
//   * The client reloads EXACTLY ONCE when boot changes or v advances —
//     a bare reconnect (same boot, same v) never reloads.
//   * Fallback, not rollback: if WebSockets are unavailable the client
//     degrades to the /api/events SSE stream; if that dies too it parks
//     with a manual-refresh pill instead of a reload loop.
import { loadAll, where, groupBy, topGroups, sum, defaultCsvPath, type CellFile } from "../src/dataframe.js";
import { auditReport } from "../src/ml-audit.js";
import { findingsReport } from "../src/findings.js";
import { existsSync, watch } from "fs";

const PORT = Number(process.env.BUN_DEV_PORT ?? 25142);
const CSV = defaultCsvPath();

console.log(`[cellfiles-ui] loading ${CSV} ...`);
const rows: CellFile[] = await loadAll(CSV);
console.log(`[cellfiles-ui] ${rows.length} rows loaded`);

let auditCache: ReturnType<typeof auditReport> | null = null;
const audit = () => (auditCache ??= auditReport(rows, { exists: existsSync }));

let findingsCache: ReturnType<typeof findingsReport> | null = null;
const findings = () => (findingsCache ??= findingsReport(rows, { exists: existsSync }));

// Lazy path -> row index for the raw-row drill-through (/api/row).
let rowIndex: Map<string, CellFile> | null = null;
const rowByPath = (path: string) => {
  if (!rowIndex) rowIndex = new Map(rows.map((r) => [r.path, r]));
  return rowIndex.get(path) ?? null;
};

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

const bootId = Math.random().toString(36).slice(2);
let htmlVersion = 0;

// Live HMR sockets. Tracked explicitly: broadcast iterates this set, so a
// dead socket can never wedge the push path (close() always removes it).
const hmrClients = new Set<import("bun").ServerWebSocket>();

const hmrState = () => JSON.stringify({ boot: bootId, v: htmlVersion });

function broadcastHmr() {
  const msg = hmrState();
  for (const ws of hmrClients) {
    try { ws.send(msg); } catch { /* dead socket; close() cleans up */ }
  }
}

const server = Bun.serve({
  // idleTimeout 0 = disabled. Bun's default 10s idle kill was closing the
  // long-lived SSE fallback stream, and the old blind-onerror client turned
  // that into a refresh loop. Both transports here are long-lived by design.
  idleTimeout: 0,  port: PORT,
  hostname: "0.0.0.0",
  websocket: {
    open(ws) {
      hmrClients.add(ws);
      ws.send(hmrState()); // handshake: current {boot, v} on every connect
    },
    close(ws) { hmrClients.delete(ws); },
    message() { /* server->client only; client messages ignored */ },
  },
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
    // Human findings: 3-class triage (actionable / needs-review / expected),
    // grouped by directory/workload, every finding carrying a WHY string.
    // Outlier status is evidence, not verdict. Expected/cache noise is
    // aggregated into counts — never listed row-by-row on the homepage.
    "/api/findings": () => Response.json(findings()),
    // Raw-row drill-through: full 14-column row for one path.
    "/api/row": (req) => {
      const path = new URL(req.url).searchParams.get("path") ?? "";
      const r = rowByPath(path);
      if (!r) return new Response("no such path", { status: 404 });
      return Response.json({
        path: r.path, parent: r.parent, name: r.name, ext: r.ext,
        size_bytes: r.size, mtime_utc: r.mtime, mode_oct: r.mode,
        uid: r.uid, gid: r.gid, is_symlink: r.isSymlink,
        link_target: r.linkTarget, is_hidden: r.isHidden,
        depth: r.depth, non_ascii: r.nonAscii,
      });
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
    // Primary hot-reload transport: event-driven WebSocket. Pushes happen
    // only on connect (handshake) and on app.html change (broadcast) —
    // there is no heartbeat and no polling anywhere in this loop.
    "/api/hmr": (req, srv) => {
      if (srv.upgrade(req)) return;
      return new Response("hot-reload requires websocket", { status: 426 });
    },
    // Fallback transport: long-lived SSE, pull-driven via async generator
    // (manual controller + setInterval enqueues never got flushed by Bun's
    // response pump). Kept for degraded environments where WebSockets are
    // unavailable — the client only uses it when /api/hmr fails.
    "/api/events": () => {
      const boot = bootId;
      async function* sse() {
        yield `data: {"boot":"${boot}","v":${htmlVersion}}\n\n`;
        while (true) {
          await Bun.sleep(5000);
          yield `data: {"boot":"${boot}","v":${htmlVersion}}\n\n`;
        }
      }
      return new Response(ReadableStream.from(sse()), {
        headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      });
    },
  },
  fetch: () => new Response("not found", { status: 404 }),
});

console.log(`[cellfiles-ui] live at http://0.0.0.0:${server.port}/ (boot ${bootId})`);

// Watch app.html directly (bun --hot only tracks the module graph, not
// Bun.file assets). Debounced: one save can fire several fs events.
// On fire: bump v and push to every connected HMR client, exactly once.
const htmlPath = new URL("./app.html", import.meta.url).pathname;
let watchTimer: ReturnType<typeof setTimeout> | null = null;
watch(htmlPath, () => {
  if (watchTimer) clearTimeout(watchTimer);
  watchTimer = setTimeout(() => {
    htmlVersion++;
    console.log(`[cellfiles-ui] app.html changed -> v${htmlVersion}, pushing to ${hmrClients.size} hmr client(s)`);
    broadcastHmr();
  }, 400);
});
