// agent.ts — the cell-files explorer agent: Deuz tool loop + dataframe tools,
// pointed at an OpenAI-compatible endpoint (the herd) via createOpenAICompatible.
import { generateText } from "@deuz-sdk/core";
import { createOpenAICompatible } from "@deuz-sdk/core/providers";
import type { ToolSet } from "@deuz-sdk/core";
import { loadAll, where, groupBy, topGroups, sum, defaultCsvPath, type CellFile } from "./dataframe.js";
import { auditReport } from "./ml-audit.js";
import { existsSync } from "fs";

const CSV = defaultCsvPath();
let cache: CellFile[] | null = null;
async function rows(): Promise<CellFile[]> {
  if (!cache) cache = await loadAll(CSV);
  return cache;
}

const J = (v: unknown) => JSON.parse(JSON.stringify(v));

export function cellFilesTools(): ToolSet {
  return {
    dataframe_profile: {
      description: "Profile the dataframe: row count, total bytes, top extensions by count and bytes, top directories, hidden/symlink/empty counts.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      execute: async () => {
        const r = await rows();
        const byExt = [...groupBy(r, (x) => x.ext || "(noext)").entries()]
          .map(([e, g]) => ({ ext: e, count: g.length, bytes: sum(g) }))
          .sort((a, b) => b.count - a.count).slice(0, 20);
        return J({
          rows: r.length, totalBytes: sum(r),
          topExtensions: byExt,
          topDirs: topGroups(groupBy(r, (x) => x.parent), 15),
          hidden: where(r, (x) => x.isHidden).length,
          symlinks: where(r, (x) => x.isSymlink).length,
          nonAscii: where(r, (x) => x.nonAscii).length,
          empty: where(r, (x) => x.size === 0).length,
        });
      },
    },
    dataframe_top: {
      description: "Largest files in the dataframe.",
      parameters: {
        type: "object",
        properties: { limit: { type: "number", description: "how many (default 20, max 100)" } },
        additionalProperties: false,
      },
      execute: async (args) => {
        const { limit } = args as { limit?: number };
        const r = await rows();
        return J([...r].sort((a, b) => b.size - a.size).slice(0, Math.min(limit ?? 20, 100))
          .map((x) => ({ path: x.path, size: x.size, mtime: x.mtime.toISOString() })));
      },
    },
    dataframe_audit: {
      description: "Run the ML anomaly audit over the dataframe. Returns ranked findings (path, score 0..1, reason, which audits fired).",
      parameters: {
        type: "object",
        properties: { limit: { type: "number", description: "how many findings (default 30, max 200)" } },
        additionalProperties: false,
      },
      execute: async (args) => {
        const { limit } = args as { limit?: number };
        const r = await rows();
        const findings = auditReport(r, { exists: existsSync });
        return J(findings.slice(0, Math.min(limit ?? 30, 200)).map((f) => ({
          path: f.row.path, score: +f.score.toFixed(3), reason: f.reason, audits: f.audits,
          size: f.row.size, mode: f.row.mode, mtime: f.row.mtime.toISOString(),
        })));
      },
    },
    dataframe_query: {
      description: "Filter files by extension, parent/name substring, size bounds, hidden/symlink flags.",
      parameters: {
        type: "object",
        properties: {
          ext: { type: "string" }, parentContains: { type: "string" }, nameContains: { type: "string" },
          minSize: { type: "number" }, maxSize: { type: "number" },
          isHidden: { type: "boolean" }, isSymlink: { type: "boolean" },
          limit: { type: "number", description: "cap results (default 50, max 500)" },
        },
        additionalProperties: false,
      },
      execute: async (args) => {
        const q = args as Record<string, string | number | boolean | undefined>;
        const r = await rows();
        const out = where(r,
          (x) => q.ext === undefined || x.ext === q.ext,
          (x) => q.parentContains === undefined || x.parent.includes(q.parentContains as string),
          (x) => q.nameContains === undefined || x.name.includes(q.nameContains as string),
          (x) => q.minSize === undefined || x.size >= (q.minSize as number),
          (x) => q.maxSize === undefined || x.size <= (q.maxSize as number),
          (x) => q.isHidden === undefined || x.isHidden === (q.isHidden as boolean),
          (x) => q.isSymlink === undefined || x.isSymlink === (q.isSymlink as boolean),
        ).slice(0, Math.min((q.limit as number) ?? 50, 500));
        return J({ count: out.length, files: out.map((x) => ({ path: x.path, size: x.size, mode: x.mode })) });
      },
    },
  };
}

const SYSTEM = `You are a filesystem forensics analyst. Your evidence is the cell-files
dataframe: 211,154 rows, one per file found by \`rg -uu --hidden --files\` over
/home, /root, /tmp on the hatch cell. Columns: path, parent, name, ext,
size_bytes, mtime_utc, mode_oct, uid, gid, is_symlink, link_target, is_hidden,
depth, non_ascii.

You have four tools: dataframe_profile (shape of the data), dataframe_top
(biggest files), dataframe_audit (ML anomaly findings, ranked by score),
dataframe_query (filtered search).

Workflow: profile first, then audit, then dig into the most suspicious findings
with targeted queries. Scores are leads, not verdicts — say what you verified
vs what is still a hypothesis. Report: what you found, the evidence, what you
ruled out, what still needs eyes. Be specific: paths, sizes, scores. Never
recommend deleting or chmodding anything; that needs explicit human approval
per path.`;

export async function runExplorerAgent(goal: string, opts: { maxSteps?: number } = {}): Promise<string> {
  const modelId = process.env.CELL_FILES_MODEL;
  if (!modelId) throw new Error("Set CELL_FILES_MODEL (e.g. the herd model id) before running the agent.");
  const baseURL = process.env.CELL_FILES_BASE_URL ?? "http://127.0.0.1:25100/v1";
  const provider = createOpenAICompatible({
    id: "herd",
    baseURL,
    apiKeyOptional: true,
    ...(process.env.CELL_FILES_API_KEY ? { apiKey: process.env.CELL_FILES_API_KEY } : {}),
  });
  const result = await generateText({
    model: provider(modelId),
    instructions: SYSTEM,
    prompt: goal,
    maxSteps: opts.maxSteps ?? 15,
    tools: cellFilesTools(),
    onStepFinish: (step) => {
      for (const call of step.toolCalls ?? []) {
        console.error(`  -> ${call.toolName}(${JSON.stringify(call.args).slice(0, 160)})`);
      }
    },
  });
  console.error(`steps=${result.steps?.length ?? 1} tokens=${result.usage?.totalTokens ?? "?"} stoppedBy=${result.providerMetadata?.deuz?.stoppedBy ?? "natural"}`);
  return result.text;
}
