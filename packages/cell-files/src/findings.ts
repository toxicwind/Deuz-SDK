// src/findings.ts — human-facing findings layer over the ml-audit anomaly report.
//
// Borrowed pattern (DefectDojo-class findings management, via GitHub code search
// on DefectDojo/django-DefectDojo findings_list_snippet.html):
//   1. triage taxonomy first — their active/verified vs false-positive/duplicate/
//      out-of-scope becomes our three classes: actionable / needs-review / expected.
//   2. findings grouped by location (their "finding groups"; ours: directory/workload).
//   3. every finding carries a human WHY (their title+description; our `why`).
//   4. outlier status is evidence, never verdict (their "unverified" state).
//   5. repetitive noise (our .cache/vendor/testdata) is aggregated, never listed
//      row-by-row on the homepage — same dedupe instinct as their finding groups.
import type { CellFile } from "./dataframe.js";
function groupBy<T>(rows: T[], key: (r: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const r of rows) {
    const k = key(r);
    const a = m.get(k);
    if (a) a.push(r);
    else m.set(k, [r]);
  }
  return m;
}
import { auditReport } from "./ml-audit.js";

export type FindingClass = "actionable" | "needs-review" | "expected";

export interface RawFinding {
  row: CellFile;
  score: number;
  reason: string;
  audits: string[];
}

export interface ClassifiedFinding extends RawFinding {
  cls: FindingClass;
  /** human explanation of WHY this row was flagged */
  why: string;
  /** first-3-segment rollup, e.g. /home/hatch/workspace */
  workload: string;
}

/** Parents whose findings are routine build/cache/vendor/test noise.
 *  Aggregated into counts — never listed row-by-row on the homepage. */
const EXPECTED_PARENT =
  /(^|\/)\.(cache|npm|bun|mozilla|vscode-server|local|config)(\/|$)|\/__pycache__(\/|$)|\/node_modules(\/|$)|\/\.venv(\/|$)|\/site-packages(\/|$)|\/pkg\/mod(\/|$)|\/testdata(\/|$)|\/nist-pkits(\/|$)|\/assets\/icons(\/|$)/i;

export function workloadOf(path: string): string {
  const seg = path.split("/").filter(Boolean);
  return "/" + seg.slice(0, 3).join("/");
}

const WHY: Record<string, (f: RawFinding) => string> = {
  "size-iqr": (f) =>
    `Size outlier vs its .${f.row.ext || "(noext)"} peers (${f.reason}). Statistical evidence only — vendored blobs and testdata trip this constantly.`,
  "size-z": (f) =>
    `Globally absurd size (${f.reason}). Files this far off the global distribution are rare outside disk images and dumps — worth a look.`,
  "names": (f) =>
    `Suspicious name pattern (${f.reason}). Odd names hide payloads — and test fixtures. A lead, not a verdict.`,
  "perms": (f) =>
    `Permission anomaly (${f.reason}). Directly security-relevant: check who can read, write, or execute this.`,
  "mtime": (f) =>
    `Timestamp anomaly (${f.reason}). Future or far-off mtimes suggest tampering, clock skew, or build artifacts — context decides.`,
  "ext-dir": (f) =>
    `Risky file type in a risky place (${f.reason}). Executables and keys in /tmp-style dirs are a classic dropper pattern.`,
  "symlink": (f) =>
    `Dangling symlink (${f.reason}). Points at something that no longer exists — a moved target, or a broken chain.`,
};

function whyFor(f: RawFinding): string {
  const parts = f.audits.map((a) => (WHY[a] ? WHY[a](f) : `${a}: ${f.reason}`));
  return [...new Set(parts)].join(" ");
}

function classify(f: RawFinding): FindingClass {
  const audits = new Set(f.audits);
  // actionable: direct security signal, no statistical hedging needed
  if (audits.has("perms") || audits.has("ext-dir")) return "actionable";
  if (audits.has("mtime") && /future/.test(f.reason)) return "actionable";
  // expected: routine cache/vendor/testdata noise, or build-artifact timestamps
  if (EXPECTED_PARENT.test(f.row.parent)) return "expected";
  if (audits.has("mtime") && /epoch zero/.test(f.reason)) return "expected";
  return "needs-review";
}

export interface FindingGroup {
  workload: string;
  dir: string;
  count: number;
  /** capped full listing (actionable / needs-review); empty for expected */
  findings: ClassifiedFinding[];
  /** expected groups carry a few samples instead of a listing */
  sample?: ClassifiedFinding[];
}

export interface FindingsReport {
  total: number;
  generatedAt: string;
  classes: Record<FindingClass, { count: number; groups: FindingGroup[] }>;
}

export function findingsReport(
  rows: CellFile[],
  opts: { exists?: (p: string) => boolean } = {},
  caps = { groups: 25, perGroup: 50, sample: 3 },
): FindingsReport {
  const raw = auditReport(rows, opts);
  const classified: ClassifiedFinding[] = raw.map((f) => ({
    ...f,
    cls: classify(f),
    why: whyFor(f),
    workload: workloadOf(f.row.path),
  }));
  const classes = {} as FindingsReport["classes"];
  for (const cls of ["actionable", "needs-review", "expected"] as FindingClass[]) {
    const inCls = classified.filter((f) => f.cls === cls);
    const groups: FindingGroup[] = [...groupBy(inCls, (f) => f.row.parent).entries()]
      .map(([dir, fs]) => {
        const sorted = [...fs].sort((a, b) => b.score - a.score);
        const g: FindingGroup = {
          workload: sorted[0]?.workload ?? "",
          dir,
          count: fs.length,
          findings: cls === "expected" ? [] : sorted.slice(0, caps.perGroup),
        };
        if (cls === "expected") g.sample = sorted.slice(0, caps.sample);
        return g;
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, caps.groups);
    classes[cls] = { count: inCls.length, groups };
  }
  return { total: raw.length, generatedAt: new Date().toISOString(), classes };
}
