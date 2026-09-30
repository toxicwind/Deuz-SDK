// dataframe.ts — streaming loader + query helpers for the cell-files inventory.
// Source: cell-files-20260930.csv.gz (rg -uu --hidden --files of /home /root /tmp on the cell).
import { createGunzip } from "zlib";
import { createReadStream } from "fs";
import { createInterface } from "readline";

export interface CellFile {
  path: string;
  parent: string;
  name: string;
  ext: string;
  size: number;
  mtime: Date;
  mode: string;      // octal string e.g. "644"
  uid: number;
  gid: number;
  isSymlink: boolean;
  linkTarget: string;
  isHidden: boolean;
  depth: number;
  nonAscii: boolean;
}

function parseRow(line: string): CellFile | null {
  // minimal CSV parse honoring quotes (loader wrote it, so shape is known)
  const fields: string[] = [];
  let cur = "", inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false; }
      else cur += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { fields.push(cur); cur = ""; }
    else cur += c;
  }
  fields.push(cur);
  if (fields.length !== 14) return null;
  const [path, parent, name, ext, size, mtime, mode, uid, gid, isSymlink, linkTarget, isHidden, depth, nonAscii] = fields;
  return {
    path, parent, name, ext,
    size: Number(size), mtime: new Date(mtime), mode,
    uid: Number(uid), gid: Number(gid),
    isSymlink: isSymlink === "1", linkTarget,
    isHidden: isHidden === "1", depth: Number(depth), nonAscii: nonAscii === "1",
  };
}

/** Default CSV path: $CELL_FILES_CSV, else the sidecar data file next to the repo root. */
export function defaultCsvPath(): string {
  return process.env.CELL_FILES_CSV
    ?? new URL("../../../../cell-files-20260930.csv.gz", import.meta.url).pathname;
}

/** Stream every row. Memory-safe for the full 211k rows. Gunzips iff path ends .gz. */
export async function eachRow(gzPath: string, fn: (r: CellFile) => void): Promise<number> {
  let n = 0, header = true;
  let input: NodeJS.ReadableStream = createReadStream(gzPath);
  if (gzPath.endsWith(".gz")) input = input.pipe(createGunzip());
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    if (header) { header = false; continue; }
    if (!line) continue;
    const r = parseRow(line);
    if (r) { fn(r); n++; }
  }
  return n;
}

/** Load all rows into memory (~211k rows, fine on yote). */
export async function loadAll(gzPath: string): Promise<CellFile[]> {
  const rows: CellFile[] = [];
  await eachRow(gzPath, (r) => rows.push(r));
  return rows;
}

/** Filter helper: pass any predicates, get matching rows. */
export function where(rows: CellFile[], ...preds: Array<(r: CellFile) => boolean>): CellFile[] {
  return rows.filter((r) => preds.every((p) => p(r)));
}

/** Group rows by a key fn. Returns Map<key, rows>. */
export function groupBy(rows: CellFile[], key: (r: CellFile) => string): Map<string, CellFile[]> {
  const m = new Map<string, CellFile[]>();
  for (const r of rows) {
    const k = key(r);
    let a = m.get(k);
    if (!a) { a = []; m.set(k, a); }
    a.push(r);
  }
  return m;
}

/** Top-N groups by count, descending. */
export function topGroups(groups: Map<string, CellFile[]>, n = 20): Array<[string, number]> {
  return [...groups.entries()].map(([k, v]) => [k, v.length] as [string, number])
    .sort((a, b) => b[1] - a[1]).slice(0, n);
}

export const sum = (rows: CellFile[]) => rows.reduce((a, r) => a + r.size, 0);
export const median = (xs: number[]) => {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
