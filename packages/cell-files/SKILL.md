# cell-files skill

Exploration + ML-audit of the cell filesystem inventory dataframe.

## Data

`cell-files-20260930.csv.gz` — 211,154 rows, one per file found by
`rg -uu --hidden --files` over `/home`, `/root`, `/tmp` on the hatch cell.

Columns: `path, parent, name, ext, size_bytes, mtime_utc, mode_oct, uid, gid,
is_symlink, link_target, is_hidden, depth, non_ascii`.

## Load it

```ts
import { loadAll, eachRow, where, groupBy, topGroups } from "./src/dataframe.js";
const rows = await loadAll("./cell-files-20260930.csv.gz");   // all in memory
await eachRow("./cell-files-20260930.csv.gz", (r) => { /* streaming */ });
```

## Explore it

```ts
topGroups(groupBy(rows, r => r.ext || "(noext)"), 20);   // top extensions
where(rows, r => r.isHidden, r => r.size > 1e6);          // big hidden files
```

CLI: `bun bin/explore.ts profile | top | audit [--limit=N]`

## ML-audit it

```ts
import { auditReport } from "./src/ml-audit.js";
import { existsSync } from "fs";
const findings = auditReport(rows, { exists: existsSync });
// findings: [{ row, score 0..1, reason, audits: [...] }] ranked by score
```

Individual audits (all return ranked `Finding[]`):

- `sizeOutliersIQR(rows)` — per-extension IQR size outliers
- `sizeZScore(rows, threshold=4)` — global log-size z-score outliers
- `weirdNames(rows)` — entropy / non-ascii / control chars / leading dash / double extensions
- `permAnomalies(rows)` — world-writable, setuid/setgid, sensitive names with loose perms
- `mtimeOutliers(rows)` — future mtimes, epoch zero, far-from-bulk
- `extDirMismatch(rows)` — risky extensions (pem/key/sh/env/...) in odd dirs
- `brokenSymlinks(rows, exists)` — dangling symlink targets

## Rules

- Scores are heuristics, not verdicts. A finding is a lead — verify against the
  live box (`ls`, `stat`, `file`) before acting on it.
- Never delete or chmod from audit output without Chris's explicit say-so on
  that exact path.
- New audits go in `src/ml-audit.ts` as pure functions returning `Finding[]`,
  and get wired into `auditReport`.
