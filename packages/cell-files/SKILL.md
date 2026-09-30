---
name: cell-files
description: "Exploration + ML-audit of the hatch cell filesystem-inventory dataframe (211,154 rows). Streaming/query helpers in Bun/TS, seven pure-TS anomaly audits with corroboration-calibrated scoring, and a Deuz-tool-loop agent that works findings to evidence-graded reports."
license: MIT
inputs: [cell-files-20260930.csv.gz]
outputs: [ranked-findings, evidence-report]
feeds_into: [live-verification, remediation]
---

# cell-files skill

Exploration + ML-audit of the cell filesystem inventory dataframe.

## Data

`cell-files-20260930.csv.gz` — 211,154 rows, one per file found by
`rg -uu --hidden --files` over `/home`, `/root`, `/tmp` on the hatch cell.
Override with `$CELL_FILES_CSV`.

Columns: `path, parent, name, ext, size_bytes, mtime_utc, mode_oct, uid, gid,
is_symlink, link_target, is_hidden, depth, non_ascii`.

## Evidence preservation

Borrowed from digital-forensics practice (zhaoxuya520/reverse-skill): work
the inventory read-only, never mutate the source.

- SHA-256 of the canonical `.csv.gz`:
  `3bd4b9f04024c36a57b54855a9020115582c700c89357e3b15ef1ad9700a9505`
  (211,154 data rows + header; verified cell↔yote 2026-09-30).
- Treat the CSV as the evidence copy. Analysis reads it; verification reads
  the live box. Never "fix" a finding by editing the dataframe.
- A finding is a lead, not a verdict. Verify against the live path (`ls`,
  `stat`, `file`) before acting.

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

Scoring: a lone audit caps at 0.8; each corroborating audit adds 0.15
(max 1.0). A perfect score means multiple independent audits agree.

## Hunting playbook

Hypothesis-driven, borrowed from threat-hunting (same source):

1. **Hypothesize** — "group-writable env files under scratch dirs", "binaries
   with 1980-era mtimes", "huge files with no extension".
2. **Query** — `dataframe_query` / `where()` to pull the candidate set.
3. **Corroborate** — run `auditReport`; one audit firing is a curiosity,
   two+ is a pattern worth chasing.
4. **Rule-ify** — a repeatable pattern becomes a new pure function in
   `src/ml-audit.ts` returning `Finding[]`, wired into `auditReport`.
5. **Verify** — check the live path. Kill false positives with evidence,
   keep the ones that survive.

## Agentic explorer

`bun bin/run-agent.ts "<goal>"` (needs `$CELL_FILES_MODEL`; optional
`$CELL_FILES_BASE_URL` default herd `:25100/v1`, `$CELL_FILES_API_KEY`).
The Deuz `generateText` tool loop gets four tools — `dataframe_profile`,
`dataframe_top`, `dataframe_audit`, `dataframe_query` — and works the
AGENT.md workflow to an evidence-graded report.

## Rules

- Scores are heuristics, not verdicts. Verify on the live box before acting.
- Never delete or chmod from audit output without Chris's explicit say-so on
  that exact path.
- New audits go in `src/ml-audit.ts` as pure functions returning `Finding[]`,
  and get wired into `auditReport`.
- Findings about the cell stay in this project; the dataframe never leaves
  the estate.

## Sources

Patterns adapted from real third-party skills (structure and workflow ideas
only; all dataframe code is ours):

- `zhaoxuya520/reverse-skill` — `digital-forensics` (evidence preservation,
  chain of custody), `threat-hunting` (hypothesis-driven loop). Via the
  `sickn33/agentic-awesome-skills` mirror; MIT.
- `majiayu000/claude-skill-registry` — `recon-osint` frontmatter
  (`inputs`/`outputs`/`feeds_into` skill-composition metadata). License
  varies; frontmatter pattern only.
- `jmagly/aiwg` — forensics `triage-agent` (phase context, red-flag
  escalation) informed AGENT.md.
