# @cell-files/explorer

Agentic exploration and ML-audit of the hatch cell's filesystem inventory,
built on the [Deuz SDK](https://github.com/Deuz-AI/Deuz-SDK) agent loop
(forked to `toxicwind/Deuz-SDK` as this repo's head).

## Data

`cell-files-20260930.csv.gz` (sidecar, gitignored) — 211,154 rows from
`rg -uu --hidden --files` over `/home`, `/root`, `/tmp` on the cell.
Override with `$CELL_FILES_CSV`.

## Use

```sh
bun run profile   # shape of the data
bun run top       # biggest files
bun run audit     # ML anomaly audit, ranked findings
```

## Agentic explorer

```sh
CELL_FILES_MODEL=<herd model id> bun run agent -- "your investigation goal"
# env: CELL_FILES_BASE_URL (default http://127.0.0.1:25100/v1),
#      CELL_FILES_API_KEY (optional), CELL_FILES_CSV (optional)
```

The agent gets four tools — `dataframe_profile`, `dataframe_top`,
`dataframe_audit`, `dataframe_query` — and works the forensics workflow in
`AGENT.md`: profile → audit → targeted queries → evidence-graded report.

## Layout

- `src/dataframe.ts` — streaming/loaded CSV access, `where`/`groupBy`/`topGroups`
- `src/ml-audit.ts` — pure-TS anomaly audits + merged `auditReport`
- `src/agent.ts` — Deuz `generateText` tool loop over the dataframe tools
- `bin/explore.ts` — CLI: `profile | top | audit`
- `bin/run-agent.ts` — CLI: agentic investigation
- `SKILL.md` / `AGENT.md` — skill doc + agent definition
