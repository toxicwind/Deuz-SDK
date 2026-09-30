// run-agent.ts — CLI entry: bun bin/run-agent.ts "your investigation goal"
// Env: CELL_FILES_MODEL (required), CELL_FILES_BASE_URL (default herd :25100/v1),
//      CELL_FILES_API_KEY (optional), CELL_FILES_CSV (default sidecar .gz).
import { runExplorerAgent } from "../src/agent.js";

const goal = process.argv.slice(2).join(" ") || "Profile the dataframe, run the anomaly audit, and report the 10 most suspicious findings with evidence.";
const text = await runExplorerAgent(goal);
console.log(text);
