// Smoke test: runs the real plugin under Bun, as OpenCode does, against the debug binary.
// From the repo root: cargo build && bun plugins/opencode/smoke.mjs
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { Redacted } from "./redacted.ts"

const root = resolve(import.meta.dir, "../..")
// A throwaway HOME, so the user's config and stats stay out of the run.
const home = mkdtempSync(join(tmpdir(), "redacted-smoke-"))
const $ = Bun.$.env({ ...process.env, HOME: home, REDACTED_STATS_FILE: join(home, "stats.jsonl") })
const hooks = await Redacted({ $, directory: home })
const afterTool = hooks["tool.execute.after"]

// Built at runtime so no secret-shaped literal sits in the source.
const key = "AKIA" + "Q7".repeat(8)
const call = { tool: "bash", sessionID: "ses_smoke", callID: "call_1", args: { command: "env" } }
let failures = 0
function check(passed, what) {
  console.log(`${passed ? "ok  " : "FAIL"} ${what}`)
  if (!passed) failures += 1
}

process.env.REDACTED_BIN = join(root, "target/debug/redacted")
const builtIn = { title: "env", output: `k ${key}`, metadata: { exit: 0 } }
await afterTool(call, builtIn)
check(builtIn.output === "k [REDACTED:aws_access_key ...Q7Q7]", "the secret in a built-in tool's output is scrubbed")
check(builtIn.title === "env" && builtIn.metadata.exit === 0, "the other keys of the output survive")

const mcp = { content: [{ type: "text", text: `a ${key}` }], isError: false }
await afterTool({ ...call, tool: "github_get_file" }, mcp)
check(!JSON.stringify(mcp).includes(key) && mcp.isError === false, "a raw MCP result is scrubbed in place")

// No binary at all must fail the tool call, never show the raw output.
process.env.REDACTED_BIN = join(home, "no-such-binary")
const unscrubbed = { title: "env", output: `k ${key}`, metadata: {} }
const threw = await afterTool(call, unscrubbed).then(() => false, () => true)
check(threw, "a missing binary throws, so OpenCode fails the tool call")

if (failures > 0) process.exit(1)
