import type { Plugin } from "@opencode-ai/plugin"
import { compilePatterns } from "./patterns"
import { scrub } from "./scrub"
import { loadConfig } from "./config"

export const Redacted: Plugin = async ({ directory }) => {
  const compiled = compilePatterns()
  const config = loadConfig(directory)

  const active = compiled.filter((p) => !config.whitelist.includes(p.name))
  const allowed = new Set(config.allow.map((a) => a.toUpperCase()))

  return {
    "tool.execute.after": async (input, output) => {
      if (input.tool !== "bash") return

      const result = scrub(output.output, active, allowed)
      if (result.count > 0) {
        output.output = `[redacted] ${result.count} secret(s) scrubbed.\n\n${result.text}`
      }
    },
  }
}
