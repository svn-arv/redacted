import { readFileSync } from "fs"
import { join } from "path"
import { parse } from "yaml"

export interface RedactedConfig {
  whitelist: string[]
  allow: string[]
}

interface ConfigFile {
  override?: boolean
  whitelist?: string[]
  allow?: string[]
  keywords?: string[]
  patterns?: { name: string; regex: string }[]
}

export function loadConfig(cwd: string): RedactedConfig {
  const whitelist: string[] = []
  const allow: string[] = []

  const paths = [
    join(process.env.HOME || "~", ".config", "redacted", "config.yaml"),
    join(cwd, ".redacted.yaml"),
  ]

  for (const p of paths) {
    try {
      const cfg = parse(readFileSync(p, "utf-8")) as ConfigFile
      if (!cfg) continue

      if (cfg.override) {
        whitelist.length = 0
        allow.length = 0
      }
      if (cfg.whitelist) whitelist.push(...cfg.whitelist)
      if (cfg.allow) allow.push(...cfg.allow)
    } catch {
      // File doesn't exist or invalid, skip
    }
  }

  return { whitelist, allow }
}
