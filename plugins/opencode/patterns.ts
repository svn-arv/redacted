import { readFileSync } from "fs"
import { join } from "path"
import { parse } from "yaml"

export interface CompiledPattern {
  name: string
  regex: RegExp
  includesKey: boolean
}

interface PatternFile {
  keywords: string[]
  patterns: { name: string; regex: string; includes_key?: boolean }[]
}

// Convert Go-style inline flags (?i) to JS RegExp flags.
// Go/RE2 uses (?i) inside the pattern; JS uses flags argument.
function toJSRegex(expr: string): { pattern: string; flags: string } {
  let flags = "g"
  let pattern = expr

  if (pattern.startsWith("(?i)")) {
    flags += "i"
    pattern = pattern.slice(4)
  }

  // Go's [\s\S] for dotall works in JS too, no conversion needed
  return { pattern, flags }
}

function loadPatternFile(): PatternFile {
  const patternsPath = join(__dirname, "../../internal/patterns/patterns.yaml")
  return parse(readFileSync(patternsPath, "utf-8")) as PatternFile
}

export function compilePatterns(): CompiledPattern[] {
  const file = loadPatternFile()

  const patterns: CompiledPattern[] = file.patterns.map((p) => {
    const { pattern, flags } = toJSRegex(p.regex)
    return {
      name: p.name,
      regex: new RegExp(pattern, flags),
      includesKey: p.includes_key ?? false,
    }
  })

  const kw = file.keywords.join("|")

  patterns.push({
    name: "env_secret",
    regex: new RegExp(
      `\\b[A-Z0-9_]*(${kw})[A-Z0-9_]*\\s*[=:]\\s*[^\\s\\[][^\\s]{7,}`,
      "gi",
    ),
    includesKey: true,
  })

  patterns.push({
    name: "yaml_secret",
    regex: new RegExp(
      `key:\\s*[A-Z0-9_]*(${kw})[A-Z0-9_]*\\s*\\n\\s*value:\\s*[^\\s\\[][^\\s]{7,}`,
      "gi",
    ),
    includesKey: true,
  })

  return patterns
}
