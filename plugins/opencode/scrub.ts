import type { CompiledPattern } from "./patterns"

export interface ScrubResult {
  text: string
  count: number
}

function tail(s: string, n: number): string {
  return s.length <= n ? s : s.slice(-n)
}

function redact(name: string, match: string, includesKey: boolean): string {
  if (includesKey) {
    const eqIdx = match.indexOf("=")
    const colonIdx = match.indexOf(":")
    const idx = eqIdx >= 0 ? eqIdx : colonIdx
    if (idx >= 0) {
      const key = match.slice(0, idx).trimEnd()
      const value = match.slice(idx + 1).trimStart()
      return `${key}=[REDACTED ...${tail(value, 4)}]`
    }
  }
  return `[REDACTED:${name} ...${tail(match, 4)}]`
}

// valueOf returns the right-hand side of a KEY=value or KEY: value match,
// using whichever of `=` or `:` appears first (matching the Go side).
function valueOf(match: string): string {
  for (let i = 0; i < match.length; i++) {
    const ch = match[i]
    if (ch === "=" || ch === ":") {
      return match.slice(i + 1).trimStart()
    }
  }
  return ""
}

// looksLikeIdentifier reports whether v is a plain snake_case or CONSTANT_CASE
// identifier — variable references in source code rather than actual secrets.
function looksLikeIdentifier(v: string): boolean {
  if (!v.includes("_")) return false
  let hasLower = false
  let hasUpper = false
  for (const ch of v) {
    const code = ch.charCodeAt(0)
    if (code >= 97 && code <= 122) hasLower = true
    else if (code >= 65 && code <= 90) hasUpper = true
    else if (ch !== "_") return false
  }
  return (hasLower && !hasUpper) || (hasUpper && !hasLower)
}

export function scrub(
  text: string,
  patterns: CompiledPattern[],
  allowed: Set<string>,
): ScrubResult {
  let out = text
  let count = 0

  for (const p of patterns) {
    p.regex.lastIndex = 0
    out = out.replace(p.regex, (match) => {
      if (allowed.size > 0) {
        const upper = match.toUpperCase()
        for (const name of allowed) {
          if (upper.includes(name)) return match
        }
      }
      if (p.includesKey && looksLikeIdentifier(valueOf(match))) {
        return match
      }
      count++
      return redact(p.name, match, p.includesKey)
    })
  }

  return { text: out, count }
}
