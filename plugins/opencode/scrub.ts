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
      count++
      return redact(p.name, match, p.includesKey)
    })
  }

  return { text: out, count }
}
