// Standalone test — simulates OpenCode's tool.execute.after hook
// Run with: node --loader ts-node/esm test.mjs
//   or:     npx tsx test.mjs

import { compilePatterns } from "./patterns.ts"
import { scrub } from "./scrub.ts"
import { loadConfig } from "./config.ts"
import { randomBytes } from "crypto"

const compiled = compilePatterns()
console.log(`Loaded ${compiled.length} patterns\n`)

// Generate fake secrets at runtime to avoid GitHub push protection flags.
function randHex(n) {
  return randomBytes(Math.ceil(n / 2)).toString("hex").slice(0, n)
}
function randAlphaNum(n) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  return Array.from(randomBytes(n), (b) => chars[b % chars.length]).join("")
}

const fakeStripe = `sk_live_${randAlphaNum(24)}`
const fakeTwilioSID = `AC${randHex(32)}`
const fakeTwilioAuth = randHex(32)
const fakeAWS = `AKIA${randAlphaNum(16).toUpperCase()}`
const fakeSentry = `https://${randHex(32)}@o${randHex(6)}.ingest.sentry.io/${randHex(7)}`

// Simulate bash output from a `cat .env`
const bashOutput = `RAILS_ENV=development
DATABASE_URL=postgres://admin:${randAlphaNum(12)}@db.example.com:5432/prod
REDIS_URL=rediss://default:${randAlphaNum(10)}@redis.example.com:6379
SECRET_KEY_BASE=${randHex(32)}
STRIPE_SECRET_KEY=${fakeStripe}
TWILIO_ACCOUNT_SID=${fakeTwilioSID}
TWILIO_AUTH_TOKEN=${fakeTwilioAuth}
AWS_ACCESS_KEY_ID=${fakeAWS}
SENTRY_DSN=${fakeSentry}
APP_NAME=myapp
LOG_LEVEL=info`

// Scrub with no config (no whitelist/allow)
const result = scrub(bashOutput, compiled, new Set())

console.log("=== SCRUBBED OUTPUT ===")
console.log(result.text)
console.log(`\n=== ${result.count} secret(s) found ===\n`)

// Verify non-secrets pass through
const checks = [
  ["APP_NAME=myapp", true],
  ["LOG_LEVEL=info", true],
  ["RAILS_ENV=development", true],
  ["sk_live_", false],
  ["admin:", false],
  [fakeAWS, false],
]

let passed = 0
let failed = 0

for (const [text, shouldExist] of checks) {
  const exists = result.text.includes(text)
  if (exists === shouldExist) {
    passed++
  } else {
    failed++
    console.log(`FAIL: "${text}" ${shouldExist ? "should exist" : "should NOT exist"} in output`)
  }
}

// Identifier-like values in source code should NOT be scrubbed.
// Real secrets with digits or mixed case SHOULD be scrubbed.
const fpCases = [
  { input: "token = not_token", clean: true },
  { input: "token: other_token", clean: true },
  { input: "TOKEN = OTHER_TOKEN_CONST", clean: true },
  { input: "secret_key = secret_key_var", clean: true },
  { input: "token = params[:token]", clean: true },
  { input: "token = @other_token", clean: true },
  { input: `{"SECRET_KEY=[REDACTED", more},`, clean: true },
  { input: "TOKEN=my_token_123", clean: false },
  { input: "TOKEN=MyRealSecretToken", clean: false },
]

for (const { input, clean } of fpCases) {
  const r = scrub(input, compiled, new Set())
  const wasScrubbed = r.count > 0
  if (clean === !wasScrubbed) {
    passed++
  } else {
    failed++
    console.log(
      `FAIL: ${JSON.stringify(input)} should ${clean ? "NOT redact" : "redact"}, got: ${JSON.stringify(r.text)}`,
    )
  }
}

console.log(`${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
