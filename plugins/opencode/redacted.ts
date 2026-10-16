// redacted: OpenCode plugin that scrubs secrets from tool output (https://github.com/svn-arv/redacted)
import type { Plugin } from "@opencode-ai/plugin"

// The binary does the scrubbing; this file only carries OpenCode's output to it and back.
export const Redacted: Plugin = async ({ $, directory }) => ({
  "tool.execute.after": async (input, output) => {
    const bin = process.env.REDACTED_BIN || "redacted"
    const payload = JSON.stringify({
      tool: input.tool,
      sessionID: input.sessionID,
      callID: input.callID,
      args: input.args,
      output,
    })
    // A Response after `<` is Bun shell's way to feed a string to stdin.
    const result = await $`${bin} scrub --format opencode --cwd ${directory} < ${new Response(payload)}`
      .quiet()
      .nothrow()
    // A throw fails the tool call, so the model never sees raw output.
    // stderr is left out of the message: it can quote the config file.
    if (result.exitCode !== 0) {
      throw new Error(`redacted: scrub exited ${result.exitCode}, tool output withheld`)
    }
    let scrubbed: unknown
    try {
      scrubbed = JSON.parse(result.stdout.toString())
    } catch {
      throw new Error("redacted: scrub printed no JSON, tool output withheld")
    }
    // OpenCode keeps its reference to `output`, so it is rewritten in place, not replaced.
    for (const key of Object.keys(output)) {
      delete (output as Record<string, unknown>)[key]
    }
    if (typeof scrubbed === "object" && scrubbed !== null) {
      Object.assign(output, scrubbed)
    } else {
      // `output.output` is the text the model reads for a built-in tool.
      output.output = String(scrubbed)
    }
  },
})
