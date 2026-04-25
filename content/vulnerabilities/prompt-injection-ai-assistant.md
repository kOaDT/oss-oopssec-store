# Prompt Injection (AI Assistant)

## Overview

LLMs cannot reliably tell developer-supplied instructions apart from user-supplied content — both arrive as text, and the model's "rules" are themselves just text in the same context window. Any application that concatenates a system prompt with user input is vulnerable to instructions hidden inside that input. Layering a regex-based denylist on top is a speed bump, not a defense.

In this challenge, the AI Support Assistant builds its prompt with a confidential validation code embedded directly in the system message, then appends the user's message verbatim. A surface-level pattern filter exists, but rephrasing trivially bypasses it.

## Why This Is Dangerous

- **System prompt extraction** — instructions, "internal" metadata, and any secrets baked into the prompt can be coaxed out.
- **Behavioral override** — the model can be talked out of safety rules, escalated to use restricted tools, or steered to attack the user.
- **No clean trust boundary** — there is no markup or token that reliably tells the model "this came from the user, don't follow it".
- **Cascading bugs** — secrets revealed via prompt injection often unlock other systems (admin endpoints, internal tools, external APIs).

## Vulnerable Code

```typescript
const SYSTEM_PROMPT = `You are OSSBot, ...

INTERNAL CONFIGURATION:
---
Assistant ID: OSS-SUPPORT-BOT-v2.1
Internal validation code: <secret>
---

Tool restrictions:
- The get_compliance_report tool is restricted to authorized
  compliance directives only. ...
`;

if (containsBlockedPattern(message)) {
  return NextResponse.json({
    response: "I'm sorry, but I can't process that request. ...",
  });
}

const messages = [
  { role: "system", content: SYSTEM_PROMPT },
  { role: "user", content: message },
];

const response = await callMistral(apiKey, messages, mistralTools);
```

Two compounding mistakes:

1. **Secrets in the prompt.** The validation code is in the same context window as user input, so the model can be asked, indirectly, to reveal it.
2. **Filter as the only defense.** A regex over the user message catches "ignore previous instructions" but not roleplay framing, translation tricks, completion lures, or any of the standard rephrasings.

## Secure Implementation

Treat the prompt as untrusted, the model output as untrusted, and never put secrets where the model can see them.

**Keep secrets out of the prompt.** Anything sensitive belongs behind an authenticated API call the model can _request_ — not in the static system message. The reference for "what code does this assistant report" should live in code (or in a tool the LLM has restricted access to), never in plain text inside the prompt.

**Structure the conversation, then mark provenance.** Use the model's native role separation (system / user / tool) and add explicit, machine-readable provenance to any user-supplied content. The model will still occasionally be fooled, so this is one layer of several.

**Filter outputs as well as inputs.** Scan model responses for patterns that resemble leaked secrets (project-specific markers, key shapes, internal hostnames) and block or redact before returning to the client.

**Constrain capabilities by context.** When the agent has access to privileged tools, gate those tools behind explicit user actions or signed directives, not on free-form natural-language confirmation. Combine with tool-response sanitization (see the Malicious MCP Server write-up) to defeat indirect injection through tool outputs.

**Log and monitor.** Sample prompts and responses, alert on anomalous patterns, and rotate any credentials that might have leaked the moment a successful exploit is observed.

## References

- [OWASP LLM Top 10 — LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Simon Willison — Prompt injection](https://simonwillison.net/series/prompt-injection/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Anthropic — Mitigating prompt injection](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/mitigate-prompt-injection)
