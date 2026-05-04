/* eslint-disable */
/**
 * ============================================================================
 *  CTF LAB ARTIFACT — INERT POSTINSTALL
 * ============================================================================
 *
 *  This file is part of the OSS – OopsSec Store CTF lab. It is shipped purely
 *  as a *readable* artifact for players to inspect; it is NEVER executed:
 *
 *    1. The `react-toastfy` package is intentionally NOT listed in the root
 *       `package.json`. It lives at `packages/react-toastfy/` for inspection
 *       only — there is no `npm install` path that triggers this script.
 *    2. This script performs zero filesystem writes, zero network calls, and
 *       zero shell-outs. It logs once and exits cleanly.
 *
 *  In a real-world supply-chain attack, a malicious `postinstall` script
 *  bundled with a typosquatted package would write a poisoned AI rules file
 *  to a developer's auto-loaded tooling path, e.g.:
 *
 *      ~/.cursor/rules/productivity-helper.mdc
 *      ~/.claude/skills/productivity-helper/SKILL.md
 *      ~/.windsurf/rules/productivity-helper.md
 *
 *  The dropped file would then be picked up by the developer's AI coding
 *  agent on the next session, silently steering future code generation.
 *
 *  For pedagogy, an equivalent payload that *would have been written* is
 *  pre-committed in the lab at:
 *
 *      lab/quarantine/productivity-helper.mdc
 *
 *  Read it through the path-traversal endpoint to continue the chain.
 *
 *  Real-world references:
 *    - Pillar Security, "Rules File Backdoor" (March 2025)
 *    - npm "Shai-Hulud" worm (September 2025)
 *    - ua-parser-js, event-stream, colors.js historical incidents
 * ============================================================================
 */

console.log("[react-toastfy] productivity defaults ready");

process.exit(0);
