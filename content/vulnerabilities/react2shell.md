# React2Shell (CVE-2025-55182)

## Overview

CVE-2025-55182, also known as **React2Shell**, is a critical pre-authentication remote code execution vulnerability in React Server Components. Affected versions deserialize Flight protocol payloads in a way that lets an attacker traverse the JavaScript prototype chain and reach the global `Function` constructor, turning a request payload into arbitrary server-side code execution.

**CVSS Score:** 10.0 (Critical)

## Affected Versions

- React Server Components 19.0.0, 19.1.0, 19.1.1, and 19.2.0
- Packages: `react-server-dom-parcel`, `react-server-dom-turbopack`, `react-server-dom-webpack`

## Why This Is Dangerous

The vulnerability stems from how React Server Components deserialize Flight protocol payloads:

1. **Unsafe deserialization** — Flight payloads are processed without strict validation of the property names being accessed.
2. **Prototype chain traversal** — Module references are resolved with bracket notation (`moduleExports[metadata[2]]`), which walks the entire prototype chain.
3. **Constructor access** — Walking the chain exposes the `constructor` property, giving the attacker a handle on the global `Function` constructor.
4. **Code execution** — Combined with React's chunk processing, the attacker can build a payload that compiles and runs arbitrary JavaScript inside the Node.js process.

A successful exploit lets an attacker read environment files, exfiltrate data, spawn reverse shells, or perform any operation the Node.js process is allowed to perform.

## Vulnerable Pattern

The unsafe pattern looks roughly like this in the affected versions:

```ts
// In the Flight deserializer
const value = moduleExports[metadata[2]];
```

Because `moduleExports` is a regular object, `metadata[2]` can be any string an attacker controls — including inherited names like `constructor`, which short-circuits to `Function` and unlocks code execution downstream.

## Secure Implementation

Application owners cannot fix this in user code — the issue lives inside React's server-rendering pipeline. Mitigation is a dependency upgrade:

1. **Upgrade React** to a version that ships the patched Flight deserializer (19.2.1 or later).
2. **Upgrade Next.js** to a release that bundles the patched React Server Components.
3. **Audit transitive dependencies** for older copies of `react-server-dom-*` packages.

For library authors writing similar deserialization code, the general lesson is: never use bracket-notation lookups on user-controlled keys against an unprotected object. Use a `Map`, `Object.create(null)`, or an explicit allowlist of property names instead.

## References

- [CVE-2025-55182 Details](https://www.cyberhub.blog/cves/CVE-2025-55182)
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Facebook Security Advisory](https://www.facebook.com/security/advisories/cve-2025-55182)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-55182)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
