## Description

<!-- Describe your changes clearly and concisely. -->

## Type of change

- [ ] Bug fix
- [ ] New feature (e-commerce site improvement)
- [ ] New vulnerability / flag
- [ ] Walkthrough / writeup
- [ ] Documentation update
- [ ] Other (please describe):

## Testing done

<!-- Describe how you tested your changes. -->

## Checklist

- [ ] Documentation updated (if applicable)

### If adding a new challenge

Full walkthrough in [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-challenge). `npm run test:unit` checks most of this and names whatever is missing.

- [ ] Flag added in `prisma/flags.ts` with format `OSS{...}`
- [ ] Three progressive hints added in `flagHints` (vague → near-solution)
- [ ] Vulnerable code path is exploitable and reachable from the UI
- [ ] Reference doc added under `content/vulnerabilities/` (concept + fix only — no exploit steps, payloads, or flag value)
- [ ] Flag value mirrored in `tests/helpers/flags.ts`
- [ ] Regression tests added (unit, API, and/or E2E), asserting the vulnerable behaviour
- [ ] Walkthrough added under `docs/src/data/blog/`, with a matching `walkthroughSlug`
- [ ] Challenge added to `docs/src/data/roadmap.ts` (slug, difficulty, category and walkthrough matching the flag)
- [ ] Counts and catalog updated in `README.md` and `EDUCATORS.md` (including the OWASP grid and syllabus plans)
- [ ] No real-world secrets introduced
