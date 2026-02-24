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

- [ ] Tests pass (`npm test`)
- [ ] Lint passes (`npm run lint`)
- [ ] Documentation updated (if applicable)

### If adding a new vulnerability

- [ ] Flag added in `prisma/seed.ts` with format `OSS{...}`
- [ ] Three progressive hints added in `prisma/seed.ts`
- [ ] Vulnerable code path is exploitable and demonstrable
- [ ] Markdown documentation added under `content/vulnerabilities/`
- [ ] Regression tests added (unit, API, and/or E2E)
- [ ] No real-world secrets introduced
