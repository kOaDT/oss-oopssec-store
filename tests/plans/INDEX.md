# Vulnerability Test Plans

This directory contains one detailed test plan per vulnerability. Each plan is designed to be self-contained: pass the markdown file to a Claude Code instance and it has all the context needed to implement the tests.

## Architecture Overview

- **Jest unit tests** → `tests/unit/` — Test utility functions (hashMD5, JWT, filters)
- **Jest API tests** → `tests/api/` — Test API endpoints directly (exploitation scenarios)
- **Cypress E2E tests** → `cypress/e2e/` — Test full UI exploitation workflows
- **Test helpers** → `tests/helpers/api.ts` — Shared login, request, and assertion utilities
- **Cypress commands** → `cypress/support/commands.ts` — Custom Cypress commands (login, verifyFlag)

## Running Tests

```bash
# Unit tests only
npm run test:unit

# API tests only (requires running server: npm run dev)
npm run test:api

# E2E tests (requires running server)
npm run test:e2e

# Open Cypress interactive mode
npm run test:e2e:open

# All tests
npm run test:ci
```

## Test Plans by Category

### Injection (7)

| #   | File                                                                       | Slug                            | Flag                                 |
| --- | -------------------------------------------------------------------------- | ------------------------------- | ------------------------------------ |
| 01  | [01-sql-injection.md](01-sql-injection.md)                                 | `sql-injection`                 | `OSS{sql_1nj3ct10n_vuln3r4b1l1ty}`   |
| 02  | [02-product-search-sql-injection.md](02-product-search-sql-injection.md)   | `product-search-sql-injection`  | `OSS{pr0duct_s34rch_sql_1nj3ct10n}`  |
| 03  | [03-x-forwarded-for-sql-injection.md](03-x-forwarded-for-sql-injection.md) | `x-forwarded-for-sql-injection` | `OSS{x_f0rw4rd3d_f0r_sql1}`          |
| 04  | [04-second-order-sql-injection.md](04-second-order-sql-injection.md)       | `second-order-sql-injection`    | `OSS{s3c0nd_0rd3r_sql_1nj3ct10n}`    |
| 05  | [05-cross-site-scripting-xss.md](05-cross-site-scripting-xss.md)           | `cross-site-scripting-xss`      | `OSS{cr0ss_s1t3_scr1pt1ng_xss}`      |
| 06  | [06-prompt-injection-ai-assistant.md](06-prompt-injection-ai-assistant.md) | `prompt-injection-ai-assistant` | `OSS{pr0mpt_1nj3ct10n_41_4ss1st4nt}` |
| 22  | [22-malicious-file-upload.md](22-malicious-file-upload.md)                 | `malicious-file-upload`         | `OSS{m4l1c10us_f1l3_upl04d_xss}`     |

### Authentication (4)

| #   | File                                                                                             | Slug                                       | Flag                             |
| --- | ------------------------------------------------------------------------------------------------ | ------------------------------------------ | -------------------------------- |
| 10  | [10-weak-jwt-secret.md](10-weak-jwt-secret.md)                                                   | `weak-jwt-secret`                          | `OSS{w34k_jwt_s3cr3t_k3y}`       |
| 11  | [11-weak-md5-hashing.md](11-weak-md5-hashing.md)                                                 | `weak-md5-hashing`                         | `OSS{w34k_md5_h4sh1ng}`          |
| 13  | [13-session-fixation-weak-session-management.md](13-session-fixation-weak-session-management.md) | `session-fixation-weak-session-management` | `OSS{s3ss10n_f1x4t10n_4tt4ck}`   |
| 14  | [14-brute-force-no-rate-limiting.md](14-brute-force-no-rate-limiting.md)                         | `brute-force-no-rate-limiting`             | `OSS{brut3_f0rc3_n0_r4t3_l1m1t}` |

### Authorization (2)

| #   | File                                                                               | Slug                                | Flag                                     |
| --- | ---------------------------------------------------------------------------------- | ----------------------------------- | ---------------------------------------- |
| 08  | [08-insecure-direct-object-reference.md](08-insecure-direct-object-reference.md)   | `insecure-direct-object-reference`  | `OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}`  |
| 09  | [09-broken-object-level-authorization.md](09-broken-object-level-authorization.md) | `broken-object-level-authorization` | `OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}` |

### Request Forgery (2)

| #   | File                                                                   | Slug                          | Flag                               |
| --- | ---------------------------------------------------------------------- | ----------------------------- | ---------------------------------- |
| 16  | [16-cross-site-request-forgery.md](16-cross-site-request-forgery.md)   | `cross-site-request-forgery`  | `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}`  |
| 17  | [17-server-side-request-forgery.md](17-server-side-request-forgery.md) | `server-side-request-forgery` | `OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}` |

### Input Validation (2)

| #   | File                                                                         | Slug                             | Flag                                  |
| --- | ---------------------------------------------------------------------------- | -------------------------------- | ------------------------------------- |
| 12  | [12-mass-assignment.md](12-mass-assignment.md)                               | `mass-assignment`                | `OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}`  |
| 15  | [15-client-side-price-manipulation.md](15-client-side-price-manipulation.md) | `client-side-price-manipulation` | `OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}` |

### Information Disclosure (3)

| #   | File                                                                             | Slug                               | Flag                               |
| --- | -------------------------------------------------------------------------------- | ---------------------------------- | ---------------------------------- |
| 18  | [18-path-traversal.md](18-path-traversal.md)                                     | `path-traversal`                   | `OSS{p4th_tr4v3rs4l_4tt4ck}`       |
| 19  | [19-information-disclosure-api-error.md](19-information-disclosure-api-error.md) | `information-disclosure-api-error` | `OSS{1nf0_d1scl0sur3_4p1_3rr0r}`   |
| 20  | [20-public-env-variable.md](20-public-env-variable.md)                           | `public-env-variable`              | `OSS{public_3nvir0nment_v4ri4bl3}` |
| 21  | [21-plaintext-password-in-logs.md](21-plaintext-password-in-logs.md)             | `plaintext-password-in-logs`       | `OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}`  |

### Cryptographic (1)

| #   | File                                             | Slug               | Flag                    |
| --- | ------------------------------------------------ | ------------------ | ----------------------- |
| 11  | [11-weak-md5-hashing.md](11-weak-md5-hashing.md) | `weak-md5-hashing` | `OSS{w34k_md5_h4sh1ng}` |

### Remote Code Execution (1)

| #   | File                                   | Slug          | Flag               |
| --- | -------------------------------------- | ------------- | ------------------ |
| 23  | [23-react2shell.md](23-react2shell.md) | `react2shell` | `OSS{r3act2sh3ll}` |

### XXE (1)

| #   | File                                                               | Slug                        | Flag                                 |
| --- | ------------------------------------------------------------------ | --------------------------- | ------------------------------------ |
| 07  | [07-xxe-supplier-order-import.md](07-xxe-supplier-order-import.md) | `xxe-supplier-order-import` | `OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}` |

## Conventions

- Each test file should be named after the vulnerability slug: `<slug>.test.ts` or `<slug>.cy.ts`.
- Use the shared helpers in `tests/helpers/api.ts` for login, auth headers, and flag assertions.
- Use Cypress custom commands from `cypress/support/commands.ts` for E2E login flows.
- Each test should be independent and not rely on state from other tests.
- Use unique identifiers (timestamps/UUIDs) in test data to avoid conflicts between runs.
