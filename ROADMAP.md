# Roadmap

This document outlines planned features, security vulnerabilities, and improvements for OSS – OopsSec Store.

If you're interested in working on any of these items, feel free to pick one up and submit a pull request. Don't hesitate to open a discussion or issue if you have questions or want to propose alternative approaches.

---

## Planned Security Vulnerabilities

The following security vulnerabilities are planned for future releases. Each vulnerability should include:

- Implementation in the codebase
- A flag in the `OSS{...}` format added to `prisma/seed.ts`
- Documentation in `content/vulnerabilities/` following the `vulnerability-name.md` format

### Rate Limiting & Brute Force

**Status:** Planned

Implement a vulnerability demonstrating the lack of rate limiting on authentication endpoints, particularly the login form. This should allow attackers to perform brute force attacks against user credentials without restrictions.

**Implementation ideas:**

- Remove or bypass rate limiting on `/api/auth/login`
- Allow unlimited login attempts
- Potentially expose user enumeration through different error messages or response times
- Flag could be discovered after successfully brute-forcing an account or through rate limit bypass techniques

---

### Information Disclosure via API Error Messages

**Status:** Planned

Create a vulnerability where API routes leak sensitive information, including flags, through error messages. This could involve a lambda route or error handler that inadvertently exposes flags when exceptions occur.

**Implementation ideas:**

- Implement error handling that includes flag information in stack traces or error responses
- Create a route that processes user input and throws errors containing flags
- Ensure error messages reveal internal structure or sensitive data
- Flag should be discoverable by triggering specific error conditions

---

### Session Fixation & Weak Session Management

**Status:** Planned

Implement vulnerabilities related to session fixation and weak session management, demonstrating how improper JWT token lifecycle management can lead to security issues.

**Implementation ideas:**

- Implement JWT tokens with excessively long expiration times (e.g., 1 year or more)
- Remove or bypass token invalidation on logout - tokens remain valid even after user logs out
- Create an endpoint that allows generating tokens for any user (session fixation attack vector)
- Do not invalidate or rotate tokens when passwords are changed
- Allow tokens to be reused indefinitely without expiration or revocation
- Flag could be discoverable by exploiting a fixed session token or by using a token that should have been invalidated

---

### Malicious File Upload (Stored XSS)

**Status:** Planned

Implement a file upload vulnerability where administrators can upload product images. By replacing an image with a malicious script, an attacker could achieve stored XSS.

**Implementation ideas:**

- Add an admin interface for managing product images
- Implement file upload functionality with insufficient validation
- Allow file types other than images to be uploaded
- Store uploaded files in a way that makes them executable or renderable
- Flag should be discoverable after uploading a malicious file that triggers XSS
- Requires privilege escalation to admin role first

---

### SQL Injection in Product Search

**Status:** Planned

Add a product search functionality vulnerable to SQL injection attacks.

**Implementation ideas:**

- Create a search endpoint that queries the database with user input
- Use string concatenation or unsafe query building instead of parameterized queries
- Allow SQL injection through the search parameter
- Flag could be embedded in the database and retrievable via SQL injection
- Document the vulnerability and exploitation techniques

---

### Password Reset Token Padding Oracle (AES-CBC)

**Status:** Planned

Implement a password reset functionality where the reset token is encrypted using AES-CBC without authentication, transmitted in the URL, and vulnerable to padding oracle attacks.

**Implementation ideas:**

- Create a password reset flow with email-based token generation
- Encrypt the reset token using AES-CBC without proper authentication
- Include the encrypted token in the reset URL
- Implement error handling that reveals padding validation results through HTTP status codes
- Allow attackers to decrypt the token byte-by-byte by observing error responses
- Enable modification of the `user_id` field within the decrypted token
- Flag should be discoverable after successfully resetting another user's password (e.g., admin account)

---

### Insufficient Security Headers in Next.js Middleware

**Status:** Planned

Add a vulnerability related to insufficient or missing security headers in Next.js middleware configuration.

**Implementation ideas:**

- Create or modify `middleware.ts` with weak security headers
- Missing or improperly configured headers such as:
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security (HSTS)
  - Referrer-Policy
- Demonstrate how missing headers enable attacks (e.g., clickjacking, MIME type sniffing)
- Flag could be related to exploiting the lack of security headers

---

## Other Contribution Opportunities

Beyond security vulnerabilities, there are many ways to contribute to OSS – OopsSec Store:

### New Features

- Enhance the e-commerce functionality (wishlists, product recommendations, etc.)
- Expand the database model with new entities and relationships
- Build additional customer-facing features (order history, account management, etc.)
- Create new admin interfaces for managing the store
- Add new product categories, filters, or sorting options

### UI/UX Improvements

- Improve responsive design for mobile and tablet devices
- Enhance accessibility (ARIA labels, keyboard navigation, screen reader support)
- Refine the visual design and user interface
- Add loading states and better error handling in the UI
- Improve form validation and user feedback

### Bug Fixes

- Fix non-intentional UI/UX bugs
- Resolve functionality issues that are not intentional vulnerabilities
- Address performance issues
- Fix browser compatibility problems

### Code Quality & Refactoring

- Refactor duplicate code to follow DRY principles
- Improve code organization and structure
- Add type safety improvements
- Optimize database queries
- Enhance error handling patterns

### Documentation

- Improve vulnerability write-ups with more examples
- Add exploitation walkthroughs and tutorials
- Fix typos and improve clarity
- Add code comments where necessary
- Create video tutorials or visual guides
- Enhance API documentation

---

## How to Contribute

1. **Pick an item** from this roadmap or propose your own idea
2. **Open an issue** to discuss your approach (optional but recommended for larger changes)
3. **Fork the repository** and create a feature branch
4. **Implement your changes** following the [Contributing Guidelines](CONTRIBUTING.md)
5. **Submit a Pull Request** with a clear description of your changes

For security vulnerabilities:

- Add the flag to `prisma/seed.ts` using the `OSS{...}` format
- Create documentation in `content/vulnerabilities/` following existing patterns
- Ensure the vulnerability is exploitable and educational

For other contributions:

- Follow existing code style and patterns
- Ensure your changes don't introduce unintentional security flaws
- Test your changes thoroughly

We appreciate all contributions and look forward to your pull requests!

---

## Questions or Ideas?

If you have questions about any roadmap item or want to propose new ideas:

- Open a [GitHub Discussion](https://github.com/kOaDT/oss-oopssec-store/discussions) to start a conversation
- Create a [GitHub Issue](https://github.com/kOaDT/oss-oopssec-store/issues) to propose new features or report problems
- Submit a Pull Request directly if you're ready to implement
