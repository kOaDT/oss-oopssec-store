# Path Traversal / Directory Traversal Vulnerability

## Overview

This vulnerability demonstrates a critical security flaw where the application reads files from the filesystem using user-controlled input without proper sanitization or validation. This allows attackers to access files outside the intended directory by using path traversal sequences like `../` to navigate to sensitive system files or application files.

## Why This Is Dangerous

### Unrestricted File Access

When an application constructs file paths using user input without proper validation, it creates a severe security vulnerability:

1. **System file access** - Attackers can read sensitive system files like `/etc/passwd`, `/etc/shadow`, or configuration files
2. **Source code disclosure** - Application source code, configuration files, and secrets can be exposed
3. **Data exfiltration** - Database files, environment variables, and other sensitive data can be accessed
4. **Privilege escalation** - Access to configuration files may reveal credentials or allow further exploitation
5. **Compliance violations** - Unauthorized access to sensitive data violates privacy regulations

### What This Means

**Never trust user input when constructing file paths.** The server must:

- Validate and sanitize all file path inputs
- Use path normalization functions that resolve `..` sequences safely
- Restrict file access to a whitelist of allowed files or directories
- Use absolute paths with proper base directory restrictions
- Implement proper access controls for file operations

## The Vulnerability

In this application, the file reading endpoint (`/api/files/[slug]`) constructs file paths using the `slug` parameter directly without any validation or sanitization. The vulnerable code:

1. Takes the `slug` parameter directly from the URL
2. Joins it with the base directory using `path.join()`
3. Reads the file without checking if the resulting path is outside the intended directory
4. Returns the file content to the user

The `path.join()` function does not prevent path traversal attacks when user input contains `../` sequences, allowing attackers to escape the intended directory.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{p4th_tr4v3rs4l_4tt4ck}`, you need to exploit the path traversal vulnerability:

**Exploitation Steps:**

1. **Identify the vulnerable endpoint**: The endpoints `/api/files/[...path]` and `/api/files?file=...` read files from the `documents` directory
2. **Understand the directory structure**: The base directory is `documents/` within the project root, and the flag is stored in `flag.txt` at the project root
3. **Construct the path traversal payload**: To access `flag.txt` from the project root, use:
   ```
   ../flag.txt
   ```
4. **Access the vulnerable endpoint using query parameter:**

   ```
   /api/files?file=../flag.txt
   ```

5. **Retrieve the flag**: The API will return the contents of `flag.txt` containing the flag

**Alternative Exploitation Methods:**

You can also try accessing other sensitive files:

- **System files** (if running on Linux):

  ```
  /api/files/../../../../etc/passwd
  /api/files/../../../../etc/shadow
  /api/files/../../../../proc/version
  ```

- **Application files**:
  ```
  /api/files/../.env
  /api/files/../.env.local
  /api/files/../package.json
  ```

### Vulnerable Code

**File Reading Route (Vulnerable):**

```typescript
export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string }> }
) {
  try {
    const { slug } = await params;
    const baseDir = join(process.cwd(), "documents");
    const filePath = join(baseDir, slug); // ❌ No validation or sanitization
    const content = await readFile(filePath, "utf-8");

    return NextResponse.json({
      filename: slug,
      content,
    });
  } catch (error) {
    return NextResponse.json({ error: "Failed to read file" }, { status: 500 });
  }
}
```

The code directly uses the `slug` parameter in `path.join()`, which allows path traversal sequences to escape the `documents` directory.

### Best Practices

1. **Never trust user input**: Always validate and sanitize file paths constructed from user input
2. **Use absolute paths with base directory**: Always resolve paths relative to a known base directory
3. **Validate resolved paths**: After normalization, verify the path is within the allowed directory
4. **Use whitelisting**: When possible, maintain a whitelist of allowed files
5. **Validate filenames**: Reject filenames containing path traversal sequences (`..`, `/`, `\`)
6. **Use proper path functions**: Use `path.resolve()` and `path.normalize()` but still validate the result
7. **Implement access controls**: Even for allowed files, verify the user has permission to access them
8. **Log suspicious activity**: Monitor and log attempts to access files outside the intended directory

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP API Security Top 10 - API8:2019 - Injection](https://owasp.org/API-Security/editions/2019/fr/0xa8-injection/)
- [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
