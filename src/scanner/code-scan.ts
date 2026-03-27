// FILE: src/scanner/code-scan.ts

import * as fs from "fs";
import * as path from "path";

export interface CodeVulnerability {
  file: string;
  line: number;
  column: number;
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  snippet: string;
}

const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
]);

/**
 * Patterns for vulnerability detection.
 * Note: These are simplified regex-based detectors for static analysis.
 */
const VULNERABILITY_PATTERNS = [
  {
    type: "SQL Injection",
    severity: "CRITICAL",
    regex:
      /\.(query|execute|rawQuery|raw)\s*\(\s*([`'"].*?(\$\{.*?\}|'.*?'\s*\+\s*|[^?]*\+\s*\w+).*?['"`]?)\s*\)/i,
    description:
      "Detected potential SQL injection via string interpolation or concatenation in a raw database query.",
  },
  {
    type: "NoSQL Injection (MongoDB)",
    severity: "CRITICAL",
    regex:
      /\.(find|findOne|update|updateOne|updateMany|delete|deleteOne|deleteMany|aggregate|countDocuments|replaceOne|bulkWrite)\s*\(\s*({.*?req\.(body|query|params).*?}|req\.(body|query|params))/i,
    description:
      "Potential NoSQL injection: directly passing request objects or unvalidated properties to a MongoDB/Mongoose query. Risk: unauthorized data access or modification.",
  },
  {
    type: "NoSQL Operator Injection",
    severity: "CRITICAL",
    regex:
      /['"]?(\$where|\$expr|\$accumulator|\$function)['"]?\s*:\s*[`'"].*?(\$\{.*?\}|[^'"`]*\+\s*\w+).*?['"`]/i,
    description:
      "CRITICAL: Found NoSQL script injection using $where or similar operators with dynamic code concatenation. High risk of Remote Code Execution on DB level.",
  },
  {
    type: "NoSQL Operator Injection",
    severity: "HIGH",
    regex:
      /['"]?\$(ne|gt|gte|lt|lte|where|regex|expr)['"]?\s*:\s*req\.(body|query|params)/i,
    description:
      "Detected potential MongoDB operator injection using unsanitized request data.",
  },
  {
    type: "Insecure Regex",
    severity: "MEDIUM",
    regex: /new\s+RegExp\s*\(\s*req\.(body|query|params)/i,
    description:
      "Potential ReDoS (Regular Expression Denial of Service) through unsanitized input used in a RegExp constructor.",
  },
  {
    type: "OS Command Injection",
    severity: "CRITICAL",
    regex:
      /(exec|spawn|execSync|spawnSync)\s*\(\s*([`'"].*?(\$\{.*?\}|[^'"`]*\+\s*\w+).*?['"`]?)\s*\)/i,
    description:
      "Detected potential OS command injection via dynamic command execution with unvalidated input.",
  },
  {
    type: "Hardcoded Secret",
    severity: "HIGH",
    regex:
      /[a-z0-9_]*(?:API_KEY|SECRET|PASSWORD|PASS|TOKEN|ACCESS_KEY|SECRET_KEY|AUTH_KEY|PRIVATE_KEY|CREDENTIALS)[a-z0-9_]*\s*[:=]\s*['"`][a-z0-9_\-\.]{8,}['"`]/i,
    description:
      "Potential hardcoded secret or credential found (detected literal string assigned to a sensitive-looking key).",
  },
  {
    type: "Insecure Hash Algorithm",
    severity: "MEDIUM",
    regex: /createHash\s*\(\s*['"](md5|sha1)['"]/i,
    description:
      "Use of insecure hashing algorithm (MD5 or SHA1) which is vulnerable to collision attacks.",
  },
  {
    type: "Weak Cryptography",
    severity: "HIGH",
    regex: /crypto\.createCipher\s*\(/i,
    description:
      "Detected use of deprecated or insecure crypto.createCipher (recommend using createCipheriv with a random IV).",
  },
  {
    type: "Cross-Site Scripting (XSS)",
    severity: "HIGH",
    regex: /dangerouslySetInnerHTML/i,
    description:
      "Use of dangerouslySetInnerHTML can lead to DOM-based XSS if the content is not properly sanitized.",
  },
  {
    type: "Path Traversal",
    severity: "HIGH",
    regex:
      /\b(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|readdir|readdirSync)\s*\(\s*([`'"].*?(\$\{.*?\}|[^'"`]*\+\s*\w+).*?['"`]?)\s*\)/i,
    description:
      "Detected potential path traversal: dynamic file path construction with unvalidated concatenated input.",
  },
  {
    type: "Insecure Randomness",
    severity: "MEDIUM",
    regex: /Math\.random\s*\(\)/,
    description:
      "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomInt() for security-sensitive operations.",
  },
  {
    type: "Hardcoded Secret in Function Call",
    severity: "CRITICAL",
    regex:
      /\b(verify|sign|createHmac|createCipheriv|authenticate|login)\s*\(\s*([^,]+\s*,\s*)*['"`][a-z0-9_\-\.]{10,}['"`]\s*[,)]/i,
    description:
      "Detected potential hardcoded secret passed directly as a string literal to a security-sensitive function call.",
  },
  {
    type: "Well-known Secret Pattern",
    severity: "CRITICAL",
    regex:
      /((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})|(-----BEGIN [A-Z ]+ PRIVATE KEY-----)|(AIza[0-9A-Za-z-_]{35})|(https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+)/,
    description:
      "Detected a well-known secret pattern (AWS Key, Google API Key, RSA Private Key, or Slack Webhook).",
  },
  {
    type: "Generic Sensitive Information Disclosure",
    severity: "HIGH",
    regex:
      /\b(?:key|secret|password|pass|token|auth|api|id|sid|access|cred|private|pk|sk)\b\s*[:=]\s*['"`][a-z0-9_\-\.]{10,}['"`]/i,
    description:
      "Potential hardcoded credential detected based on sensitive keyword assignment.",
  },
];

export function scanSourceCode(projectPath: string): CodeVulnerability[] {
  const vulnerabilities: CodeVulnerability[] = [];
  const files = collectSourceFiles(projectPath);

  for (const file of files) {
    const fileVulnerabilities = analyzeFile(file);
    vulnerabilities.push(...fileVulnerabilities);
  }

  return vulnerabilities;
}

function analyzeFile(filePath: string): CodeVulnerability[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const lines = content.split("\n");
  const fileVulns: CodeVulnerability[] = [];

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i];

    for (const pattern of VULNERABILITY_PATTERNS) {
      if (pattern.regex.test(lineContent)) {
        fileVulns.push({
          file: filePath,
          line: i + 1,
          column: lineContent.indexOf(lineContent.trim()),
          type: pattern.type,
          severity: pattern.severity as any,
          description: pattern.description,
          snippet: lineContent.trim(),
        });
      }
    }
  }

  return fileVulns;
}

function collectSourceFiles(dir: string): string[] {
  const results: string[] = [];
  walkDir(dir, results);
  return results;
}

function walkDir(dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (IGNORE_DIRS.has(entry.name)) continue;

    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(full, out);
    } else if (entry.isFile() && /\.(ts|js|tsx|jsx)$/.test(entry.name)) {
      out.push(full);
    }
  }
}
