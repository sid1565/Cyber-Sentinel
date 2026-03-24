# 🛡️ CyberSentinel Security SDK

**CyberSentinel** is an AI-powered security SDK for NestJS applications. It provides a multi-layer defense system that combines **Regex-based real-time blocking** with **Claude AI-powered threat analysis and self-healing**.

---

## 🚀 The 4 Pillars of Security

### 1. Automated Vulnerability & Dependency Scanning

A CLI-based tool (`sentinel-scan`) that analyzes your project before runtime.

- **Source Code Audit**: Scans for OWASP Top 10 vulnerabilities (SQLi, XSS, Path Traversal, OS Injection).
- **NoSQL Injection Check**: Identifies risks in MongoDB/Mongoose queries.
- **Dependency Audit**: Inspects your `node_modules` for compromised packages using `npm audit`.
- **AI Security Audit**: Optionally uses Claude to provide detailed remediation steps for found issues.

### 2. Real-Time Traffic Analysis & Rate Limiting

An active firewall that monitors every request to your application.

- **Pattern Matching**: Immediate blocking of known attack signatures.
- **AI Traffic Analysis**: Background analysis of payloads using Claude to detect complex anomalies and brute-force attempts.
- **Postman Security Reports**: Automatically generates JSON reports of all failed exploitation attempts for easy reproduction.

### 3. Database & Secret Protection (Self-Healing)

A monitoring layer to ensure data integrity and prevent leakage.

- **Bulk Data Export Detection**: Blocks requests that try to extract suspiciously large amounts of data.
- **Schema Protection**: Prevents unauthorized DDL changes (e.g., `DROP`, `ALTER`) in raw queries.
- **PII Encryption**: Automated encryption and decryption of Personally Identifiable Information using the `@PII()` decorator.

### 4. Incident Reporting & Compliance Dashboard

A centralized hub for your application's security status.

- **Security Health Score**: Real-time 0–100 score based on recent threat activity.
- **Audit Logs**: Chronological log of all detected and mitigated threats.
- **Live Simulator**: Test your application's defense with built-in attack simulations.

---

## 🛠️ Installation

Since this package is managed locally, install it in your target project using the local path:

```bash
# From your target project root
npm install "/path/to/cyber-sentinel"
```

Then, compile the SDK to ensure build artifacts are ready:

```bash
cd "/path/to/cyber-sentinel"
npm run build
```

---

## ⚙️ Configuration

Register the `CyberSentinelModule` in your root `AppModule`:

```typescript
import { CyberSentinelModule } from "@company/cyber-sentinel";

@Module({
  imports: [
    CyberSentinelModule.forRoot({
      mode: "enforce", // 'enforce' = block attacks; 'monitor' = log only
      ai: {
        anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "",
        enabled: true,
      },
      // Optional customizations for bruteForce and dashboard can be added here
    }),
  ],
})
export class AppModule {}
```

---

## 📖 Usage Examples

### Protect Sensitive Fields (PII)

Mark your DTO or Entity fields as PII for automatic encryption at rest.

```typescript
import { PII } from "@company/cyber-sentinel";

export class CreateUserDto {
  @PII()
  email: string;

  @PII()
  ssn: string;
}
```

### High-Strictness Monitoring

Increase protection for specific critical routes.

```typescript
import { ThreatLevel } from "@company/cyber-sentinel";

@Controller("admin")
export class AdminController {
  @ThreatLevel("HIGH")
  @Post("users")
  create() {
    /* ... */
  }
}
```

### Exclude Routes

Explicitly opt-out of scanning for specific routes (like public health checks).

```typescript
import { SkipSentinel } from '@company/cyber-sentinel';

@SkipSentinel()
@Get('health')
getStatus() { /* ... */ }
```

---

## 🔍 Running the Scanner

Audit your codebase from the terminal:

```bash
# Basic scan
npx sentinel-scan --project ./

# AI-powered scan with remediation advice
npx sentinel-scan --project ./ --api-key YOUR_CLAUDE_KEY
```

---

## 📊 Security Dashboard

Access your live security portal at:
`http://localhost:PORT/sentinel/dashboard`

Generate a Postman Security Report of all blocked attacks:
`http://localhost:PORT/sentinel/report/postman`

---

## 📝 Requirements

- **Node.js**: 18+
- **NestJS**: 9+ or 10+
- **Anthropic API Key**: Required for AI detection and healing features.

---

**Built with ❤️ for Advanced Application Security.**
