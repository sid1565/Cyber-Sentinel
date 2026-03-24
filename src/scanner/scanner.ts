#!/usr/bin/env node
// FILE: src/scanner/scanner.ts

import * as path from "path";
import * as fs from "fs";
import Anthropic from "@anthropic-ai/sdk";
import { runDepAudit } from "./dep-audit";
import type { CveReport } from "./dep-audit";
import { checkEnvFiles } from "./env-check";
import type { EnvIssue } from "./env-check";
import { checkRouteGuards } from "./route-guard-check";
import type { UnguardedRoute } from "./route-guard-check";
import { scanSourceCode } from "./code-scan";
import type { CodeVulnerability } from "./code-scan";

interface ScanReport {
  projectPath: string;
  timestamp: string;
  depAudit: CveReport;
  envIssues: EnvIssue[];
  unguardedRoutes: UnguardedRoute[];
  codeVulnerabilities: CodeVulnerability[];
  aiAnalysis?: string;
  summary: { criticalIssues: number; totalIssues: number; passed: boolean };
}

function parseArgs(argv: string[]): { projectPath: string; apiKey?: string } {
  const args = argv.slice(2);
  const projIdx = args.indexOf("--project");
  const keyIdx = args.indexOf("--api-key");
  return {
    projectPath:
      projIdx !== -1 && args[projIdx + 1]
        ? path.resolve(args[projIdx + 1])
        : process.cwd(),
    apiKey: keyIdx !== -1 ? args[keyIdx + 1] : process.env["ANTHROPIC_API_KEY"],
  };
}

function sep(title: string): void {
  console.log("\n" + "═".repeat(64));
  console.log(`  ${title}`);
  console.log("═".repeat(64));
}

function printReport(r: ScanReport): void {
  sep("DEPENDENCY AUDIT");
  if (r.depAudit.total === 0) {
    console.log("  ✅  No vulnerabilities found");
  } else {
    console.log(
      `  ❌  ${r.depAudit.total} vulns  (critical:${r.depAudit.critical} high:${r.depAudit.high} moderate:${r.depAudit.moderate} low:${r.depAudit.low})`,
    );
    r.depAudit.vulnerabilities
      .slice(0, 10)
      .forEach((v) =>
        console.log(
          `      [${v.severity.toUpperCase().padEnd(8)}] ${v.name}: ${v.title}`,
        ),
      );
    if (r.depAudit.total > 10)
      console.log(`      … and ${r.depAudit.total - 10} more`);
  }

  sep("ENVIRONMENT VARIABLE CHECK");
  if (r.envIssues.length === 0) {
    console.log("  ✅  No issues found");
  } else {
    r.envIssues.forEach((i) => {
      const icon =
        i.severity === "CRITICAL" ? "🔴" : i.severity === "HIGH" ? "🟠" : "🟡";
      console.log(`  ${icon} [${i.severity}] ${i.variable}: ${i.issue}`);
      console.log(`       ${i.file}`);
    });
  }

  sep("ROUTE GUARD CHECK");
  if (r.unguardedRoutes.length === 0) {
    console.log("  ✅  All routes have guards");
  } else {
    r.unguardedRoutes.forEach((rt) => {
      console.log(`  ⚠️   [${rt.httpMethod.padEnd(7)}] ${rt.routePath}`);
      console.log(`        ${rt.class}.${rt.method}() — ${rt.issue}`);
    });
  }

  sep("SOURCE CODE VULNERABILITY SCAN (OWASP Top 10)");
  if (r.codeVulnerabilities.length === 0) {
    console.log("  ✅  No source code vulnerabilities detected");
  } else {
    r.codeVulnerabilities.forEach((v) => {
      const icon =
        v.severity === "CRITICAL" ? "🔴" : v.severity === "HIGH" ? "🟠" : "🟡";
      console.log(`  ${icon} [${v.severity}] ${v.type}: ${v.description}`);
      console.log(`       ${v.file}:${v.line}`);
      console.log(
        `       Snippet: ${v.snippet.slice(0, 80)}${v.snippet.length > 80 ? "..." : ""}`,
      );
    });
  }

  sep("SUMMARY");
  console.log(`  Total issues   : ${r.summary.totalIssues}`);
  console.log(`  Critical issues: ${r.summary.criticalIssues}`);
  console.log(
    `  Result         : ${r.summary.passed ? "✅  PASSED" : "❌  FAILED"}`,
  );
  console.log("═".repeat(64) + "\n");
}

/** Streams an AI-powered security analysis from Claude */
async function runAiAnalysis(
  report: ScanReport,
  apiKey: string,
): Promise<void> {
  const client = new Anthropic({ apiKey });

  const reportSummary = JSON.stringify(
    {
      depAudit: {
        total: report.depAudit.total,
        critical: report.depAudit.critical,
        high: report.depAudit.high,
        topVulns: report.depAudit.vulnerabilities.slice(0, 5).map((v) => ({
          name: v.name,
          severity: v.severity,
          title: v.title,
        })),
      },
      envIssues: report.envIssues.map((i) => ({
        variable: i.variable,
        issue: i.issue,
        severity: i.severity,
      })),
      unguardedRoutes: report.unguardedRoutes.map((r) => ({
        method: r.httpMethod,
        path: r.routePath,
        class: r.class,
      })),
      codeVulnerabilities: report.codeVulnerabilities.map((v) => ({
        type: v.type,
        severity: v.severity,
        description: v.description,
        file: v.file,
        line: v.line,
      })),
    },
    null,
    2,
  );

  const prompt = [
    "You are a senior application security engineer conducting a security audit.",
    "Below is the raw scan output for a NestJS application.",
    "",
    "```json",
    reportSummary,
    "```",
    "",
    "Provide a comprehensive security analysis including:",
    "1. **Risk Assessment** — overall risk level and most critical findings",
    "2. **Vulnerability Breakdown** — detailed analysis of each issue category",
    "3. **Prioritised Remediation Steps** — ordered from highest to lowest impact",
    "4. **Code Examples** — concrete NestJS/Node.js fixes for the top 3 issues",
    "5. **Security Score** — a score out of 10 with justification",
    "",
    "Be specific, actionable, and include code snippets where helpful.",
  ].join("\n");

  console.log("\n🤖  Claude AI Security Analysis (streaming)…\n");
  console.log("─".repeat(64));

  let fullText = "";
  const stream = await client.messages.create({
    model: "claude-opus-4-6",
    max_tokens: 4096,
    thinking: { type: "adaptive" },
    stream: true,
    messages: [{ role: "user", content: prompt }],
  });

  for await (const event of stream) {
    if (
      event.type === "content_block_delta" &&
      event.delta.type === "text_delta"
    ) {
      const chunk = event.delta.text;
      process.stdout.write(chunk);
      fullText += chunk;
    }
  }

  console.log("\n" + "─".repeat(64));
  report.aiAnalysis = fullText;
}

async function main(): Promise<void> {
  const { projectPath, apiKey } = parseArgs(process.argv);

  console.log(`\n🛡️   CyberSentinel Scanner  (AI-powered by Claude)`);
  console.log(`📁   Scanning: ${projectPath}\n`);

  console.log("🔍  Running dependency audit…");
  const depAudit = runDepAudit(projectPath);

  console.log("🔑  Checking environment files…");
  const envIssues = checkEnvFiles(projectPath);

  console.log("🛤️   Walking controller files…");
  const unguardedRoutes = checkRouteGuards(projectPath);

  console.log("🛡️   Analyzing custom code for vulnerabilities (OWASP Top 10)…");
  const codeVulnerabilities = scanSourceCode(projectPath);

  const criticalIssues =
    depAudit.critical +
    envIssues.filter((i) => i.severity === "CRITICAL").length +
    codeVulnerabilities.filter((v) => v.severity === "CRITICAL").length;

  const totalIssues =
    depAudit.total +
    envIssues.length +
    unguardedRoutes.length +
    codeVulnerabilities.length;

  const report: ScanReport = {
    projectPath,
    timestamp: new Date().toISOString(),
    depAudit,
    envIssues,
    unguardedRoutes,
    codeVulnerabilities,
    summary: { criticalIssues, totalIssues, passed: criticalIssues === 0 },
  };

  printReport(report);

  if (apiKey) {
    await runAiAnalysis(report, apiKey);
  } else {
    console.log(
      "\n💡  Tip: set ANTHROPIC_API_KEY or pass --api-key for AI-powered analysis.\n",
    );
  }

  const outPath = path.join(projectPath, "cyber-sentinel-report.json");
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\n📄  Report saved → ${outPath}\n`);

  process.exit(criticalIssues > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("[CyberSentinel] Fatal scanner error:", err);
  process.exit(1);
});
