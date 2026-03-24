// FILE: src/scanner/env-check.ts

import * as fs from 'fs';
import * as path from 'path';

export interface EnvIssue {
  file: string;
  variable: string;
  issue: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

const WEAK_VALUES = new Set([
  'secret', 'password', 'changeme', 'example', 'default', '12345678', 'qwerty',
  'letmein', 'admin', 'test', 'dev', '123456', 'password123', 'abc123',
  'fake-secret', 'your-secret-here', 'replace-me', 'todo', 'fixme',
]);

const RE_SECRET_VAR = /^(?:.*[-_])?(?:SECRET|KEY|PASSWORD|PASS|PWD|TOKEN|PRIVATE|AUTH|CREDENTIAL)(?:[-_].*)?$/i;
const ENV_FILE_NAMES = ['.env', '.env.local', '.env.development', '.env.production', '.env.staging', '.env.example'];
const MIN_SECRET_LENGTH = 16;

export function checkEnvFiles(projectPath: string): EnvIssue[] {
  const issues: EnvIssue[] = [];

  for (const fileName of ENV_FILE_NAMES) {
    const filePath = path.join(projectPath, fileName);
    if (!fs.existsSync(filePath)) continue;

    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      continue;
    }

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;

      const varName = trimmed.slice(0, eqIdx).trim();
      if (!RE_SECRET_VAR.test(varName)) continue;

      const rawValue = trimmed.slice(eqIdx + 1).trim();
      const value = rawValue.replace(/^["']|["']$/g, '');

      if (!value) {
        issues.push({ file: filePath, variable: varName, issue: 'Empty secret value', severity: 'HIGH' });
        continue;
      }
      if (WEAK_VALUES.has(value.toLowerCase())) {
        issues.push({ file: filePath, variable: varName, issue: `Weak/default secret: "${value}"`, severity: 'CRITICAL' });
        continue;
      }
      if (value.length < MIN_SECRET_LENGTH) {
        issues.push({
          file: filePath,
          variable: varName,
          issue: `Secret too short (${value.length} chars; minimum ${MIN_SECRET_LENGTH})`,
          severity: 'MEDIUM',
        });
      }
    }
  }

  return issues;
}
