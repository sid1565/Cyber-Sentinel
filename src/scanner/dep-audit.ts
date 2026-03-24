// FILE: src/scanner/dep-audit.ts

import { execSync } from 'child_process';

export interface VulnerabilityInfo {
  name: string;
  severity: string;
  title: string;
  url: string;
  range: string;
  fixAvailable: boolean | string;
}

export interface CveReport {
  total: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
  info: number;
  vulnerabilities: VulnerabilityInfo[];
}

interface ViaEntry {
  title?: string;
  url?: string;
  severity?: string;
}

interface NpmVuln {
  severity: string;
  via?: Array<ViaEntry | string>;
  range?: string;
  fixAvailable?: boolean | string;
}

interface NpmAuditJson {
  vulnerabilities?: Record<string, NpmVuln>;
}

export function runDepAudit(projectPath: string): CveReport {
  let raw: string;
  try {
    raw = execSync('npm audit --json', {
      cwd: projectPath,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err: unknown) {
    // npm audit exits 1 when vulnerabilities are found — stdout still has the JSON
    raw = (err as { stdout?: string }).stdout ?? '{}';
  }

  let audit: NpmAuditJson;
  try {
    audit = JSON.parse(raw) as NpmAuditJson;
  } catch {
    return { total: 0, critical: 0, high: 0, moderate: 0, low: 0, info: 0, vulnerabilities: [] };
  }

  const vulnMap = audit.vulnerabilities ?? {};
  const vulns: VulnerabilityInfo[] = Object.entries(vulnMap).map(([name, v]) => {
    const firstVia = v.via?.[0];
    const viaObj = typeof firstVia === 'object' ? firstVia : undefined;
    return {
      name,
      severity: v.severity,
      title: viaObj?.title ?? name,
      url: viaObj?.url ?? '',
      range: v.range ?? '*',
      fixAvailable: v.fixAvailable ?? false,
    };
  });

  const counts = vulns.reduce(
    (acc, v) => {
      if (v.severity === 'critical') acc.critical++;
      else if (v.severity === 'high') acc.high++;
      else if (v.severity === 'moderate') acc.moderate++;
      else if (v.severity === 'low') acc.low++;
      else acc.info++;
      return acc;
    },
    { critical: 0, high: 0, moderate: 0, low: 0, info: 0 },
  );

  return { total: vulns.length, ...counts, vulnerabilities: vulns };
}
