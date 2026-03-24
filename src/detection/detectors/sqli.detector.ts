// FILE: src/detection/detectors/sqli.detector.ts

import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { Detector } from '../detector.interface';
import type { ThreatEvent } from '../threat-event';
import type { SentinelRequest } from '../../middleware/request-context';

const SQLI_PATTERNS: RegExp[] = [
  /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE|CAST|CONVERT)\b/i,
  /('|--|;|\/\*|\*\/|xp_)/,
  /\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d/i,
  /\bUNION\b.{0,40}\bSELECT\b/i,
  /\b(DROP|DELETE)\b.{0,20}\bTABLE\b/i,
  /\bINSERT\b.{0,20}\bINTO\b/i,
  /\bSLEEP\s*\(\s*\d+\s*\)/i,
  /\bWAITFOR\b.{0,20}\bDELAY\b/i,
  /\bBENCHMARK\s*\(/i,
];

@Injectable()
export class SqliDetector implements Detector {
  detect(req: SentinelRequest): ThreatEvent | null {
    const target = this.buildTarget(req);
    const matched = SQLI_PATTERNS.some((p) => p.test(target));
    if (!matched) return null;

    return {
      id: randomUUID(),
      timestamp: new Date(),
      type: 'SQLI',
      severity: 'CRITICAL',
      sourceIp: req.ip ?? 'unknown',
      route: req.url ?? '/',
      method: req.method ?? 'GET',
      payload: this.sanitise(target),
      mitigated: false,
    };
  }

  private buildTarget(req: SentinelRequest): string {
    const parts: string[] = [req.url ?? ''];
    if (req.query) parts.push(JSON.stringify(req.query));
    if (req.body !== undefined && req.body !== null) {
      parts.push(typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
    }
    return parts.join(' ');
  }

  private sanitise(raw: string): string {
    return raw.replace(/<[^>]*>/g, '[tag]').slice(0, 200);
  }
}
