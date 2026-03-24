// FILE: src/detection/detectors/xss.detector.ts

import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { Detector } from '../detector.interface';
import type { ThreatEvent } from '../threat-event';
import type { SentinelRequest } from '../../middleware/request-context';

const XSS_PATTERNS: RegExp[] = [
  /<script[\s>]/i,
  /<\/script>/i,
  /javascript\s*:/i,
  /on\w{2,20}\s*=\s*["']?[^"'>\s]/i,
  /<iframe[\s>]/i,
  /<object[\s>]/i,
  /<embed[\s>]/i,
  /expression\s*\(/i,
  /vbscript\s*:/i,
  /data:text\/html/i,
  /<img[^>]+src\s*=\s*["']?\s*javascript/i,
  /document\.(cookie|write|location)/i,
  /window\.(location|open)\s*=/i,
  /\beval\s*\(/i,
];

@Injectable()
export class XssDetector implements Detector {
  detect(req: SentinelRequest): ThreatEvent | null {
    const target = this.buildTarget(req);
    const matched = XSS_PATTERNS.some((p) => p.test(target));
    if (!matched) return null;

    return {
      id: randomUUID(),
      timestamp: new Date(),
      type: 'XSS',
      severity: 'HIGH',
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
    const referer = req.headers?.['referer'];
    if (referer) parts.push(String(referer));
    return parts.join(' ');
  }

  private sanitise(raw: string): string {
    return raw.replace(/<[^>]*>/g, '[tag]').slice(0, 200);
  }
}
