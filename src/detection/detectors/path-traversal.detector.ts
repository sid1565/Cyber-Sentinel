// FILE: src/detection/detectors/path-traversal.detector.ts

import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { Detector } from '../detector.interface';
import type { ThreatEvent } from '../threat-event';
import type { SentinelRequest } from '../../middleware/request-context';

const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /\.\.[/\\]/,
  /\.\.[%2F%5C]/i,
  /%2e%2e[%2F%5C]/i,
  /\.\.%2f/i,
  /\.\.%5c/i,
  /%252e%252e/i,
  /\/{3,}/,
  /[/\\](etc|proc|sys|dev)[/\\]/i,
  /[/\\](passwd|shadow|hosts|sudoers|crontab)(\s|$)/i,
  /\0/,                       // null byte injection
  /\.(htaccess|htpasswd)$/i,
];

@Injectable()
export class PathTraversalDetector implements Detector {
  detect(req: SentinelRequest): ThreatEvent | null {
    const target = this.buildTarget(req);
    const matched = PATH_TRAVERSAL_PATTERNS.some((p) => p.test(target));
    if (!matched) return null;

    return {
      id: randomUUID(),
      timestamp: new Date(),
      type: 'PATH_TRAVERSAL',
      severity: 'HIGH',
      sourceIp: req.ip ?? 'unknown',
      route: req.url ?? '/',
      method: req.method ?? 'GET',
      payload: this.sanitise(target),
      mitigated: false,
    };
  }

  private buildTarget(req: SentinelRequest): string {
    const parts: string[] = [req.url ?? '', req.path ?? ''];
    if (req.params) parts.push(Object.values(req.params).join(' '));
    if (req.query) parts.push(JSON.stringify(req.query));
    return parts.join(' ');
  }

  private sanitise(raw: string): string {
    return raw.replace(/\0/g, '\\0').slice(0, 200);
  }
}
