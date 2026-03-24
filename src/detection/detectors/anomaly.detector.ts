// FILE: src/detection/detectors/anomaly.detector.ts

import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { Detector } from '../detector.interface';
import type { ThreatEvent } from '../threat-event';
import type { SentinelRequest } from '../../middleware/request-context';

interface Baseline {
  avgBodySize: number;
  avgHeaderCount: number;
  requestCount: number;
}

const THRESHOLDS = {
  bodySizeMultiplier: 10,
  headerCountMultiplier: 3,
  minSamples: 10,
  maxBodySize: 1_000_000,  // 1 MB hard limit
  maxHeaderCount: 50,
};

@Injectable()
export class AnomalyDetector implements Detector {
  private baseline: Baseline = { avgBodySize: 0, avgHeaderCount: 0, requestCount: 0 };

  detect(req: SentinelRequest): ThreatEvent | null {
    const bodySize = this.getBodySize(req);
    const headerCount = Object.keys(req.headers ?? {}).length;
    const anomaly = this.score(bodySize, headerCount);

    this.updateBaseline(bodySize, headerCount);
    if (!anomaly) return null;

    return {
      id: randomUUID(),
      timestamp: new Date(),
      type: 'ANOMALY',
      severity: anomaly.score > 8 ? 'CRITICAL' : anomaly.score > 5 ? 'HIGH' : 'MEDIUM',
      sourceIp: req.ip ?? 'unknown',
      route: req.url ?? '/',
      method: req.method ?? 'GET',
      payload: anomaly.reason,
      mitigated: false,
    };
  }

  private score(bodySize: number, headerCount: number): { score: number; reason: string } | null {
    const reasons: string[] = [];
    let score = 0;

    if (bodySize > THRESHOLDS.maxBodySize) {
      score += 5;
      reasons.push(`Body oversized: ${bodySize} bytes`);
    }
    if (headerCount > THRESHOLDS.maxHeaderCount) {
      score += 3;
      reasons.push(`Excess headers: ${headerCount}`);
    }
    if (this.baseline.requestCount >= THRESHOLDS.minSamples) {
      if (this.baseline.avgBodySize > 0 &&
          bodySize > this.baseline.avgBodySize * THRESHOLDS.bodySizeMultiplier) {
        score += 4;
        reasons.push(`Body ${Math.round(bodySize / this.baseline.avgBodySize)}× baseline`);
      }
      if (this.baseline.avgHeaderCount > 0 &&
          headerCount > this.baseline.avgHeaderCount * THRESHOLDS.headerCountMultiplier) {
        score += 2;
        reasons.push(`Headers ${Math.round(headerCount / this.baseline.avgHeaderCount)}× baseline`);
      }
    }

    return score > 0 ? { score, reason: reasons.join('; ') } : null;
  }

  private getBodySize(req: SentinelRequest): number {
    if (!req.body) return 0;
    try {
      return typeof req.body === 'string' ? req.body.length : JSON.stringify(req.body).length;
    } catch {
      return 0;
    }
  }

  private updateBaseline(bodySize: number, headerCount: number): void {
    const n = this.baseline.requestCount;
    this.baseline.avgBodySize = (this.baseline.avgBodySize * n + bodySize) / (n + 1);
    this.baseline.avgHeaderCount = (this.baseline.avgHeaderCount * n + headerCount) / (n + 1);
    this.baseline.requestCount++;
  }
}
