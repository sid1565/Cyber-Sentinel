// FILE: src/dashboard/metrics.service.ts

import { Injectable } from "@nestjs/common";
import type { ThreatLevelLabel } from "../middleware/request-context";
import type { ThreatEvent } from "../detection/threat-event";

interface RequestMetric {
  timestamp: number;
  method: string;
  route: string;
  durationMs: number;
  threatLevel: ThreatLevelLabel;
}

export interface MetricsSummary {
  totalRequests: number;
  threatenedRequests: number;
  blockedIps: number;
  avgDurationMs: number;
  healthScore: number; // 0-100 scale
  threatBreakdown: Record<ThreatEvent["type"], number>;
  severityBreakdown: Record<ThreatEvent["severity"], number>;
}

const MAX_METRICS = 10_000;

@Injectable()
export class MetricsService {
  private readonly requests: RequestMetric[] = [];
  private readonly threatCounts = new Map<ThreatEvent["type"], number>();
  private readonly severityCounts = new Map<ThreatEvent["severity"], number>();

  recordRequest(
    method: string,
    route: string,
    durationMs: number,
    threatLevel: ThreatLevelLabel,
  ): void {
    if (this.requests.length >= MAX_METRICS) this.requests.shift();
    this.requests.push({
      timestamp: Date.now(),
      method,
      route,
      durationMs,
      threatLevel,
    });
  }

  recordThreat(event: ThreatEvent): void {
    this.threatCounts.set(
      event.type,
      (this.threatCounts.get(event.type) ?? 0) + 1,
    );
    this.severityCounts.set(
      event.severity,
      (this.severityCounts.get(event.severity) ?? 0) + 1,
    );
  }

  getSummary(blockedIpCount: number): MetricsSummary {
    const total = this.requests.length;
    const threatened = this.requests.filter(
      (r) => r.threatLevel !== "NONE",
    ).length;
    const avgDurationMs =
      total > 0
        ? this.requests.reduce((s, r) => s + r.durationMs, 0) / total
        : 0;

    return {
      totalRequests: total,
      threatenedRequests: threatened,
      blockedIps: blockedIpCount,
      avgDurationMs: Math.round(avgDurationMs * 100) / 100,
      healthScore: this.calculateHealthScore(),
      threatBreakdown: Object.fromEntries(this.threatCounts) as Record<
        ThreatEvent["type"],
        number
      >,
      severityBreakdown: Object.fromEntries(this.severityCounts) as Record<
        ThreatEvent["severity"],
        number
      >,
    };
  }

  private calculateHealthScore(): number {
    let score = 100;
    const critical = this.severityCounts.get("CRITICAL") ?? 0;
    const high = this.severityCounts.get("HIGH") ?? 0;
    const medium = this.severityCounts.get("MEDIUM") ?? 0;

    score -= critical * 5;
    score -= high * 2;
    score -= medium * 1;

    return Math.max(0, score);
  }
}
