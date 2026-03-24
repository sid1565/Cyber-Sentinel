// FILE: src/detection/detectors/brute-force.detector.ts

import { Injectable, Inject, OnModuleDestroy } from "@nestjs/common";
import { randomUUID } from "crypto";
import type { Detector } from "../detector.interface";
import type { ThreatEvent } from "../threat-event";
import type { SentinelRequest } from "../../middleware/request-context";
import { CYBER_SENTINEL_OPTIONS } from "../../cyber-sentinel.options";
import type { CyberSentinelOptions } from "../../cyber-sentinel.options";

interface IpRecord {
  count: number;
  windowStart: number;
}

@Injectable()
export class BruteForceDetector implements Detector, OnModuleDestroy {
  private readonly ipMap = new Map<string, IpRecord>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(
    @Inject(CYBER_SENTINEL_OPTIONS)
    private readonly options: CyberSentinelOptions,
  ) {
    // Periodically evict expired windows to prevent memory growth
    this.cleanupTimer = setInterval(
      () => this.evictExpired(),
      options.bruteForce!.windowMs! * 2,
    );
  }

  onModuleDestroy(): void {
    clearInterval(this.cleanupTimer);
  }

  detect(req: SentinelRequest): ThreatEvent | null {
    const ip = req.ip ?? "unknown";
    const now = Date.now();
    const { windowMs, maxAttempts } = this.options.bruteForce as Required<
      Exclude<CyberSentinelOptions["bruteForce"], undefined>
    >;

    const record = this.ipMap.get(ip);
    if (!record || now - record.windowStart > windowMs!) {
      this.ipMap.set(ip, { count: 1, windowStart: now });
      return null;
    }

    record.count++;
    if (record.count <= maxAttempts!) return null;

    return {
      id: randomUUID(),
      timestamp: new Date(),
      type: "BRUTE_FORCE",
      severity: record.count > maxAttempts * 2 ? "CRITICAL" : "HIGH",
      sourceIp: ip,
      route: req.url ?? "/",
      method: req.method ?? "GET",
      payload: `${record.count} requests in ${windowMs}ms window`,
      mitigated: false,
    };
  }

  private evictExpired(): void {
    const now = Date.now();
    const cutoff = this.options.bruteForce!.windowMs! * 2;
    for (const [ip, record] of this.ipMap.entries()) {
      if (now - record.windowStart > cutoff) this.ipMap.delete(ip);
    }
  }
}
