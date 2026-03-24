// FILE: src/detection/detection-engine.service.ts

import { Injectable, Logger } from "@nestjs/common";
import { EventEmitter } from "events";
import type { ThreatEvent } from "./threat-event";
import type { SentinelRequest } from "../middleware/request-context";
import { SqliDetector } from "./detectors/sqli.detector";
import { XssDetector } from "./detectors/xss.detector";
import { PathTraversalDetector } from "./detectors/path-traversal.detector";
import { BruteForceDetector } from "./detectors/brute-force.detector";
import { AnomalyDetector } from "./detectors/anomaly.detector";
import { NoSqlDetector } from "./detectors/nosql.detector";
import { AiThreatAnalyzerService } from "../ai/ai-threat-analyzer.service";
import type { Detector } from "./detector.interface";
import { RateLimiterService } from "./rate-limiter.service";
import { randomUUID } from "crypto";

/**
 * Two-layer threat detection:
 *  1. Regex detectors — synchronous, used for immediate real-time blocking.
 *  2. Claude AI analyzer — async, deep analysis, emits enriched 'threat' events
 *     in the background without adding latency to the response pipeline.
 */
@Injectable()
export class DetectionEngineService extends EventEmitter {
  private readonly logger = new Logger(DetectionEngineService.name);
  private readonly detectors: Detector[];

  constructor(
    sqli: SqliDetector,
    xss: XssDetector,
    pathTraversal: PathTraversalDetector,
    bruteForce: BruteForceDetector,
    anomaly: AnomalyDetector,
    nosql: NoSqlDetector,
    private readonly rateLimiter: RateLimiterService,
    private readonly ai: AiThreatAnalyzerService,
  ) {
    super({ captureRejections: true });
    this.detectors = [sqli, xss, pathTraversal, bruteForce, anomaly, nosql];
  }

  /** Run regex scan (sync) + fire AI analysis in background. */
  async scan(req: SentinelRequest): Promise<ThreatEvent[]> {
    const settled = await Promise.all(
      this.detectors.map((d) => Promise.resolve(d.detect(req))),
    );
    let events = settled.filter((e): e is ThreatEvent => e !== null);

    // Prioritization: if we have specific high-severity threats, suppress noisy ones
    const specific = events.some((e) =>
      ["SQLI", "XSS", "PATH_TRAVERSAL"].includes(e.type),
    );
    if (specific) {
      events = events.filter(
        (e) => !["BRUTE_FORCE", "ANOMALY"].includes(e.type),
      );
    }

    // Immediate Rate Limit Check (from RateLimiterService fallback)
    if (this.rateLimiter.isLimitExceeded(req.ip ?? "unknown")) {
      events.push({
        id: randomUUID(),
        timestamp: new Date(),
        type: "RATE_LIMIT_EXCEEDED",
        severity: "HIGH",
        sourceIp: req.ip ?? "unknown",
        route: req.url ?? "/",
        method: req.method ?? "GET",
        payload: "Requests: > 100/min",
        mitigated: false,
      });
    }

    if (events.length > 0) {
      const critical = events.find((e) => e.severity === "CRITICAL");
      if (critical) {
        this.emit("threat", critical);
        this.runAiAnalysis(req); // background — never awaited
        return [critical];
      }
      events.forEach((e) => this.emit("threat", e));
    }

    // AI always runs in background for deeper intelligence on all requests
    this.runAiAnalysis(req);
    return events;
  }

  /** Fire-and-forget — Claude AI never blocks the HTTP response */
  private runAiAnalysis(req: SentinelRequest): void {
    if (!this.ai.isEnabled) return;
    this.ai
      .analyze(req)
      .then((event) => {
        if (event) {
          this.logger.debug(
            `[AI] ${event.severity} ${event.type} from ${event.sourceIp}`,
          );
          this.emit("threat:ai", event);
          this.emit("threat", event);
        }
      })
      .catch((err) => this.logger.error("[AI] analysis error", err));
  }

  /** Manually emit a threat event from runtime monitors (DB, IO). */
  emitThreat(event: ThreatEvent): void {
    this.logger.debug(
      `[Manual] ${event.severity} ${event.type} from ${event.sourceIp}`,
    );
    this.emit("threat", event);
  }

  /** Listen for threat events from both regex and AI layers */
  onThreat(listener: (event: ThreatEvent) => void): this {
    return this.on("threat", listener);
  }

  /** Listen only for AI-sourced threat events */
  onAiThreat(listener: (event: ThreatEvent) => void): this {
    return this.on("threat:ai", listener);
  }
}
