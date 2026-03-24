// FILE: src/middleware/sentinel.middleware.ts

import { Injectable, Inject, NestMiddleware } from "@nestjs/common";
import { DetectionEngineService } from "../detection/detection-engine.service";
import { AuditLogService } from "../dashboard/audit-log.service";
import { PolicyStore } from "../healing/policy-store";
import { APP_GUARD, APP_INTERCEPTOR, Reflector } from "@nestjs/core";
import { SKIP_SENTINEL_KEY } from "../decorators/skip-sentinel.decorator";
import {
  SentinelRequest,
  ThreatContext,
  ThreatLevelLabel,
  attachThreatContext,
  createDefaultContext,
} from "./request-context";
import { CYBER_SENTINEL_OPTIONS } from "../cyber-sentinel.options";
import type { CyberSentinelOptions } from "../cyber-sentinel.options";
import type { ThreatEvent } from "../detection/threat-event";

type NextFn = () => void;

const SEVERITY_ORDER: ThreatLevelLabel[] = [
  "NONE",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

@Injectable()
export class SentinelMiddleware implements NestMiddleware {
  constructor(
    private readonly engine: DetectionEngineService,
    private readonly auditLog: AuditLogService,
    private readonly policyStore: PolicyStore,
    private readonly reflector: Reflector,
    @Inject(CYBER_SENTINEL_OPTIONS)
    private readonly options: CyberSentinelOptions,
  ) {}

  async use(
    req: SentinelRequest,
    res: SentinelResponse,
    next: NextFn,
  ): Promise<void> {
    const ip = req.ip ?? "unknown";

    // 0. Skip check (Fast path for dashboard/health)
    if (this.options.skipSentinel) {
      return next();
    }

    // Try to get metadata if NestJS has attached it to the request handler
    // Note: In middleware, the handler might not be fully metadata-available
    // yet depending on when it's called.
    const handler = (req as any)._sentinelHandler;
    const controller = (req as any)._sentinelController;

    if (handler && controller) {
      const skip = this.reflector.getAllAndOverride<boolean>(
        SKIP_SENTINEL_KEY,
        [handler, controller],
      );
      if (skip) return next();
    }

    const isIpBlocked = await this.policyStore.isBlocked(ip);

    // 1. Immediate IP Block Check (Fast path)
    if (isIpBlocked) {
      if (res.status && res.json) {
        res.status!(403).json!({
          error: "Security Policy Violation",
          message:
            "Access denied: Your IP has been temporarily blocked by CyberSentinel.",
        });
        return;
      }
      return;
    }

    const ctx = createDefaultContext();
    attachThreatContext(req, ctx);

    try {
      const events = await this.engine.scan(req);
      if (events.length > 0) {
        ctx.threatLevel = this.maxSeverity(events);
        ctx.detectedThreats = events.map((e) => e.type);

        const isCritical = events.some((e) => e.severity === "CRITICAL");

        events.forEach((e) => {
          this.auditLog.append(e);
          this.options.onThreat?.(e);
        });

        // 2. Real-time Blocking
        if (isCritical && this.options.mode === "enforce") {
          if (res.status && res.json) {
            res.status!(403).json!({
              error: "Threat Detected",
              message:
                "CyberSentinel blocked this request due to detected vulnerability exploitation attempt.",
            });
            return;
          }
        }
      }
    } catch (err) {
      console.error("[CyberSentinel][Middleware] Detection error:", err);
    }

    next();
  }

  private maxSeverity(events: ThreatEvent[]): ThreatLevelLabel {
    return events.reduce<ThreatLevelLabel>((max, e) => {
      const level = e.severity as ThreatLevelLabel;
      return SEVERITY_ORDER.indexOf(level) > SEVERITY_ORDER.indexOf(max)
        ? level
        : max;
    }, "NONE");
  }
}

// Augment the NestMiddleware-compatible response shape without importing express
export interface SentinelResponse extends Record<string, unknown> {
  status?: (code: number) => SentinelResponse;
  json?: (body: unknown) => void;
  end?: () => void;
}
