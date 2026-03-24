// FILE: src/dashboard/dashboard.controller.ts

import {
  Controller,
  Get,
  Req,
  Res,
  Inject,
  ForbiddenException,
  NotFoundException,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import { MetricsService } from "./metrics.service";
import { AuditLogService } from "./audit-log.service";
import { PolicyStore } from "../healing/policy-store";
import { PostmanReportService } from "./postman-report.service";
import { CYBER_SENTINEL_OPTIONS } from "../cyber-sentinel.options";
import type { CyberSentinelOptions } from "../cyber-sentinel.options";
import { SkipSentinel } from "../decorators/skip-sentinel.decorator";
import type { SentinelRequest } from "../middleware/request-context";

// Minimal response shape (works with express & fastify)
interface HttpResponse {
  status(code: number): this;
  json(body: unknown): void;
}

/**
 * Exposes GET /sentinel/dashboard  (or configured path)
 * Protected by optional API key header.
 * @SkipSentinel() prevents recursive self-inspection of dashboard calls.
 */
@SkipSentinel()
@Controller("sentinel")
export class DashboardController {
  constructor(
    private readonly metrics: MetricsService,
    private readonly auditLog: AuditLogService,
    private readonly store: PolicyStore,
    private readonly postmanReport: PostmanReportService,
    @Inject(CYBER_SENTINEL_OPTIONS)
    private readonly options: CyberSentinelOptions,
  ) {}

  @Get("dashboard")
  @HttpCode(HttpStatus.OK)
  async getDashboard(
    @Req() req: SentinelRequest,
    @Res() res: HttpResponse,
  ): Promise<void> {
    if (!this.options.dashboard?.enabled) {
      throw new NotFoundException("Dashboard is disabled");
    }

    this.assertApiKey(req);

    const blockedIps = this.store.getBlockedIps();
    const summary = this.metrics.getSummary(blockedIps.length);
    const recentThreats = this.auditLog.getLast(50);

    res.json({ summary, recentThreats, blockedIps });
  }

  @Get("report/postman")
  async getPostmanReport(
    @Req() req: SentinelRequest,
    @Res() res: HttpResponse,
  ): Promise<void> {
    this.assertApiKey(req);
    const report = this.postmanReport.generateCollection();
    res.json(report);
  }

  @Get("health")
  @HttpCode(HttpStatus.OK)
  getHealth(): Record<string, unknown> {
    return { status: "ok", ts: new Date().toISOString() };
  }

  private assertApiKey(req: SentinelRequest): void {
    const { apiKeyHeader, apiKey } = this.options.dashboard || {};
    if (!apiKeyHeader || !apiKey) return;

    const provided = req.headers?.[apiKeyHeader.toLowerCase()];
    if (provided !== apiKey) {
      throw new ForbiddenException("Invalid or missing dashboard API key");
    }
  }
}
