// FILE: src/interceptors/response-audit.interceptor.ts

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { MetricsService } from '../dashboard/metrics.service';
import { getThreatContext } from '../middleware/request-context';
import type { SentinelRequest } from '../middleware/request-context';

/**
 * APP_INTERCEPTOR that measures response time and records per-request
 * metrics (method, route, duration, threat level) to MetricsService.
 */
@Injectable()
export class ResponseAuditInterceptor implements NestInterceptor {
  constructor(private readonly metrics: MetricsService) {}

  intercept(ctx: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = ctx.switchToHttp().getRequest<SentinelRequest>();
    const start = Date.now();

    return next.handle().pipe(
      tap({
        next: () => this.record(req, start),
        error: () => this.record(req, start),
      }),
    );
  }

  private record(req: SentinelRequest, start: number): void {
    const durationMs = Date.now() - start;
    const threatCtx = getThreatContext(req);
    this.metrics.recordRequest(
      req.method ?? 'GET',
      req.url ?? '/',
      durationMs,
      threatCtx?.threatLevel ?? 'NONE',
    );
  }
}
