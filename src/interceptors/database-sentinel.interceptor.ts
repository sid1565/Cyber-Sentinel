// FILE: src/interceptors/database-sentinel.interceptor.ts

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Inject,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";
import { DatabaseMonitorService } from "../detection/database-monitor.service";
import {
  SentinelRequest,
  getThreatContext,
} from "../middleware/request-context";
import { DetectionEngineService } from "../detection/detection-engine.service";

/**
 * Interceptor that monitors database-related methods for anomalies.
 * It can detect bulk data exports and unauthorized schema changes.
 */
@Injectable()
export class DatabaseSentinelInterceptor implements NestInterceptor {
  constructor(
    private readonly monitor: DatabaseMonitorService,
    private readonly engine: DetectionEngineService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<SentinelRequest>();
    const ip = request.ip ?? "unknown";
    const route = request.url ?? "unknown";
    const method = request.method ?? "unknown";

    return next.handle().pipe(
      tap((data) => {
        // 1. Monitor for Bulk Data Exports
        if (Array.isArray(data)) {
          const event = this.monitor.monitorQueryResult(
            ip,
            route,
            method,
            data.length,
          );
          if (event) {
            this.engine.emitThreat(event);
          }
        }
      }),
    );
  }
}
