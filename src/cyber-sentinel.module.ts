// FILE: src/cyber-sentinel.module.ts

import {
  Module,
  Global,
  DynamicModule,
  MiddlewareConsumer,
  NestModule,
  Provider,
} from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR, Reflector } from "@nestjs/core";
import { DatabaseMonitorService } from "./detection/database-monitor.service";
import { CryptoService } from "./ai/crypto.service";
import { PiiInterceptor } from "./interceptors/pii.interceptor";
import {
  CYBER_SENTINEL_OPTIONS,
  mergeWithDefaults,
  CyberSentinelOptions,
  CyberSentinelAsyncOptions,
} from "./cyber-sentinel.options";

// AI Services
import { AiThreatAnalyzerService } from "./ai/ai-threat-analyzer.service";
import { AiHealerAdvisorService } from "./ai/ai-healer-advisor.service";

// Detection
import { DetectionEngineService } from "./detection/detection-engine.service";
import { SqliDetector } from "./detection/detectors/sqli.detector";
import { XssDetector } from "./detection/detectors/xss.detector";
import { PathTraversalDetector } from "./detection/detectors/path-traversal.detector";
import { BruteForceDetector } from "./detection/detectors/brute-force.detector";
import { AnomalyDetector } from "./detection/detectors/anomaly.detector";
import { NoSqlDetector } from "./detection/detectors/nosql.detector";
import { RateLimiterService } from "./detection/rate-limiter.service";

// Healing
import { PolicyStore } from "./healing/policy-store";
import { SelfHealerService } from "./healing/self-healer.service";
import { BlockIpAction } from "./healing/actions/block-ip.action";
import { TightenCorsAction } from "./healing/actions/tighten-cors.action";
import { RotateSecretAction } from "./healing/actions/rotate-secret.action";

// Middleware / Guards / Interceptors
import { SentinelMiddleware } from "./middleware/sentinel.middleware";
import { ThreatBlockGuard } from "./guards/threat-block.guard";
import { ResponseAuditInterceptor } from "./interceptors/response-audit.interceptor";
import { DatabaseSentinelInterceptor } from "./interceptors/database-sentinel.interceptor";

// Dashboard
import { DashboardController } from "./dashboard/dashboard.controller";
import { MetricsService } from "./dashboard/metrics.service";
import { AuditLogService } from "./dashboard/audit-log.service";
import { PostmanReportService } from "./dashboard/postman-report.service";
import { NotificationService } from "./dashboard/notification.service";

const SHARED_PROVIDERS: Provider[] = [
  Reflector,
  AiThreatAnalyzerService,
  AiHealerAdvisorService,
  DetectionEngineService,
  SqliDetector,
  XssDetector,
  PathTraversalDetector,
  BruteForceDetector,
  AnomalyDetector,
  NoSqlDetector,
  PolicyStore,
  SelfHealerService,
  BlockIpAction,
  TightenCorsAction,
  RotateSecretAction,
  MetricsService,
  AuditLogService,
  RateLimiterService,
  PostmanReportService,
  DatabaseMonitorService,
  CryptoService,
  NotificationService,
  { provide: APP_GUARD, useClass: ThreatBlockGuard },
  { provide: APP_INTERCEPTOR, useClass: ResponseAuditInterceptor },
  { provide: APP_INTERCEPTOR, useClass: PiiInterceptor },
  { provide: APP_INTERCEPTOR, useClass: DatabaseSentinelInterceptor },
];

const EXPORTS = [
  AiThreatAnalyzerService,
  AiHealerAdvisorService,
  DetectionEngineService,
  PolicyStore,
  MetricsService,
  AuditLogService,
  PostmanReportService,
  DatabaseMonitorService,
  CryptoService,
  NotificationService,
  RateLimiterService,
  RotateSecretAction,
  DatabaseSentinelInterceptor,
  NoSqlDetector,
];

@Global()
@Module({})
export class CyberSentinelModule implements NestModule {
  /** Synchronous configuration */
  static forRoot(options: CyberSentinelOptions): DynamicModule {
    const merged = mergeWithDefaults(options);
    return {
      module: CyberSentinelModule,
      providers: [
        { provide: CYBER_SENTINEL_OPTIONS, useValue: merged },
        ...SHARED_PROVIDERS,
      ],
      controllers: [DashboardController],
      exports: EXPORTS,
    };
  }

  /** Asynchronous configuration (e.g. reading from ConfigService) */
  static forRootAsync(asyncOpts: CyberSentinelAsyncOptions): DynamicModule {
    const asyncProvider: Provider = {
      provide: CYBER_SENTINEL_OPTIONS,
      useFactory: async (...args: unknown[]) => {
        const opts = await asyncOpts.useFactory(...args);
        return mergeWithDefaults(opts);
      },
      inject: asyncOpts.inject ?? [],
    };

    return {
      module: CyberSentinelModule,
      imports: (asyncOpts.imports as DynamicModule[]) ?? [],
      providers: [asyncProvider, ...SHARED_PROVIDERS],
      controllers: [DashboardController],
      exports: EXPORTS,
    };
  }

  /** Register SentinelMiddleware globally for all routes */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(SentinelMiddleware).forRoutes("*");
  }
}
