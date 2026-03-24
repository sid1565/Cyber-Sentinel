// FILE: src/index.ts

// Module & Options
export { CyberSentinelModule } from "./cyber-sentinel.module";
export {
  CyberSentinelOptions,
  CyberSentinelAiOptions,
  CyberSentinelAsyncOptions,
  CYBER_SENTINEL_OPTIONS,
  mergeWithDefaults,
} from "./cyber-sentinel.options";

// AI & Crypto
export { AiThreatAnalyzerService } from "./ai/ai-threat-analyzer.service";
export {
  AiHealerAdvisorService,
  HealerAdvice,
  HealingAction,
} from "./ai/ai-healer-advisor.service";
export { CryptoService } from "./ai/crypto.service";

// Detection
export { DetectionEngineService } from "./detection/detection-engine.service";
export { RateLimiterService } from "./detection/rate-limiter.service";
export { DatabaseMonitorService } from "./detection/database-monitor.service";
export {
  ThreatEvent,
  ThreatType,
  ThreatSeverity,
} from "./detection/threat-event";
export { Detector } from "./detection/detector.interface";

// Detectors
export { SqliDetector } from "./detection/detectors/sqli.detector";
export { XssDetector } from "./detection/detectors/xss.detector";
export { PathTraversalDetector } from "./detection/detectors/path-traversal.detector";
export { BruteForceDetector } from "./detection/detectors/brute-force.detector";
export { AnomalyDetector } from "./detection/detectors/anomaly.detector";
export { NoSqlDetector } from "./detection/detectors/nosql.detector";

// Healing & Actions
export { PolicyStore } from "./healing/policy-store";
export { SelfHealerService } from "./healing/self-healer.service";
export { BlockIpAction } from "./healing/actions/block-ip.action";
export { TightenCorsAction } from "./healing/actions/tighten-cors.action";
export {
  RotateSecretAction,
  RotatedSecret,
} from "./healing/actions/rotate-secret.action";

// Middleware / Guards / Interceptors
export {
  SentinelMiddleware,
  SentinelResponse,
} from "./middleware/sentinel.middleware";
export { ThreatBlockGuard } from "./guards/threat-block.guard";
export { ResponseAuditInterceptor } from "./interceptors/response-audit.interceptor";
export { PiiInterceptor } from "./interceptors/pii.interceptor";
export { DatabaseSentinelInterceptor } from "./interceptors/database-sentinel.interceptor";
export {
  SentinelRequest,
  ThreatContext,
  ThreatLevelLabel,
} from "./middleware/request-context";

// Dashboard & Reporting
export { DashboardController } from "./dashboard/dashboard.controller";
export { MetricsService, MetricsSummary } from "./dashboard/metrics.service";
export { AuditLogService } from "./dashboard/audit-log.service";
export { PostmanReportService } from "./dashboard/postman-report.service";
export { NotificationService } from "./dashboard/notification.service";

// Decorators
export { PII, PII_METADATA_KEY } from "./decorators/pii.decorator";
export {
  SkipSentinel,
  SKIP_SENTINEL_KEY,
} from "./decorators/skip-sentinel.decorator";
export {
  ThreatLevel,
  THREAT_LEVEL_KEY,
} from "./decorators/threat-level.decorator";

// Scanner
export { runDepAudit, CveReport } from "./scanner/dep-audit";
export { checkEnvFiles } from "./scanner/env-check";
export { checkRouteGuards } from "./scanner/route-guard-check";
