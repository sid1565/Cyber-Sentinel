// FILE: src/middleware/request-context.ts

/**
 * Minimal typed request surface used across the SDK.
 * Keeps express/fastify out of mandatory dependencies.
 */
export interface SentinelRequest extends Record<string, unknown> {
  ip?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  query?: Record<string, unknown>;
  params?: Record<string, string>;
  path?: string;
}

export type ThreatLevelLabel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ThreatContext {
  blocked: boolean;
  threatLevel: ThreatLevelLabel;
  detectedThreats: string[];
  processedAt: Date;
}

const SENTINEL_CTX_KEY = '__sentinel_ctx__';

export function attachThreatContext(req: SentinelRequest, ctx: ThreatContext): void {
  req[SENTINEL_CTX_KEY] = ctx;
}

export function getThreatContext(req: SentinelRequest): ThreatContext | undefined {
  const val = req[SENTINEL_CTX_KEY];
  if (val !== null && typeof val === 'object' && 'blocked' in val) {
    return val as ThreatContext;
  }
  return undefined;
}

export function createDefaultContext(): ThreatContext {
  return {
    blocked: false,
    threatLevel: 'NONE',
    detectedThreats: [],
    processedAt: new Date(),
  };
}
