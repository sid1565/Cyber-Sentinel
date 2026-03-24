// FILE: src/cyber-sentinel.options.ts

import type { ThreatEvent } from "./detection/threat-event";
import type { InjectionToken, ModuleMetadata } from "@nestjs/common";

export interface CyberSentinelAiOptions {
  /** Your Anthropic API key — or set ANTHROPIC_API_KEY env var */
  anthropicApiKey: string;
  /** Claude model to use. Defaults to 'claude-opus-4-6' */
  model?: string;
  /** Set false to disable AI analysis (regex-only mode). Defaults to true */
  enabled?: boolean;
  /** Minimum confidence 0–1 for an AI finding to fire. Defaults to 0.7 */
  confidenceThreshold?: number;
}

export interface CyberSentinelOptions {
  mode: "monitor" | "enforce"; // monitor = log only; enforce = block + heal
  redisUrl?: string; // optional Redis for distributed policy store
  encryptionKey?: string; // 32-character key for PII encryption
  allowedOrigins?: string[]; // initial CORS whitelist
  skipSentinel?: boolean; // global bypass
  bruteForce?: {
    windowMs?: number; // default 60_000
    maxAttempts?: number; // default 20
  };
  onThreat?: (event: ThreatEvent) => void; // custom hook
  dashboard?: {
    enabled?: boolean;
    path?: string; // default '/sentinel'
    apiKeyHeader?: string; // header name for dashboard auth
    apiKey?: string;
  };
  /** Claude AI-powered threat analysis + healing advice. Optional — omit for regex-only. */
  ai?: CyberSentinelAiOptions;
}

export interface CyberSentinelAsyncOptions {
  imports?: ModuleMetadata["imports"];
  useFactory: (
    ...args: unknown[]
  ) => CyberSentinelOptions | Promise<CyberSentinelOptions>;
  inject?: InjectionToken[];
}

/** Injection token for the options object */
export const CYBER_SENTINEL_OPTIONS = "CYBER_SENTINEL_OPTIONS";

export const DEFAULT_BRUTE_FORCE: CyberSentinelOptions["bruteForce"] = {
  windowMs: 60_000,
  maxAttempts: 20,
};

export const DEFAULT_DASHBOARD: CyberSentinelOptions["dashboard"] = {
  enabled: true,
  path: "/sentinel",
};

export const DEFAULT_AI: Required<
  Omit<CyberSentinelAiOptions, "anthropicApiKey">
> = {
  model: "claude-opus-4-6",
  enabled: true,
  confidenceThreshold: 0.7,
};

export function mergeWithDefaults(
  opts: CyberSentinelOptions,
): CyberSentinelOptions {
  return {
    ...opts,
    bruteForce: { ...DEFAULT_BRUTE_FORCE, ...(opts.bruteForce ?? {}) } as any,
    dashboard: { ...DEFAULT_DASHBOARD, ...(opts.dashboard ?? {}) } as any,
    ai: opts.ai ? ({ ...DEFAULT_AI, ...opts.ai } as any) : undefined,
  };
}
