// FILE: src/ai/ai-threat-analyzer.service.ts

import { Injectable, Inject, OnModuleInit, Logger } from '@nestjs/common';
import Anthropic from '@anthropic-ai/sdk';
import { randomUUID } from 'crypto';
import { CYBER_SENTINEL_OPTIONS } from '../cyber-sentinel.options';
import type { CyberSentinelOptions } from '../cyber-sentinel.options';
import type { ThreatEvent } from '../detection/threat-event';
import type { SentinelRequest } from '../middleware/request-context';

/** Shape Claude must return — kept flat so additionalProperties: false is satisfied */
interface AiAnalysisResult {
  is_threat: boolean;
  threat_type: string;
  severity: string;
  confidence: number;
  reasoning: string;
  sanitized_payload: string;
}

const OUTPUT_SCHEMA = {
  type: 'object' as const,
  properties: {
    is_threat:         { type: 'boolean' },
    threat_type:       { type: 'string', enum: ['SQLI','XSS','PATH_TRAVERSAL','BRUTE_FORCE','ANOMALY','NONE'] },
    severity:          { type: 'string', enum: ['LOW','MEDIUM','HIGH','CRITICAL','NONE'] },
    confidence:        { type: 'number' },
    reasoning:         { type: 'string' },
    sanitized_payload: { type: 'string' },
  },
  required: ['is_threat','threat_type','severity','confidence','reasoning','sanitized_payload'],
  additionalProperties: false,
};

@Injectable()
export class AiThreatAnalyzerService implements OnModuleInit {
  private readonly logger = new Logger(AiThreatAnalyzerService.name);
  private client?: Anthropic;
  private model = 'claude-opus-4-6';
  private threshold = 0.7;
  private enabled = false;

  constructor(
    @Inject(CYBER_SENTINEL_OPTIONS) private readonly options: CyberSentinelOptions,
  ) {}

  onModuleInit(): void {
    const ai = this.options.ai;
    if (!ai?.anthropicApiKey || ai.enabled === false) return;
    this.client  = new Anthropic({ apiKey: ai.anthropicApiKey });
    this.model     = ai.model ?? 'claude-opus-4-6';
    this.threshold = ai.confidenceThreshold ?? 0.7;
    this.enabled   = true;
    this.logger.log(`AI threat analysis enabled (model: ${this.model}, threshold: ${this.threshold})`);
  }

  get isEnabled(): boolean { return this.enabled; }

  /**
   * Asks Claude to analyse the request for threats.
   * Returns a ThreatEvent when confidence ≥ threshold, otherwise null.
   * Never throws — logs errors and returns null on failure.
   */
  async analyze(req: SentinelRequest): Promise<ThreatEvent | null> {
    if (!this.enabled || !this.client) return null;

    const prompt = this.buildPrompt(req);
    try {
      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 512,
        thinking: { type: 'adaptive' },
        output_config: { format: { type: 'json_schema', schema: OUTPUT_SCHEMA } },
        messages: [{ role: 'user', content: prompt }],
      });

      const textBlock = response.content.find((b) => b.type === 'text');
      if (!textBlock || textBlock.type !== 'text') return null;

      const parsed = JSON.parse(textBlock.text) as AiAnalysisResult;
      if (!parsed.is_threat || parsed.confidence < this.threshold) return null;
      if (parsed.threat_type === 'NONE' || parsed.severity === 'NONE') return null;

      return this.toThreatEvent(parsed, req);
    } catch (err) {
      this.logger.warn(`AI analysis failed (will fallback to regex): ${String(err)}`);
      return null;
    }
  }

  private buildPrompt(req: SentinelRequest): string {
    const headers  = JSON.stringify(this.safeHeaders(req.headers ?? {}));
    const query    = JSON.stringify(req.query ?? {});
    const body     = this.bodyExcerpt(req.body);
    return [
      'You are a cybersecurity expert. Analyze this HTTP request for security threats.',
      '',
      `Method: ${req.method ?? 'GET'}`,
      `URL: ${req.url ?? '/'}`,
      `Source IP: ${req.ip ?? 'unknown'}`,
      `Headers: ${headers}`,
      `Query: ${query}`,
      `Body excerpt: ${body}`,
      '',
      'Check for: SQL injection, XSS, path traversal, brute force, anomalous patterns.',
      'Reply ONLY with the JSON schema. Set is_threat=false if the request is benign.',
    ].join('\n');
  }

  private toThreatEvent(r: AiAnalysisResult, req: SentinelRequest): ThreatEvent {
    return {
      id: randomUUID(),
      timestamp: new Date(),
      type: r.threat_type as ThreatEvent['type'],
      severity: r.severity as ThreatEvent['severity'],
      sourceIp: req.ip ?? 'unknown',
      route: req.url ?? '/',
      method: req.method ?? 'GET',
      payload: r.sanitized_payload.slice(0, 200),
      mitigated: false,
      action: `AI analysis (confidence: ${(r.confidence * 100).toFixed(0)}%) — ${r.reasoning.slice(0, 120)}`,
    };
  }

  private safeHeaders(h: Record<string, string | string[] | undefined>): Record<string, string> {
    const safe: Record<string, string> = {};
    const skip = new Set(['authorization', 'cookie', 'x-api-key']);
    for (const [k, v] of Object.entries(h)) {
      if (!skip.has(k.toLowerCase()) && v !== undefined) {
        safe[k] = Array.isArray(v) ? v.join(', ') : v;
      }
    }
    return safe;
  }

  private bodyExcerpt(body: unknown): string {
    if (!body) return '';
    const raw = typeof body === 'string' ? body : JSON.stringify(body);
    return raw.slice(0, 500);
  }
}
