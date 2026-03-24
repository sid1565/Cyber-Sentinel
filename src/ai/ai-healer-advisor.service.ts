// FILE: src/ai/ai-healer-advisor.service.ts

import { Injectable, Inject, OnModuleInit, Logger } from '@nestjs/common';
import Anthropic from '@anthropic-ai/sdk';
import { CYBER_SENTINEL_OPTIONS } from '../cyber-sentinel.options';
import type { CyberSentinelOptions } from '../cyber-sentinel.options';
import type { ThreatEvent } from '../detection/threat-event';

export type HealingAction = 'BLOCK_IP' | 'TIGHTEN_CORS' | 'ROTATE_SECRET' | 'MONITOR' | 'NONE';

export interface HealerAdvice {
  action: HealingAction;
  reason: string;
  blockDurationMs?: number;
}

const ADVICE_SCHEMA = {
  type: 'object' as const,
  properties: {
    action:          { type: 'string', enum: ['BLOCK_IP','TIGHTEN_CORS','ROTATE_SECRET','MONITOR','NONE'] },
    reason:          { type: 'string' },
    blockDurationMs: { type: 'number' },
  },
  required: ['action', 'reason'],
  additionalProperties: false,
};

@Injectable()
export class AiHealerAdvisorService implements OnModuleInit {
  private readonly logger = new Logger(AiHealerAdvisorService.name);
  private client?: Anthropic;
  private model = 'claude-opus-4-6';
  private enabled = false;

  constructor(
    @Inject(CYBER_SENTINEL_OPTIONS) private readonly options: CyberSentinelOptions,
  ) {}

  onModuleInit(): void {
    const ai = this.options.ai;
    if (!ai?.anthropicApiKey || ai.enabled === false) return;
    this.client  = new Anthropic({ apiKey: ai.anthropicApiKey });
    this.model   = ai.model ?? 'claude-opus-4-6';
    this.enabled = true;
  }

  get isEnabled(): boolean { return this.enabled; }

  /**
   * Asks Claude what mitigation action to apply for the given threat.
   * Falls back to rule-based advice on error.
   */
  async advise(event: ThreatEvent): Promise<HealerAdvice> {
    if (!this.enabled || !this.client) return this.ruleBased(event);

    const prompt = [
      'You are a cybersecurity incident-response expert.',
      `A ${event.severity} severity ${event.type} attack was detected.`,
      `Source IP: ${event.sourceIp}  Route: ${event.method} ${event.route}`,
      `Payload excerpt: ${event.payload ?? 'N/A'}`,
      '',
      'Choose the SINGLE best mitigation action: BLOCK_IP | TIGHTEN_CORS | ROTATE_SECRET | MONITOR | NONE',
      'For BLOCK_IP, also provide blockDurationMs (e.g. 3600000 = 1 hour).',
      'Reply ONLY with the JSON schema.',
    ].join('\n');

    try {
      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 256,
        thinking: { type: 'adaptive' },
        output_config: { format: { type: 'json_schema', schema: ADVICE_SCHEMA } },
        messages: [{ role: 'user', content: prompt }],
      });

      const textBlock = response.content.find((b) => b.type === 'text');
      if (!textBlock || textBlock.type !== 'text') return this.ruleBased(event);

      const parsed = JSON.parse(textBlock.text) as HealerAdvice;
      this.logger.debug(`AI healer advice for ${event.type}: ${parsed.action} — ${parsed.reason}`);
      return parsed;
    } catch (err) {
      this.logger.warn(`AI healer failed, using rule-based fallback: ${String(err)}`);
      return this.ruleBased(event);
    }
  }

  /** Rule-based fallback — same logic as original SelfHealerService */
  private ruleBased(event: ThreatEvent): HealerAdvice {
    switch (event.type) {
      case 'SQLI':
      case 'XSS':
      case 'PATH_TRAVERSAL':
        return { action: 'BLOCK_IP', reason: `Auto-block on ${event.type}`, blockDurationMs: 3_600_000 };
      case 'BRUTE_FORCE':
        return { action: 'BLOCK_IP', reason: 'Brute-force threshold exceeded', blockDurationMs: 1_800_000 };
      case 'ANOMALY':
        if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
          return { action: 'BLOCK_IP', reason: 'High-severity anomaly', blockDurationMs: 900_000 };
        }
        return { action: 'MONITOR', reason: 'Low-severity anomaly — monitor only' };
      default:
        return { action: 'NONE', reason: 'No automated action configured' };
    }
  }
}
