// FILE: src/healing/actions/block-ip.action.ts

import { Injectable } from '@nestjs/common';
import { PolicyStore } from '../policy-store';
import type { ThreatEvent } from '../../detection/threat-event';

const BLOCK_TTL_BY_SEVERITY: Record<ThreatEvent['severity'], number> = {
  LOW: 5 * 60_000,       // 5 min
  MEDIUM: 30 * 60_000,   // 30 min
  HIGH: 2 * 3_600_000,   // 2 h
  CRITICAL: 24 * 3_600_000, // 24 h
};

@Injectable()
export class BlockIpAction {
  constructor(private readonly store: PolicyStore) {}

  /** AI advisor may supply an explicit durationMs; falls back to severity-based TTL */
  async execute(ip: string, event: ThreatEvent, durationMs?: number): Promise<string> {
    const ttl = durationMs ?? BLOCK_TTL_BY_SEVERITY[event.severity];
    await this.store.blockIp(ip, ttl);
    const msg = `Blocked IP ${ip} for ${ttl / 60_000} min (${event.severity})`;
    console.warn(`[CyberSentinel][BlockIp] ${msg}`);
    return msg;
  }
}
