// FILE: src/healing/actions/tighten-cors.action.ts

import { Injectable } from '@nestjs/common';
import { PolicyStore } from '../policy-store';
import type { ThreatEvent } from '../../detection/threat-event';

const PERMISSIVE_ORIGINS = new Set(['*', 'null']);

/**
 * Removes wildcard / permissive CORS origins from the policy store
 * when a brute-force or anomaly threat is detected.
 */
@Injectable()
export class TightenCorsAction {
  constructor(private readonly store: PolicyStore) {}

  execute(event: ThreatEvent): string {
    const origins = this.store.getAllowedOrigins();
    const removed: string[] = [];

    for (const origin of origins) {
      if (PERMISSIVE_ORIGINS.has(origin)) {
        this.store.removeAllowedOrigin(origin);
        removed.push(origin);
      }
    }

    const msg = removed.length > 0
      ? `Removed permissive CORS origins: ${removed.join(', ')} (triggered by ${event.type})`
      : `No permissive CORS origins to remove (${event.type})`;

    console.warn(`[CyberSentinel][TightenCors] ${msg}`);
    return msg;
  }
}
