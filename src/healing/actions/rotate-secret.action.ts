// FILE: src/healing/actions/rotate-secret.action.ts

import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';
import type { ThreatEvent } from '../../detection/threat-event';

export interface RotatedSecret {
  route: string;
  newSecret: string;
  rotatedAt: Date;
}

/**
 * Generates a cryptographically-secure replacement secret and records it.
 * In production, wire the `onRotate` callback to push the secret to your
 * secrets manager (Vault, AWS SSM, etc.).
 */
@Injectable()
export class RotateSecretAction {
  private readonly rotations: RotatedSecret[] = [];
  onRotate?: (rotated: RotatedSecret) => void;

  execute(event: ThreatEvent): string {
    const newSecret = randomBytes(32).toString('hex');
    const rotated: RotatedSecret = {
      route: event.route,
      newSecret,
      rotatedAt: new Date(),
    };

    this.rotations.push(rotated);
    this.onRotate?.(rotated);

    const msg = `Secret rotated for route ${event.route} at ${rotated.rotatedAt.toISOString()}`;
    console.warn(`[CyberSentinel][RotateSecret] ${msg}`);
    return msg;
  }

  getRotations(): Readonly<RotatedSecret[]> {
    return this.rotations;
  }
}
