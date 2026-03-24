// FILE: src/decorators/threat-level.decorator.ts

import { SetMetadata } from '@nestjs/common';
import type { ThreatSeverity } from '../detection/threat-event';

export const THREAT_LEVEL_KEY = 'cyber_sentinel:threat_level';

/**
 * Override the minimum severity threshold for a specific route or controller.
 * When a detected event severity is below this level, it will be logged but
 * not trigger self-healing actions for this route.
 *
 * @example
 * @ThreatLevel('HIGH')
 * @Post('upload')
 * uploadFile() { ... }
 */
export const ThreatLevel = (level: ThreatSeverity): ClassDecorator & MethodDecorator =>
  SetMetadata(THREAT_LEVEL_KEY, level);
