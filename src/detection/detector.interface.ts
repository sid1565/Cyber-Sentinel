// FILE: src/detection/detector.interface.ts

import type { ThreatEvent } from './threat-event';
import type { SentinelRequest } from '../middleware/request-context';

/**
 * Contract every detector must satisfy.
 * detect() is synchronous so detectors stay side-effect-free.
 * The engine wraps each call in Promise.resolve() for parallel execution.
 */
export interface Detector {
  detect(req: SentinelRequest): ThreatEvent | null;
}
