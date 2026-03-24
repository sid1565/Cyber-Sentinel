// FILE: src/decorators/skip-sentinel.decorator.ts

import { SetMetadata } from '@nestjs/common';

export const SKIP_SENTINEL_KEY = 'cyber_sentinel:skip';

/**
 * Apply to a controller class or route handler to bypass all
 * CyberSentinel checks (detection, blocking, auditing).
 *
 * @example
 * @SkipSentinel()
 * @Get('health')
 * healthCheck() { return { ok: true }; }
 */
export const SkipSentinel = (): ClassDecorator & MethodDecorator =>
  SetMetadata(SKIP_SENTINEL_KEY, true);
