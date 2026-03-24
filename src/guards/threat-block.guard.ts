// FILE: src/guards/threat-block.guard.ts

import { Injectable, Inject, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PolicyStore } from '../healing/policy-store';
import { CYBER_SENTINEL_OPTIONS } from '../cyber-sentinel.options';
import type { CyberSentinelOptions } from '../cyber-sentinel.options';
import { SKIP_SENTINEL_KEY } from '../decorators/skip-sentinel.decorator';
import type { SentinelRequest } from '../middleware/request-context';

/**
 * APP_GUARD that blocks requests from IPs flagged in the PolicyStore.
 * Respects @SkipSentinel() on handlers or controllers.
 * No-ops in 'monitor' mode.
 */
@Injectable()
export class ThreatBlockGuard implements CanActivate {
  constructor(
    private readonly store: PolicyStore,
    private readonly reflector: Reflector,
    @Inject(CYBER_SENTINEL_OPTIONS) private readonly options: CyberSentinelOptions,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    if (this.options.mode !== 'enforce') return true;

    const skip = this.reflector.getAllAndOverride<boolean>(SKIP_SENTINEL_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (skip) return true;

    const req = ctx.switchToHttp().getRequest<SentinelRequest>();
    const ip = req.ip ?? 'unknown';

    const blocked = await this.store.isBlocked(ip);
    if (blocked) throw new ForbiddenException('Access denied by CyberSentinel policy');

    return true;
  }
}
