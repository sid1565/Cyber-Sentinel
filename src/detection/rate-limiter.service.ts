// FILE: src/detection/rate-limiter.service.ts

import { Injectable } from "@nestjs/common";

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

@Injectable()
export class RateLimiterService {
  private readonly clients = new Map<
    string,
    { count: number; expiresAt: number }
  >();
  private readonly config: RateLimitConfig = {
    windowMs: 60 * 1000, // 1 minute window
    maxRequests: 100, // 100 requests per minute
  };

  /** returns true if rate limit is exceeded */
  isLimitExceeded(ip: string): boolean {
    const now = Date.now();
    const entry = this.clients.get(ip);

    if (!entry || entry.expiresAt < now) {
      this.clients.set(ip, { count: 1, expiresAt: now + this.config.windowMs });
      return false;
    }

    entry.count++;
    if (entry.count > this.config.maxRequests) {
      return true;
    }

    return false;
  }

  getRemaining(ip: string): number {
    const entry = this.clients.get(ip);
    if (!entry || entry.expiresAt < Date.now()) return this.config.maxRequests;
    return Math.max(0, this.config.maxRequests - entry.count);
  }
}
