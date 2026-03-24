// FILE: src/healing/policy-store.ts

import { Injectable, Inject, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { CYBER_SENTINEL_OPTIONS } from '../cyber-sentinel.options';
import type { CyberSentinelOptions } from '../cyber-sentinel.options';

interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', duration: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  quit(): Promise<void>;
}

/**
 * Append-only policy store for blocked IPs and CORS rules.
 * Uses in-memory Sets as primary storage; optionally syncs to Redis
 * when redisUrl is provided (requires optional peer: ioredis).
 */
@Injectable()
export class PolicyStore implements OnModuleInit, OnModuleDestroy {
  private readonly blockedIps = new Set<string>();
  private readonly allowedOrigins: Set<string>;
  private redis?: RedisLike;

  constructor(
    @Inject(CYBER_SENTINEL_OPTIONS) private readonly options: CyberSentinelOptions,
  ) {
    this.allowedOrigins = new Set(options.allowedOrigins ?? []);
  }

  async onModuleInit(): Promise<void> {
    if (this.options.redisUrl) await this.initRedis(this.options.redisUrl);
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis?.quit();
  }

  async blockIp(ip: string, ttlMs = 3_600_000): Promise<void> {
    this.blockedIps.add(ip);
    if (this.redis) {
      await this.redis.set(`sentinel:blocked:${ip}`, '1', 'EX', Math.floor(ttlMs / 1000));
    }
  }

  async isBlocked(ip: string): Promise<boolean> {
    if (this.blockedIps.has(ip)) return true;
    if (this.redis) {
      const val = await this.redis.get(`sentinel:blocked:${ip}`);
      if (val) { this.blockedIps.add(ip); return true; }
    }
    return false;
  }

  unblockIp(ip: string): void {
    this.blockedIps.delete(ip);
  }

  addAllowedOrigin(origin: string): void {
    this.allowedOrigins.add(origin);
  }

  removeAllowedOrigin(origin: string): void {
    this.allowedOrigins.delete(origin);
  }

  getAllowedOrigins(): string[] {
    return [...this.allowedOrigins];
  }

  getBlockedIps(): string[] {
    return [...this.blockedIps];
  }

  private async initRedis(url: string): Promise<void> {
    try {
      // ioredis is an optional peer — dynamic import keeps it out of the bundle
      // @ts-ignore: optional peer dependency may not be installed
      const mod = await import('ioredis') as { default: new (url: string) => RedisLike };
      this.redis = new mod.default(url);
    } catch {
      console.warn('[CyberSentinel] ioredis not found — using in-memory policy store only.');
    }
  }
}
