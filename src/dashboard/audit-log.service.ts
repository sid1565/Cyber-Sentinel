// FILE: src/dashboard/audit-log.service.ts

import { Injectable } from '@nestjs/common';
import type { ThreatEvent } from '../detection/threat-event';

const DEFAULT_CAPACITY = 1_000;

/**
 * Append-only circular buffer for ThreatEvents.
 * Oldest entries are overwritten once capacity is reached —
 * memory footprint is bounded and predictable.
 */
@Injectable()
export class AuditLogService {
  private readonly capacity = DEFAULT_CAPACITY;
  private readonly buffer: (ThreatEvent | undefined)[];
  private head = 0;   // next write index
  private size = 0;   // number of valid entries (≤ capacity)

  constructor() {
    this.buffer = new Array<ThreatEvent | undefined>(this.capacity).fill(undefined);
  }

  append(event: ThreatEvent): void {
    this.buffer[this.head] = event;
    this.head = (this.head + 1) % this.capacity;
    if (this.size < this.capacity) this.size++;
  }

  /** Returns all stored events in chronological order (oldest first). */
  getAll(): ThreatEvent[] {
    if (this.size === 0) return [];

    if (this.size < this.capacity) {
      return this.buffer.slice(0, this.size) as ThreatEvent[];
    }
    // Buffer is full: oldest entry starts at current head
    return [
      ...this.buffer.slice(this.head),
      ...this.buffer.slice(0, this.head),
    ] as ThreatEvent[];
  }

  /** Returns the last `n` events (most recent). */
  getLast(n: number): ThreatEvent[] {
    return this.getAll().slice(-Math.abs(n));
  }

  clear(): void {
    this.buffer.fill(undefined);
    this.head = 0;
    this.size = 0;
  }

  get count(): number {
    return this.size;
  }
}
