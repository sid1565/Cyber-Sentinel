// FILE: src/detection/database-monitor.service.ts

import { Injectable, Logger } from "@nestjs/common";
import { randomUUID } from "crypto";
import type { ThreatEvent } from "./threat-event";

@Injectable()
export class DatabaseMonitorService {
  private readonly logger = new Logger(DatabaseMonitorService.name);
  private readonly BULK_EXPORT_THRESHOLD = 500; // Threshold for bulk record detection

  /**
   * Monitor query results for bulk data export attempts.
   * Returns a ThreatEvent if the result set is suspiciously large.
   */
  monitorQueryResult(
    ip: string,
    route: string,
    method: string,
    rowCount: number,
  ): ThreatEvent | null {
    if (rowCount >= this.BULK_EXPORT_THRESHOLD) {
      this.logger.warn(
        `Suspiciously large data export detected: ${rowCount} rows from ${ip} on ${route}`,
      );

      return {
        id: randomUUID(),
        timestamp: new Date(),
        type: "ANOMALY",
        severity: rowCount > 2000 ? "CRITICAL" : "HIGH",
        sourceIp: ip,
        route,
        method,
        payload: `Bulk data export attempt: ${rowCount} records requested.`,
        mitigated: false,
      };
    }
    return null;
  }

  /**
   * Detect potential unauthorized schema changes (SQL/NoSQL) or operator injection.
   */
  monitorSchemaChange(ip: string, query: string): ThreatEvent | null {
    const ddlKeywords = [
      "DROP",
      "TRUNCATE",
      "ALTER",
      "CREATE",
      "RENAME",
      "$WHERE",
      "$EXPR",
      "$ACCUMULATOR",
    ];
    const matched = ddlKeywords.find((kw) => query.toUpperCase().includes(kw));

    if (matched) {
      return {
        id: randomUUID(),
        timestamp: new Date(),
        type: matched.startsWith("$") ? "ANOMALY" : "SQLI",
        severity: "CRITICAL",
        sourceIp: ip,
        route: "DATABASE_LEVEL",
        method: "RAW_QUERY",
        payload: `Unauthorized query modification attempt: ${matched} detected in raw database query.`,
        mitigated: false,
      };
    }
    return null;
  }
}
