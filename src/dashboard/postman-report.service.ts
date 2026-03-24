// FILE: src/dashboard/postman-report.service.ts

import { Injectable } from "@nestjs/common";
import { AuditLogService } from "./audit-log.service";
import type { ThreatEvent } from "../detection/threat-event";

/**
 * Generates a Postman Collection JSON from the detected exploitation attempts.
 * This allows security teams to reproduce and analyze attacks in Postman.
 */
@Injectable()
export class PostmanReportService {
  constructor(private readonly auditLog: AuditLogService) {}

  generateCollection(): any {
    const events = this.auditLog.getAll();
    const collection = {
      info: {
        _postman_id: `sentinel-report-${Date.now()}`,
        name: `CyberSentinel Security Report - ${new Date().toISOString()}`,
        description: `Failed exploitation attempts detected by CyberSentinel SDK. \nTotal threats: ${events.length}`,
        schema:
          "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
      },
      item: events.map((event, index) =>
        this.mapEventToPostmanItem(event, index),
      ),
    };

    return collection;
  }

  private mapEventToPostmanItem(event: ThreatEvent, index: number): any {
    // Attempt to reconstruct original URL if possible
    const host = "{{host}}"; // Postman variable
    const url = `${host}${event.route}`;

    return {
      name: `Attempt #${index + 1}: ${event.type} [${event.severity}]`,
      request: {
        method: event.method,
        header: [
          { key: "X-CyberSentinel-Threat-ID", value: event.id, type: "text" },
          { key: "X-Source-IP", value: event.sourceIp, type: "text" },
        ],
        body: {
          mode: "raw",
          raw:
            typeof event.payload === "string"
              ? event.payload
              : JSON.stringify(event.payload, null, 2),
          options: { raw: { language: "json" } },
        },
        url: {
          raw: url,
          host: [host],
          path: event.route.split("/").filter(Boolean),
        },
        description: `Type: ${event.type}\nSeverity: ${event.severity}\nIP: ${event.sourceIp}\nMitigated: ${event.mitigated}\nAction: ${event.action ?? "None"}`,
      },
      response: [],
    };
  }
}
