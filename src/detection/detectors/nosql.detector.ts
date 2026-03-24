// FILE: src/detection/detectors/nosql.detector.ts

import { Injectable } from "@nestjs/common";
import { Detector } from "../detector.interface";
import { SentinelRequest } from "../../middleware/request-context";
import { ThreatEvent } from "../threat-event";
import { randomUUID } from "crypto";

@Injectable()
export class NoSqlDetector implements Detector {
  private readonly nosqlPatterns = [
    // Operator injection
    /['"]?\$[a-z]+['"]?\s*:/i,
    // Script injection
    /\{\s*\$where\s*:/i,
    // Accumulator injection
    /\{\s*\$accumulator\s*:/i,
  ];

  detect(req: SentinelRequest): ThreatEvent | null {
    const payloads = [
      JSON.stringify(req.query ?? {}),
      JSON.stringify(req.body ?? {}),
      JSON.stringify(req.params ?? {}),
    ].join(" ");

    for (const pattern of this.nosqlPatterns) {
      if (pattern.test(payloads)) {
        return {
          id: randomUUID(),
          timestamp: new Date(),
          type: "ANOMALY",
          severity: "HIGH",
          sourceIp: req.ip ?? "unknown",
          route: req.url ?? "/",
          method: req.method ?? "GET",
          payload: `NoSQL Injection attempt detected: matches ${pattern.toString()}`,
          mitigated: false,
        };
      }
    }

    return null;
  }
}
