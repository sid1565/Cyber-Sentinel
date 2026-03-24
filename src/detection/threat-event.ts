// FILE: src/detection/threat-event.ts

export interface ThreatEvent {
  id: string; // uuid v4
  timestamp: Date;
  type:
    | "SQLI"
    | "XSS"
    | "PATH_TRAVERSAL"
    | "BRUTE_FORCE"
    | "ANOMALY"
    | "RATE_LIMIT_EXCEEDED";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  sourceIp: string;
  route: string;
  method: string;
  payload?: string; // sanitised excerpt, never full body
  mitigated: boolean;
  action?: string; // what self-healer did
}

export type ThreatType = ThreatEvent["type"];
export type ThreatSeverity = ThreatEvent["severity"];
