// FILE: src/dashboard/notification.service.ts

import { Injectable, Logger } from "@nestjs/common";
import type { ThreatEvent } from "../detection/threat-event";

@Injectable()
export class NotificationService {
  private readonly logger = new Logger(NotificationService.name);

  /**
   * Dispatches a high-priority alert for critical threats.
   * In a real implementation, this would call Slack Webhooks or SendGrid API.
   */
  async notify(event: ThreatEvent): Promise<void> {
    if (event.severity === "CRITICAL" || event.severity === "HIGH") {
      await this.sendSlackAlert(event);
      await this.sendEmailAlert(event);
    }
  }

  private async sendSlackAlert(event: ThreatEvent): Promise<void> {
    const message = {
      text: `🚨 *CyberSentinel Alert: Critical Threat Detected*`,
      attachments: [
        {
          color: event.severity === "CRITICAL" ? "#ff0000" : "#ffa500",
          title: `Type: ${event.type}`,
          text: `Route: ${event.route}\nIP: ${event.sourceIp}\nAction: ${event.action ?? "Pending Review"}\nTimestamp: ${event.timestamp.toISOString()}`,
          footer: "CyberSentinel Real-time Monitoring",
        },
      ],
    };

    // Actual Slack Webhook call would go here
    this.logger.warn(
      `[Notification][Slack] ${JSON.stringify(message.text)} - ${event.type} from ${event.sourceIp}`,
    );
  }

  private async sendEmailAlert(event: ThreatEvent): Promise<void> {
    const subject = `[CyberSentinel] ${event.severity} Severity Threat Detected: ${event.type}`;
    const body = `
      CyberSentinel has detected a potential security incident.
      ---------------------------------------------------------
      Event Type: ${event.type}
      Severity: ${event.severity}
      Source IP: ${event.sourceIp}
      Impacted Route: ${event.route}
      Action Taken: ${event.action ?? "None - Manual investigation required"}
      Timestamp: ${event.timestamp.toISOString()}
    `;

    // Actual Email Service (SMTP/SendGrid) call would go here
    this.logger.warn(`[Notification][Email] ${subject}`);
  }
}
