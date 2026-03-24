// FILE: src/healing/self-healer.service.ts

import { Injectable, Inject, OnModuleInit, Logger } from "@nestjs/common";
import { DetectionEngineService } from "../detection/detection-engine.service";
import { AiHealerAdvisorService } from "../ai/ai-healer-advisor.service";
import { BlockIpAction } from "./actions/block-ip.action";
import { TightenCorsAction } from "./actions/tighten-cors.action";
import { RotateSecretAction } from "./actions/rotate-secret.action";
import { CYBER_SENTINEL_OPTIONS } from "../cyber-sentinel.options";
import { NotificationService } from "../dashboard/notification.service";
import type { CyberSentinelOptions } from "../cyber-sentinel.options";
import type { ThreatEvent } from "../detection/threat-event";

/**
 * Subscribes to DetectionEngineService 'threat' events.
 * In enforce mode: asks the AI advisor what action to take, then executes it.
 * Falls back to rule-based actions if AI is unavailable.
 */
@Injectable()
export class SelfHealerService implements OnModuleInit {
  private readonly logger = new Logger(SelfHealerService.name);

  constructor(
    private readonly engine: DetectionEngineService,
    private readonly advisor: AiHealerAdvisorService,
    private readonly blockIpAction: BlockIpAction,
    private readonly tightenCorsAction: TightenCorsAction,
    private readonly rotateSecretAction: RotateSecretAction,
    private readonly notification: NotificationService,
    @Inject(CYBER_SENTINEL_OPTIONS)
    private readonly options: CyberSentinelOptions,
  ) {}

  onModuleInit(): void {
    this.engine.onThreat((event) => {
      this.handleThreat(event).catch((err) =>
        this.logger.error("[SelfHealer] action failed", err),
      );
    });
  }

  private async handleThreat(event: ThreatEvent): Promise<void> {
    if (this.options.mode !== "enforce") return;

    // Ask Claude (or rule-based fallback) for the best mitigation
    const advice = await this.advisor.advise(event);
    this.logger.debug(
      `Healer advice for ${event.type}: ${advice.action} — ${advice.reason}`,
    );

    let actionLabel: string | undefined;

    switch (advice.action) {
      case "BLOCK_IP":
        actionLabel = await this.blockIpAction.execute(
          event.sourceIp,
          event,
          advice.blockDurationMs,
        );
        break;
      case "TIGHTEN_CORS":
        actionLabel = this.tightenCorsAction.execute(event);
        break;
      case "ROTATE_SECRET":
        actionLabel = this.rotateSecretAction.execute(event);
        break;
      case "MONITOR":
        actionLabel = `Monitoring: ${advice.reason}`;
        break;
      case "NONE":
      default:
        break;
    }

    if (actionLabel) {
      event.mitigated = true;
      event.action = `${advice.action}: ${advice.reason.slice(0, 100)}`;

      // Dispatch alerts for high-severity managed threats
      await this.notification.notify(event);
    }
  }
}
