// FILE: src/decorators/pii.decorator.ts

import { SetMetadata } from "@nestjs/common";

export const PII_METADATA_KEY = "cyber-sentinel:pii";

/**
 * Marks a property as containing Personally Identifiable Information (PII).
 * The CyberSentinel PiiInterceptor will automatically encrypt/decrypt this
 * field in request/response payloads.
 */
export function PII() {
  return (target: object, propertyKey: string | symbol) => {
    SetMetadata(PII_METADATA_KEY, true)(
      target,
      propertyKey,
      Object.getOwnPropertyDescriptor(target, propertyKey) || {},
    );
  };
}
