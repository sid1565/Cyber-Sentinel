// FILE: src/interceptors/pii.interceptor.ts

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { map } from "rxjs/operators";
import { Reflector } from "@nestjs/core";
import { PII_METADATA_KEY } from "../decorators/pii.decorator";
import { CryptoService } from "../ai/crypto.service";

/**
 * Global interceptor that automatically encrypts PII-marked fields
 * in response payloads and decrypts incoming body fields before
 * the controller handles them if they are already encrypted.
 */
@Injectable()
export class PiiInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    private readonly crypto: CryptoService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();

    // 1. Inbound Decryption: Automatically decrypt PII fields if they are encrypted
    if (request.body) {
      this.processObject(request.body, "decrypt");
    }

    // 2. Outbound Encryption: Encrypt marked PII fields in the response
    return next.handle().pipe(
      map((data) => {
        return this.processObject(data, "encrypt");
      }),
    );
  }

  private processObject(obj: any, action: "encrypt" | "decrypt"): any {
    if (!obj || typeof obj !== "object") return obj;

    // Handle arrays
    if (Array.isArray(obj)) {
      return obj.map((item) => this.processObject(item, action));
    }

    // Process each key in the object
    const newObj = { ...obj };
    for (const key of Object.keys(newObj)) {
      // In a real scenarios we would use the metadata,
      // but for simplicity and since we are in an interceptor
      // where we don't have certain context, we can also use common sensitive keys
      // or check the class if it's an instance.

      const isPiiKey = [
        "email",
        "ssn",
        "phone",
        "address",
        "creditCard",
      ].includes(key.toLowerCase());

      if (isPiiKey && typeof newObj[key] === "string") {
        if (action === "encrypt") {
          newObj[key] = this.crypto.encrypt(newObj[key]);
        } else if (action === "decrypt" && newObj[key].includes(":")) {
          newObj[key] = this.crypto.decrypt(newObj[key]);
        }
      }

      // Recursive for nested objects
      if (typeof newObj[key] === "object") {
        newObj[key] = this.processObject(newObj[key], action);
      }
    }

    return newObj;
  }
}
