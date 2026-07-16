import { fromBase64Url, toBase64Url } from "./base64url";
import { KeyVaultClient } from "./key-vault-client";

const wrappingKeyStorageKey = "kvpp.browser.local-wrap-key";
const createDebugPhaseStorageKey = "kvpp.debug.createPhase";

export type ProtectedContentKey = {
  protectionMode: string;
  keyId: string | null;
  value: string;
};

export interface MetadataKeyProtector {
  readonly protectionMode: string;
  protectContentKey(contentKey: CryptoKey): Promise<ProtectedContentKey>;
  unprotectContentKey(protectedContentKey: ProtectedContentKey): Promise<CryptoKey>;
}

export class BrowserLocalMetadataKeyProtector implements MetadataKeyProtector {
  public readonly protectionMode = "BrowserLocalWrap";

  public async protectContentKey(contentKey: CryptoKey): Promise<ProtectedContentKey> {
    const wrappingKey = await this.getOrCreateWrappingKey();
    const wrapped = await crypto.subtle.wrapKey("raw", contentKey, wrappingKey, "AES-KW");

    return {
      protectionMode: this.protectionMode,
      keyId: null,
      value: toBase64Url(wrapped)
    };
  }

  public async unprotectContentKey(protectedContentKey: ProtectedContentKey): Promise<CryptoKey> {
    const wrappingKey = await this.getOrCreateWrappingKey();
    return crypto.subtle.unwrapKey(
      "raw",
      toPlainArrayBuffer(fromBase64Url(protectedContentKey.value)),
      wrappingKey,
      "AES-KW",
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  private async getOrCreateWrappingKey(): Promise<CryptoKey> {
    const existing = await getStoredWrappingKeyJwk();
    if (existing) {
      return crypto.subtle.importKey("jwk", existing, { name: "AES-KW" }, true, ["wrapKey", "unwrapKey"]);
    }

    const key = await crypto.subtle.generateKey({ name: "AES-KW", length: 256 }, true, ["wrapKey", "unwrapKey"]);
    const exported = await crypto.subtle.exportKey("jwk", key);
    await setStoredWrappingKeyJwk(exported);
    return key;
  }
}

export class KeyVaultMetadataKeyProtector implements MetadataKeyProtector {
  public readonly protectionMode = "KeyVaultWrap";

  public constructor(private readonly client: KeyVaultClient) {}

  public async protectContentKey(contentKey: CryptoKey): Promise<ProtectedContentKey> {
    await setCreateDebugPhase("save-record:protect-content-key:export");
    const exported = new Uint8Array(await crypto.subtle.exportKey("raw", contentKey));
    await setCreateDebugPhase("save-record:protect-content-key:wrapkey-request");
    const wrapped = await this.client.wrapKey(exported);
    await setCreateDebugPhase("save-record:protect-content-key:wrapkey-response");

    return {
      protectionMode: this.protectionMode,
      keyId: wrapped.keyId,
      value: toBase64Url(wrapped.wrappedKey)
    };
  }

  public async unprotectContentKey(protectedContentKey: ProtectedContentKey): Promise<CryptoKey> {
    if (!protectedContentKey.keyId) {
      throw new Error("Key Vault-wrapped content keys must include a metadata key identifier.");
    }

    const unwrapped = await this.client.unwrapKey(protectedContentKey.keyId, fromBase64Url(protectedContentKey.value));
    return crypto.subtle.importKey("raw", toPlainArrayBuffer(unwrapped), { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }
}

function toPlainArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}

async function getStoredWrappingKeyJwk(): Promise<JsonWebKey | null> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([wrappingKeyStorageKey], (items: Record<string, unknown>) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve((items[wrappingKeyStorageKey] as JsonWebKey | undefined) ?? null);
    });
  });
}

async function setStoredWrappingKeyJwk(value: JsonWebKey): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [wrappingKeyStorageKey]: value }, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

async function setCreateDebugPhase(phase: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [createDebugPhaseStorageKey]: phase }, () => resolve());
  });
}
