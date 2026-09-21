import { fromBase64Url, toBase64Url } from "./base64url";
import { getCachedMetadataSummary, loadEnvelopesFromCache, replaceEnvelopesCache, saveEnvelopeToCache } from "./metadata-cache-store";
import { parseStoredCredentialRecord } from "./credential-lifecycle";
import { KeyVaultClient, type AccessTokenProvider } from "./key-vault-client";
import { KeyVaultSecretMetadataTransport } from "./key-vault-metadata-transport";
import { BrowserLocalMetadataKeyProtector, KeyVaultMetadataKeyProtector, type MetadataKeyProtector } from "./metadata-key-protector";
import type { BrowserCredentialEnvelope, BrowserStoredCredentialRecord, MetadataSummary } from "./models";
import type { BrowserExtensionConfig } from "./protocol";

const createDebugPhaseStorageKey = "kvpp.debug.createPhase";

export type BrowserMetadataEnvironment = {
  keyProtector: MetadataKeyProtector;
  transport: KeyVaultSecretMetadataTransport | null;
  keyVaultClient: KeyVaultClient | null;
};

export function createMetadataEnvironment(config: BrowserExtensionConfig, tokenProvider: AccessTokenProvider): BrowserMetadataEnvironment {
  if (config.metadataTransportMode === "LocalCacheOnly") {
    return {
      keyProtector: new BrowserLocalMetadataKeyProtector(),
      transport: null,
      keyVaultClient: null
    };
  }

  ensureKeyVaultMetadataConfig(config);

  const client = new KeyVaultClient(
    {
      baseUrl: config.keyVaultBaseUrl,
      signingKeyName: config.signingKeyName,
      metadataWrappingKeyName: config.metadataWrappingKeyName
    },
    tokenProvider
  );

  return {
    keyProtector: new KeyVaultMetadataKeyProtector(client),
    transport: new KeyVaultSecretMetadataTransport(client, config.metadataSecretPrefix),
    keyVaultClient: client
  };
}

export async function saveCredentialRecord(record: BrowserStoredCredentialRecord, environment: BrowserMetadataEnvironment): Promise<void> {
  const contentKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  await setCreateDebugPhase("save-record:protect-content-key");
  const protectedContentKey = await environment.keyProtector.protectContentKey(contentKey);
  const plaintext = new TextEncoder().encode(JSON.stringify(record));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const envelopeTemplate: BrowserCredentialEnvelope = {
    version: "2",
    recordId: record.recordId,
    contentKeyProtection: protectedContentKey.protectionMode,
    updatedAt: record.updatedAt,
    ciphertext: "",
    protectedContentKey: protectedContentKey.value,
    metadataKeyId: protectedContentKey.keyId,
    nonce: toBase64Url(nonce),
    tag: "",
    lifecycleState: record.state
  };

  const ciphertextWithTag = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: toPlainArrayBuffer(buildAssociatedData(envelopeTemplate)),
      tagLength: 128
    },
    contentKey,
    plaintext
  ));

  const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);
  const tag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);

  const envelope: BrowserCredentialEnvelope = {
    ...envelopeTemplate,
    ciphertext: toBase64Url(ciphertext),
    tag: toBase64Url(tag)
  };

  if (environment.transport) {
    await setCreateDebugPhase("save-record:save-transport");
    await environment.transport.saveEnvelope(envelope);
    try {
      await setCreateDebugPhase("save-record:save-cache");
      await saveEnvelopeToCache(record.recordId, envelope);
    } catch {
      // The authenticated remote store is authoritative. A disposable cache
      // failure must not turn a committed remote write into a failed ceremony.
    }
    return;
  }

  await setCreateDebugPhase("save-record:save-cache");
  await saveEnvelopeToCache(record.recordId, envelope);
}

export async function loadCredentialRecords(environment: BrowserMetadataEnvironment): Promise<BrowserStoredCredentialRecord[]> {
  const envelopes = await loadEnvelopes(environment);

  if (envelopes.length === 0) {
    return [];
  }

  const results: BrowserStoredCredentialRecord[] = [];

  for (const envelope of envelopes) {
    const contentKey = await environment.keyProtector.unprotectContentKey({
      protectionMode: envelope.contentKeyProtection,
      keyId: envelope.metadataKeyId,
      value: envelope.protectedContentKey
    });

    const ciphertext = fromBase64Url(envelope.ciphertext);
    const tag = fromBase64Url(envelope.tag);
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);

    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toPlainArrayBuffer(fromBase64Url(envelope.nonce)),
        additionalData: toPlainArrayBuffer(buildAssociatedData({ ...envelope, ciphertext: "", tag: "" })),
        tagLength: 128
      },
      contentKey,
      combined
    );

    const record = parseStoredCredentialRecord(JSON.parse(new TextDecoder().decode(plaintext)));
    if (record.recordId !== envelope.recordId) {
      throw new Error("Stored credential envelope and payload record IDs do not match.");
    }
    if (envelope.version === "2" && record.state !== envelope.lifecycleState) {
      throw new Error("Stored credential envelope and payload lifecycle states do not match.");
    }

    results.push(record);
  }

  return results;
}

export async function getMetadataSummary(environment: BrowserMetadataEnvironment): Promise<MetadataSummary> {
  if (!environment.transport) {
    return getCachedMetadataSummary();
  }

  const envelopes = await loadEnvelopes(environment);
  return buildMetadataSummary(envelopes);
}

function buildAssociatedData(envelope: BrowserCredentialEnvelope): Uint8Array {
  if (envelope.version !== "1" && envelope.version !== "2") {
    throw new Error("Stored credential envelope version is unsupported.");
  }

  const unixSeconds = Math.floor(new Date(envelope.updatedAt).getTime() / 1000);
  const aadFields = [
    envelope.version,
    envelope.recordId,
    envelope.contentKeyProtection,
    unixSeconds.toString(),
    envelope.metadataKeyId ?? ""
  ];
  if (envelope.version === "2") {
    if (!envelope.lifecycleState) {
      throw new Error("Stored credential envelope lifecycle state is missing.");
    }
    aadFields.push(envelope.lifecycleState);
  }

  const aadString = aadFields.join("|");

  return new TextEncoder().encode(aadString);
}

async function loadEnvelopes(environment: BrowserMetadataEnvironment): Promise<BrowserCredentialEnvelope[]> {
  if (!environment.transport) {
    return loadEnvelopesFromCache();
  }

  const remoteEnvelopes = await environment.transport.loadAllEnvelopes();
  try {
    await replaceEnvelopesCache(remoteEnvelopes);
  } catch {
    // The local cache is disposable and must never republish records that are
    // absent from the authenticated remote snapshot.
  }
  return remoteEnvelopes;
}

function buildMetadataSummary(envelopes: BrowserCredentialEnvelope[]): MetadataSummary {
  const relyingPartySet = new Set<string>();
  let lastUpdatedAt: string | null = null;
  let storedCredentialCount = 0;

  for (const envelope of envelopes) {
    if (envelope.lifecycleState === "pending" || envelope.lifecycleState === "deleted") {
      continue;
    }

    storedCredentialCount += 1;
    if (envelope.rpId) {
      relyingPartySet.add(envelope.rpId);
    }

    if (!lastUpdatedAt || envelope.updatedAt > lastUpdatedAt) {
      lastUpdatedAt = envelope.updatedAt;
    }
  }

  return {
    storedCredentialCount,
    relyingPartyCount: relyingPartySet.size,
    lastUpdatedAt
  };
}

function ensureKeyVaultMetadataConfig(config: BrowserExtensionConfig): void {
  if (!config.keyVaultBaseUrl.trim()) {
    throw new Error("Key Vault Base URL is required for Key Vault-backed metadata mode.");
  }

  if (!config.metadataWrappingKeyName.trim()) {
    throw new Error("Metadata Wrap Key is required for Key Vault-backed metadata mode.");
  }

  if (!config.metadataSecretPrefix.trim()) {
    throw new Error("Metadata Secret Prefix is required for Key Vault-backed metadata mode.");
  }
}

function toPlainArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}

async function setCreateDebugPhase(phase: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [createDebugPhaseStorageKey]: phase }, () => resolve());
  });
}
