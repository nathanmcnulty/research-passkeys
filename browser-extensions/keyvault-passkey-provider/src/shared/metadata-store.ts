import { fromBase64Url, toBase64Url } from "./base64url";
import { deleteEnvelopeFromCache, loadEnvelopesFromCache, saveEnvelopeToCache } from "./metadata-cache-store";
import { DevelopmentFunctionCatalogClient, type FunctionCatalogSnapshot } from "./function-catalog-client";
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
  developmentCatalog: DevelopmentFunctionCatalogClient | null;
};

export function createMetadataEnvironment(config: BrowserExtensionConfig, tokenProvider: AccessTokenProvider): BrowserMetadataEnvironment {
  if (config.metadataTransportMode === "LocalCacheOnly") {
    return {
      keyProtector: new BrowserLocalMetadataKeyProtector(),
      transport: null,
      keyVaultClient: null,
      developmentCatalog: null
    };
  }

  if (config.metadataTransportMode === "FunctionCatalog") {
    return {
      keyProtector: new BrowserLocalMetadataKeyProtector(),
      transport: null,
      keyVaultClient: null,
      developmentCatalog: new DevelopmentFunctionCatalogClient({
        baseUrl: config.developmentFunctionAppBaseUrl,
        apiScope: `api://${config.clientId}/access_as_user`
      }, tokenProvider)
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
    keyVaultClient: client,
    developmentCatalog: config.developmentFunctionAppBaseUrl.trim()
      ? new DevelopmentFunctionCatalogClient({
          baseUrl: config.developmentFunctionAppBaseUrl,
          apiScope: `api://${config.clientId}/access_as_user`
        }, tokenProvider)
      : null
  };
}

export async function saveCredentialRecord(record: BrowserStoredCredentialRecord, environment: BrowserMetadataEnvironment): Promise<void> {
  const contentKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  await setCreateDebugPhase("save-record:protect-content-key");
  const protectedContentKey = await environment.keyProtector.protectContentKey(contentKey);
  const plaintext = new TextEncoder().encode(JSON.stringify(record));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const envelopeTemplate: BrowserCredentialEnvelope = {
    version: "1",
    recordId: record.recordId,
    contentKeyProtection: protectedContentKey.protectionMode,
    updatedAt: record.updatedAt,
    ciphertext: "",
    protectedContentKey: protectedContentKey.value,
    metadataKeyId: protectedContentKey.keyId,
    nonce: toBase64Url(nonce),
    tag: ""
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
  }

  await setCreateDebugPhase("save-record:save-cache");
  await saveEnvelopeToCache(record.recordId, envelope);
}

export async function loadCredentialRecords(environment: BrowserMetadataEnvironment): Promise<BrowserStoredCredentialRecord[]> {
  const [envelopes, catalogSnapshot] = await Promise.all([
    loadEnvelopes(environment),
    environment.developmentCatalog?.loadSnapshot() ?? Promise.resolve(emptyCatalogSnapshot())
  ]);

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

    results.push(JSON.parse(new TextDecoder().decode(plaintext)) as BrowserStoredCredentialRecord);
  }

  return mergeCredentialRecords(results, catalogSnapshot);
}

export async function deleteCredentialRecord(recordId: string, environment: BrowserMetadataEnvironment): Promise<void> {
  if (environment.developmentCatalog) {
    const catalog = await environment.developmentCatalog.loadSnapshot();
    if (catalog.knownRecordIds.has(recordId)) {
      await environment.developmentCatalog.delete(recordId);
      await deleteEnvelopeFromCache(recordId);
      return;
    }
  }

  if (environment.transport) {
    await environment.transport.deleteEnvelope(recordId);
  }

  await deleteEnvelopeFromCache(recordId);
}

export async function getMetadataSummary(environment: BrowserMetadataEnvironment): Promise<MetadataSummary> {
  const records = await loadCredentialRecords(environment);
  return buildMetadataSummary(records);
}

function buildAssociatedData(envelope: BrowserCredentialEnvelope): Uint8Array {
  const unixSeconds = Math.floor(new Date(envelope.updatedAt).getTime() / 1000);
  const aadString = [
    envelope.version,
    envelope.recordId,
    envelope.contentKeyProtection,
    unixSeconds.toString(),
    envelope.metadataKeyId ?? ""
  ].join("|");

  return new TextEncoder().encode(aadString);
}

async function loadEnvelopes(environment: BrowserMetadataEnvironment): Promise<BrowserCredentialEnvelope[]> {
  if (!environment.transport) {
    return loadEnvelopesFromCache();
  }

  const [remoteEnvelopes, cachedEnvelopes] = await Promise.all([
    environment.transport.loadAllEnvelopes(),
    loadEnvelopesFromCache()
  ]);
  const mergedEnvelopes = mergeEnvelopes(remoteEnvelopes, cachedEnvelopes);
  await Promise.all(mergedEnvelopes.map((envelope) => saveEnvelopeToCache(envelope.recordId, envelope)));
  return mergedEnvelopes;
}

function mergeEnvelopes(
  remoteEnvelopes: BrowserCredentialEnvelope[],
  cachedEnvelopes: BrowserCredentialEnvelope[]
): BrowserCredentialEnvelope[] {
  const envelopesByRecordId = new Map<string, BrowserCredentialEnvelope>();

  for (const envelope of cachedEnvelopes) {
    envelopesByRecordId.set(envelope.recordId, envelope);
  }

  for (const envelope of remoteEnvelopes) {
    const existing = envelopesByRecordId.get(envelope.recordId);
    if (!existing || Date.parse(envelope.updatedAt) >= Date.parse(existing.updatedAt)) {
      envelopesByRecordId.set(envelope.recordId, envelope);
    }
  }

  return Array.from(envelopesByRecordId.values());
}

function buildMetadataSummary(records: BrowserStoredCredentialRecord[]): MetadataSummary {
  const relyingPartySet = new Set<string>();
  let lastUpdatedAt: string | null = null;

  for (const record of records) {
    relyingPartySet.add(record.rpId);

    if (!lastUpdatedAt || record.updatedAt > lastUpdatedAt) {
      lastUpdatedAt = record.updatedAt;
    }
  }

  return {
    storedCredentialCount: records.length,
    relyingPartyCount: relyingPartySet.size,
    lastUpdatedAt
  };
}

function emptyCatalogSnapshot(): FunctionCatalogSnapshot {
  return { activeRecords: [], knownRecordIds: new Set<string>() };
}

function mergeCredentialRecords(
  storedRecords: BrowserStoredCredentialRecord[],
  catalog: FunctionCatalogSnapshot
): BrowserStoredCredentialRecord[] {
  const recordsById = new Map(storedRecords.map((record) => [record.recordId, record]));
  const activeCatalogRecordsById = new Map(catalog.activeRecords.map((record) => [record.recordId, record]));

  for (const recordId of catalog.knownRecordIds) {
    const catalogRecord = activeCatalogRecordsById.get(recordId);
    if (!catalogRecord) {
      recordsById.delete(recordId);
      continue;
    }

    const storedRecord = recordsById.get(recordId);
    if (!storedRecord || Date.parse(catalogRecord.updatedAt) >= Date.parse(storedRecord.updatedAt)) {
      recordsById.set(recordId, catalogRecord);
    }
  }

  return Array.from(recordsById.values());
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
