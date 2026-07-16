import type { BrowserCredentialEnvelope } from "./models";
import { KeyVaultClient } from "./key-vault-client";

const envelopeContentType = "application/vnd.keyvault-passkey-provider.envelope+json";
const manifestContentType = "application/vnd.keyvault-passkey-provider.manifest+json";
const createDebugPhaseStorageKey = "kvpp.debug.createPhase";

type MetadataManifest = {
  version: "1";
  updatedAt: string;
  recordIds: string[];
};

export class KeyVaultSecretMetadataTransport {
  public constructor(
    private readonly client: KeyVaultClient,
    private readonly secretPrefix: string
  ) {}

  public async saveEnvelope(envelope: BrowserCredentialEnvelope): Promise<void> {
    await setCreateDebugPhase("save-record:save-transport:save-envelope-secret");
    await this.client.setSecret(this.buildSecretName(envelope.recordId), JSON.stringify(envelope), {
      contentType: envelopeContentType,
      tags: {
        recordId: envelope.recordId,
        rpId: envelope.rpId ?? "",
        backendKind: envelope.backendKind ?? ""
      }
    });

    await setCreateDebugPhase("save-record:save-transport:update-manifest");
    await this.upsertManifestRecordId(envelope.recordId);
  }

  public async loadEnvelope(recordId: string): Promise<BrowserCredentialEnvelope | null> {
    const secret = await this.client.getSecret(this.buildSecretName(recordId));
    if (!secret?.value) {
      return null;
    }

    return JSON.parse(secret.value) as BrowserCredentialEnvelope;
  }

  public async loadEnvelopes(recordIds: string[]): Promise<BrowserCredentialEnvelope[]> {
    const envelopes = await Promise.all(recordIds.map((recordId) => this.loadEnvelope(recordId)));
    return envelopes.filter((envelope): envelope is BrowserCredentialEnvelope => envelope !== null);
  }

  public async loadAllEnvelopes(): Promise<BrowserCredentialEnvelope[]> {
    const recordIds = await this.loadManifestRecordIds();
    if (recordIds.length === 0) {
      return [];
    }

    return this.loadEnvelopes(recordIds);
  }

  public async deleteEnvelope(recordId: string): Promise<void> {
    await this.client.deleteSecret(this.buildSecretName(recordId));
    await this.removeManifestRecordId(recordId);
  }

  public buildSecretName(recordId: string): string {
    return `${this.secretPrefix}-${recordId.toLowerCase()}`;
  }

  public buildManifestSecretName(): string {
    return `${this.secretPrefix}-manifest`;
  }

  public async loadManifestRecordIds(): Promise<string[]> {
    await setCreateDebugPhase("save-record:save-transport:load-manifest");
    const secret = await this.client.getSecret(this.buildManifestSecretName());
    if (!secret?.value) {
      return [];
    }

    const manifest = JSON.parse(secret.value) as Partial<MetadataManifest>;
    return Array.isArray(manifest.recordIds)
      ? manifest.recordIds.filter((recordId): recordId is string => typeof recordId === "string" && recordId.length > 0)
      : [];
  }

  private async upsertManifestRecordId(recordId: string): Promise<void> {
    const recordIds = await this.loadManifestRecordIds();
    if (!recordIds.includes(recordId)) {
      recordIds.push(recordId);
    }

    await this.saveManifest(recordIds);
  }

  private async removeManifestRecordId(recordId: string): Promise<void> {
    const recordIds = await this.loadManifestRecordIds();
    const filtered = recordIds.filter((candidate) => candidate !== recordId);

    if (filtered.length === recordIds.length) {
      return;
    }

    await this.saveManifest(filtered);
  }

  private async saveManifest(recordIds: string[]): Promise<void> {
    const manifest: MetadataManifest = {
      version: "1",
      updatedAt: new Date().toISOString(),
      recordIds: [...new Set(recordIds)].sort((left, right) => left.localeCompare(right))
    };

    await setCreateDebugPhase("save-record:save-transport:save-manifest-secret");
    await this.client.setSecret(this.buildManifestSecretName(), JSON.stringify(manifest), {
      contentType: manifestContentType,
      tags: {
        kind: "metadata-manifest"
      }
    });
  }
}

async function setCreateDebugPhase(phase: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [createDebugPhaseStorageKey]: phase }, () => resolve());
  });
}
