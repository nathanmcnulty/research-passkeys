import { fromBase64Url, toBase64Url } from "./base64url";

const apiVersion = "7.5";
const createDebugPhaseStorageKey = "kvpp.debug.createPhase";

export type AccessToken = {
  accessToken: string;
  expiresOn?: string;
};

export type AccessTokenProvider = (scopes: string[]) => Promise<AccessToken>;

export type KeyVaultClientConfig = {
  baseUrl: string;
  signingKeyName: string;
  metadataWrappingKeyName: string;
};

export type KeyVaultEcKey = {
  keyId: string;
  keyName: string;
  x: Uint8Array;
  y: Uint8Array;
};

export type KeyVaultSecretRecord = {
  id: string;
  name: string;
  value: string | null;
  contentType: string | null;
  tags: Record<string, string>;
  updatedAt: string | null;
};

export class KeyVaultClient {
  public constructor(
    private readonly config: KeyVaultClientConfig,
    private readonly tokenProvider: AccessTokenProvider
  ) {}

  public async createEcP256Key(keyName: string, keyType: "EC" | "EC-HSM"): Promise<KeyVaultEcKey> {
    const response = await this.sendJson<{ key: { kid: string; x: string; y: string } }>(
      "POST",
      `${this.config.baseUrl}/keys/${encodeURIComponent(keyName)}/create?api-version=${apiVersion}`,
      {
        kty: keyType,
        crv: "P-256",
        key_ops: ["sign", "verify"],
        attributes: { enabled: true }
      }
    );

    return {
      keyId: response.key.kid,
      keyName,
      x: fromBase64Url(response.key.x),
      y: fromBase64Url(response.key.y)
    };
  }

  public async signDigest(keyIdentifier: string, digest: Uint8Array): Promise<Uint8Array> {
    const keyPath = this.normalizeKeyPath(keyIdentifier);
    const response = await this.sendJson<{ value: string }>(
      "POST",
      `${keyPath}/sign?api-version=${apiVersion}`,
      {
        alg: "ES256",
        value: toBase64Url(digest)
      }
    );

    return fromBase64Url(response.value);
  }

  public async deleteKey(keyIdentifier: string): Promise<void> {
    const keyPath = this.normalizeKeyPath(keyIdentifier);
    await this.sendJson<unknown>(
      "DELETE",
      `${keyPath}?api-version=${apiVersion}`,
      undefined,
      false
    );
  }

  public async wrapKey(contentKey: Uint8Array): Promise<{ keyId: string; wrappedKey: Uint8Array }> {
    await setCreateDebugPhase("save-record:protect-content-key:wrapkey:get-key-id");
    const keyId = await this.getMetadataKeyIdentifier();
    await setCreateDebugPhase("save-record:protect-content-key:wrapkey:post-wrap");
    const keyPath = this.normalizeKeyPath(keyId);
    const response = await this.sendJson<{ value: string }>(
      "POST",
      `${keyPath}/wrapkey?api-version=${apiVersion}`,
      {
        alg: "RSA-OAEP-256",
        value: toBase64Url(contentKey)
      }
    );

    return {
      keyId,
      wrappedKey: fromBase64Url(response.value)
    };
  }

  public async unwrapKey(keyIdentifier: string, wrappedKey: Uint8Array): Promise<Uint8Array> {
    const keyPath = this.normalizeKeyPath(keyIdentifier);
    const response = await this.sendJson<{ value: string }>(
      "POST",
      `${keyPath}/unwrapkey?api-version=${apiVersion}`,
      {
        alg: "RSA-OAEP-256",
        value: toBase64Url(wrappedKey)
      }
    );

    return fromBase64Url(response.value);
  }

  public async getMetadataKeyIdentifier(): Promise<string> {
    const response = await this.sendJson<{ key: { kid: string } }>(
      "GET",
      `${this.config.baseUrl}/keys/${encodeURIComponent(this.config.metadataWrappingKeyName)}?api-version=${apiVersion}`
    );

    return response.key.kid;
  }

  public async setSecret(name: string, value: string, options?: { contentType?: string; tags?: Record<string, string> }): Promise<void> {
    await this.sendWithoutResponseBody(
      "PUT",
      `${this.config.baseUrl}/secrets/${encodeURIComponent(name)}?api-version=${apiVersion}`,
      {
        value,
        contentType: options?.contentType,
        tags: options?.tags
      }
    );
  }

  public async getSecret(name: string): Promise<KeyVaultSecretRecord | null> {
    const response = await this.sendJson<SecretResponse | null>(
      "GET",
      `${this.config.baseUrl}/secrets/${encodeURIComponent(name)}?api-version=${apiVersion}`,
      undefined,
      false
    );

    return response ? this.mapSecretResponse(response) : null;
  }

  public async deleteSecret(name: string): Promise<void> {
    await this.sendJson<unknown>(
      "DELETE",
      `${this.config.baseUrl}/secrets/${encodeURIComponent(name)}?api-version=${apiVersion}`,
      undefined,
      false
    );
  }

  private async sendJson<TResponse>(
    method: string,
    url: string,
    body?: unknown,
    ensureSuccess = true
  ): Promise<TResponse> {
    const response = await this.send(method, url, body);

    if (!ensureSuccess && response.status === 404) {
      return null as TResponse;
    }

    if (!response.ok) {
      throw await createKeyVaultRequestError(response);
    }

    return response.json() as Promise<TResponse>;
  }

  private async sendWithoutResponseBody(
    method: string,
    url: string,
    body?: unknown
  ): Promise<void> {
    const response = await this.send(method, url, body);

    if (!response.ok) {
      throw await createKeyVaultRequestError(response);
    }

    await response.arrayBuffer();
  }

  private async send(
    method: string,
    url: string,
    body?: unknown
  ): Promise<Response> {
    const token = await this.acquireVaultToken();
    return fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${token.accessToken}`,
        ...(body ? { "Content-Type": "application/json" } : {})
      },
      body: body ? JSON.stringify(body) : undefined
    });
  }

  private async acquireVaultToken(): Promise<AccessToken> {
    try {
      return await this.tokenProvider(["https://vault.azure.net/.default"]);
    } catch (error) {
      const message = error instanceof Error && error.message
        ? `Key Vault sign-in is required or expired. ${error.message}`
        : "Key Vault sign-in is required or expired. Reauthenticate in the extension popup and retry.";
      throw new DOMException(message, "NotAllowedError");
    }
  }

  private normalizeKeyPath(keyIdentifier: string): string {
    if (keyIdentifier.startsWith("https://")) {
      return keyIdentifier.replace(/\/$/, "");
    }

    return `${this.config.baseUrl}/keys/${keyIdentifier.replace(/^\/+/, "")}`;
  }

  private mapSecretResponse(secret: SecretResponse): KeyVaultSecretRecord {
    const segments = secret.id.split("/");
    const name = segments.at(-1) ?? secret.id;
    return {
      id: secret.id,
      name,
      value: secret.value ?? null,
      contentType: secret.contentType ?? null,
      tags: secret.tags ?? {},
      updatedAt: secret.attributes?.updated ? new Date(secret.attributes.updated * 1000).toISOString() : null
    };
  }
}

async function setCreateDebugPhase(phase: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [createDebugPhaseStorageKey]: phase }, () => resolve());
  });
}

type SecretResponse = {
  id: string;
  value?: string;
  contentType?: string;
  tags?: Record<string, string>;
  attributes?: {
    updated?: number;
  };
};

type KeyVaultErrorEnvelope = {
  error?: {
    code?: string;
    message?: string;
  };
};

async function createKeyVaultRequestError(response: Response): Promise<DOMException> {
  const detail = await readKeyVaultErrorDetail(response);
  const statusLine = `${response.status} ${response.statusText}`.trim();

  if (response.status === 401) {
    return new DOMException(
      `Key Vault rejected the request with ${statusLine}. Reauthenticate in the extension popup and retry.${detail ? ` ${detail}` : ""}`,
      "NotAllowedError"
    );
  }

  if (response.status === 403) {
    return new DOMException(
      `Key Vault rejected the request with ${statusLine}. The signed-in account does not have the required vault permissions.${detail ? ` ${detail}` : ""}`,
      "SecurityError"
    );
  }

  return new DOMException(
    `Key Vault request failed with ${statusLine}.${detail ? ` ${detail}` : ""}`,
    "OperationError"
  );
}

async function readKeyVaultErrorDetail(response: Response): Promise<string | null> {
  const responseText = await response.text();
  if (!responseText) {
    return null;
  }

  try {
    const payload = JSON.parse(responseText) as KeyVaultErrorEnvelope;
    const code = payload.error?.code?.trim();
    const message = payload.error?.message?.trim();

    if (code && message) {
      return `${code}: ${message}`;
    }

    if (message) {
      return message;
    }

    if (code) {
      return code;
    }
  } catch {
    // Best-effort parsing only.
  }

  const collapsed = responseText.replace(/\s+/g, " ").trim();
  return collapsed.length > 0 ? collapsed : null;
}
