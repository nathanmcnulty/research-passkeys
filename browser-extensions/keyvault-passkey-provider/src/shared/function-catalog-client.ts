import type { BrowserStoredCredentialRecord } from "./models";
import { fromBase64Url, toBase64Url } from "./base64url";
import type { AccessTokenProvider } from "./key-vault-client";

export type FunctionCatalogSnapshot = {
  activeRecords: BrowserStoredCredentialRecord[];
  knownRecordIds: Set<string>;
};

export type DevelopmentFunctionCatalogConfig = {
  baseUrl: string;
  apiScope: string;
};

export type FunctionAssertion = {
  authenticatorData: Uint8Array;
  signature: Uint8Array;
  signCount: number;
};

export type FunctionBrowserContext = {
  provider: "entra" | "okta";
  rpId: string;
  userName: string;
  userAgent: string | null;
};

type FunctionCatalogResponse = {
  success?: boolean;
  records?: unknown;
  error?: unknown;
};

type PasskeyCatalogRecord = {
  recordId: string;
  provider: "entra" | "okta";
  credentialId: string;
  rpId: string;
  userHandle: string | null;
  userName: string;
  displayName: string;
  keyVault: {
    vaultName: string;
    keyName: string;
    keyId: string;
  };
  status: "active" | "disabled" | "deleted";
  signCount: number;
  createdAt: string;
  updatedAt: string;
};

export class DevelopmentFunctionCatalogClient {
  private readonly fetchImpl: typeof fetch;

  public constructor(
    private readonly config: DevelopmentFunctionCatalogConfig,
    private readonly tokenProvider: AccessTokenProvider,
    fetchImpl: typeof fetch = globalThis.fetch
  ) {
    this.fetchImpl = fetchImpl.bind(globalThis);
  }

  public async loadSnapshot(): Promise<FunctionCatalogSnapshot> {
    const headers = await this.getHeaders();
    const response = await this.fetchImpl(buildCatalogUrl(this.config.baseUrl), {
      method: "GET",
      cache: "no-store",
      headers
    });

    const payload = await readResponsePayload(response);
    if (!response.ok || payload.success !== true || !Array.isArray(payload.records)) {
      const detail = typeof payload.error === "string" && payload.error.trim()
        ? ` ${payload.error.trim()}`
        : "";
      throw new Error(`Function catalog request failed with HTTP ${response.status}.${detail}`);
    }

    const records = payload.records.map(parseCatalogRecord);
    const knownRecordIds = new Set(records.map((record) => record.recordId));
    if (knownRecordIds.size !== records.length) {
      throw new Error("Function catalog response contains duplicate recordId values.");
    }
    const activeRecords = records
      .filter((record) => record.status === "active")
      .map((record) => mapCatalogRecord(record));

    return { activeRecords, knownRecordIds };
  }

  public async assert(
    recordId: string,
    rpId: string,
    clientDataHash: Uint8Array,
    userVerified: boolean
  ): Promise<FunctionAssertion> {
    const response = await this.fetchImpl(buildAssertionUrl(this.config.baseUrl, recordId), {
      method: "POST",
      cache: "no-store",
      headers: {
        ...(await this.getHeaders()),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ rpId, clientDataHash: toBase64Url(clientDataHash), userVerified })
    });
    const payload = await readResponsePayload(response) as FunctionCatalogResponse & {
      authenticatorData?: unknown;
      signature?: unknown;
      signCount?: unknown;
      signatureFormat?: unknown;
    };
    if (!response.ok || payload.success !== true) {
      const detail = typeof payload.error === "string" && payload.error.trim() ? ` ${payload.error.trim()}` : "";
      throw new Error(`Function assertion request failed with HTTP ${response.status}.${detail}`);
    }
    if (typeof payload.authenticatorData !== "string" || typeof payload.signature !== "string"
      || payload.signatureFormat !== "ieee-p1363" || !Number.isInteger(payload.signCount)) {
      throw new Error("Function assertion response is invalid.");
    }
    return {
      authenticatorData: fromBase64Url(payload.authenticatorData),
      signature: fromBase64Url(payload.signature),
      signCount: payload.signCount as number
    };
  }

  public async loadBrowserContext(recordId: string): Promise<FunctionBrowserContext> {
    const response = await this.fetchImpl(buildBrowserContextUrl(this.config.baseUrl, recordId), {
      method: "GET",
      cache: "no-store",
      headers: await this.getHeaders()
    });
    const payload = await readResponsePayload(response) as FunctionCatalogResponse & {
      browserContext?: unknown;
    };
    if (!response.ok || payload.success !== true || !isObject(payload.browserContext)) {
      const detail = typeof payload.error === "string" && payload.error.trim() ? ` ${payload.error.trim()}` : "";
      throw new Error(`Function browser-context request failed with HTTP ${response.status}.${detail}`);
    }

    const context = payload.browserContext;
    return {
      provider: requireEnum(context.provider, ["entra", "okta"], "provider", 0),
      rpId: requireString(context.rpId, "rpId", 0),
      userName: requireString(context.userName, "userName", 0),
      userAgent: typeof context.userAgent === "string" && context.userAgent.trim() ? context.userAgent.trim() : null
    };
  }

  public async delete(recordId: string): Promise<void> {
    const response = await this.fetchImpl(buildRecordUrl(this.config.baseUrl, recordId), {
      method: "DELETE",
      cache: "no-store",
      headers: await this.getHeaders()
    });
    const payload = await readResponsePayload(response);
    if (!response.ok || payload.success !== true) {
      const detail = typeof payload.error === "string" && payload.error.trim() ? ` ${payload.error.trim()}` : "";
      throw new Error(`Function passkey removal failed with HTTP ${response.status}.${detail}`);
    }
  }

  private async getHeaders(): Promise<Record<string, string>> {
    const token = await this.tokenProvider([this.config.apiScope]);
    return { Accept: "application/json", Authorization: `Bearer ${token.accessToken}` };
  }
}

export function mapCatalogRecord(
  record: PasskeyCatalogRecord
): BrowserStoredCredentialRecord {
  if (!record.userHandle?.trim()) {
    throw new Error(`Function catalog record '${record.recordId}' has no WebAuthn userHandle.`);
  }

  return {
    recordId: record.recordId,
    credentialId: record.credentialId,
    rpId: record.rpId,
    userHandle: record.userHandle,
    userName: record.userName,
    userDisplayName: record.displayName || record.userName,
    signingKeyId: record.keyVault.keyId,
    backendKind: "key-vault",
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    signCount: record.signCount
  };
}

function buildAssertionUrl(baseUrl: string, recordId: string): string {
  const parsed = parseDevelopmentFunctionUrl(baseUrl);
  const normalizedPath = parsed.pathname.replace(/\/+$/, "");
  parsed.pathname = normalizedPath.endsWith("/api")
    ? `${normalizedPath}/passkeys/${encodeURIComponent(recordId)}/assert`
    : `${normalizedPath}/api/passkeys/${encodeURIComponent(recordId)}/assert`;
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

function buildBrowserContextUrl(baseUrl: string, recordId: string): string {
  const parsed = new URL(buildRecordUrl(baseUrl, recordId));
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, "")}/browser-context`;
  return parsed.toString();
}

function buildRecordUrl(baseUrl: string, recordId: string): string {
  const parsed = parseDevelopmentFunctionUrl(baseUrl);
  const normalizedPath = parsed.pathname.replace(/\/+$/, "");
  parsed.pathname = normalizedPath.endsWith("/api")
    ? `${normalizedPath}/passkeys/${encodeURIComponent(recordId)}`
    : `${normalizedPath}/api/passkeys/${encodeURIComponent(recordId)}`;
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

function buildCatalogUrl(baseUrl: string): string {
  const parsed = parseDevelopmentFunctionUrl(baseUrl);
  const normalizedPath = parsed.pathname.replace(/\/+$/, "");
  parsed.pathname = normalizedPath.endsWith("/api")
    ? `${normalizedPath}/passkeys`
    : `${normalizedPath}/api/passkeys`;
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

function parseDevelopmentFunctionUrl(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Development Function App Base URL must be an absolute URL.");
  }

  const isLocalHttp = parsed.protocol === "http:"
    && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]");
  if (parsed.protocol !== "https:" && !isLocalHttp) {
    throw new Error("Development Function App Base URL must use HTTPS, except for localhost development.");
  }

  return parsed;
}

function parseCatalogRecord(value: unknown, index: number): PasskeyCatalogRecord {
  if (!isObject(value)) {
    throw new Error(`Function catalog record at index ${index} is not an object.`);
  }

  const keyVault = value.keyVault;
  if (!isObject(keyVault)) {
    throw new Error(`Function catalog record at index ${index} has no keyVault object.`);
  }

  const record: PasskeyCatalogRecord = {
    recordId: requireString(value.recordId, "recordId", index),
    provider: requireEnum(value.provider, ["entra", "okta"], "provider", index),
    credentialId: requireString(value.credentialId, "credentialId", index),
    rpId: requireString(value.rpId, "rpId", index),
    userHandle: value.userHandle == null ? null : requireString(value.userHandle, "userHandle", index),
    userName: requireString(value.userName, "userName", index),
    displayName: typeof value.displayName === "string" ? value.displayName : "",
    keyVault: {
      vaultName: requireString(keyVault.vaultName, "keyVault.vaultName", index),
      keyName: requireString(keyVault.keyName, "keyVault.keyName", index),
      keyId: requireString(keyVault.keyId, "keyVault.keyId", index)
    },
    status: requireEnum(value.status, ["active", "disabled", "deleted"], "status", index),
    signCount: requireNonnegativeInteger(value.signCount, "signCount", index),
    createdAt: requireDateTime(value.createdAt, "createdAt", index),
    updatedAt: requireDateTime(value.updatedAt, "updatedAt", index)
  };

  if (!isUuid(record.recordId)) {
    throw new Error(`Function catalog record at index ${index} has an invalid recordId.`);
  }

  return record;
}

async function readResponsePayload(response: Response): Promise<FunctionCatalogResponse> {
  try {
    return await response.json() as FunctionCatalogResponse;
  } catch {
    return {};
  }
}

function requireString(value: unknown, field: string, index: number): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Function catalog record at index ${index} has an invalid ${field}.`);
  }
  return value;
}

function requireDateTime(value: unknown, field: string, index: number): string {
  const result = requireString(value, field, index);
  if (Number.isNaN(Date.parse(result))) {
    throw new Error(`Function catalog record at index ${index} has an invalid ${field}.`);
  }
  return result;
}

function requireNonnegativeInteger(value: unknown, field: string, index: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`Function catalog record at index ${index} has an invalid ${field}.`);
  }
  return value;
}

function requireEnum<TValue extends string>(
  value: unknown,
  allowed: readonly TValue[],
  field: string,
  index: number
): TValue {
  if (typeof value !== "string" || !allowed.includes(value as TValue)) {
    throw new Error(`Function catalog record at index ${index} has an invalid ${field}.`);
  }
  return value as TValue;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
