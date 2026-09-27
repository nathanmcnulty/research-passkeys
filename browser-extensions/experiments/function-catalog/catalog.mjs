// Research-only, read-only Function catalog adapter. No signing or mutation routes.
export class ReadOnlyFunctionCatalog {
  constructor({ baseUrl, apiScope, tokenProvider, fetchImpl = globalThis.fetch }) {
    if (typeof apiScope !== "string" || !apiScope.trim() || typeof tokenProvider !== "function"
      || typeof fetchImpl !== "function") {
      throw new TypeError("Catalog scope, token provider, and fetch implementation are required.");
    }
    this.url = catalogUrl(baseUrl);
    this.apiScope = apiScope;
    this.tokenProvider = tokenProvider;
    this.fetchImpl = fetchImpl;
  }

  async list() {
    const token = await this.tokenProvider([this.apiScope]);
    if (typeof token?.accessToken !== "string" || !token.accessToken.trim()) {
      throw new Error("Catalog access token is unavailable.");
    }
    const response = await this.fetchImpl.call(globalThis, this.url, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: { Accept: "application/json", Authorization: `Bearer ${token.accessToken}` }
    });
    if (!response.ok) throw new Error(`Function catalog request failed with HTTP ${response.status}.`);
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error("Function catalog response is not JSON.");
    }
    if (payload?.success !== true || !Array.isArray(payload.records) || payload.records.length > 1000) {
      throw new Error("Function catalog response is invalid.");
    }
    const records = payload.records.map(parseRecord);
    if (new Set(records.map((record) => record.recordId)).size !== records.length
      || new Set(records.map((record) => record.credentialId)).size !== records.length) {
      throw new Error("Function catalog response contains duplicate credentials.");
    }
    return records;
  }
}

function catalogUrl(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error("Function catalog base URL must be absolute.");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(local && url.protocol === "http:"))
    || url.username || url.password || url.search || url.hash) {
    throw new Error("Function catalog base URL must be HTTPS without credentials, query, or fragment.");
  }
  const pathname = url.pathname.replace(/\/+$/, "");
  url.pathname = pathname.endsWith("/api") ? `${pathname}/passkeys` : `${pathname}/api/passkeys`;
  return url.toString();
}

function parseRecord(value, index) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Function catalog record ${index} is invalid.`);
  }
  const required = ["recordId", "credentialId", "rpId", "userHandle", "userName", "updatedAt"];
  for (const field of required) {
    if (typeof value[field] !== "string" || !value[field].trim()) {
      throw new Error(`Function catalog record ${index} has invalid ${field}.`);
    }
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.recordId)
    || Number.isNaN(Date.parse(value.updatedAt))
    || !["active", "disabled", "deleted"].includes(value.status)
    || !Number.isSafeInteger(value.signCount) || value.signCount < 0) {
    throw new Error(`Function catalog record ${index} has invalid metadata.`);
  }
  return {
    recordId: value.recordId,
    credentialId: value.credentialId,
    rpId: value.rpId,
    userHandle: value.userHandle,
    userName: value.userName,
    displayName: typeof value.displayName === "string" && value.displayName.trim()
      ? value.displayName : value.userName,
    status: value.status,
    signCount: value.signCount,
    updatedAt: value.updatedAt
  };
}
