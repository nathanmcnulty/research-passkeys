const vaultClouds = [
  { hostSuffix: ".vault.azure.net", tokenScope: "https://vault.azure.net/.default" },
  { hostSuffix: ".vault.azure.cn", tokenScope: "https://vault.azure.cn/.default" },
  { hostSuffix: ".vault.usgovcloudapi.net", tokenScope: "https://vault.usgovcloudapi.net/.default" },
  { hostSuffix: ".vault.microsoftazure.de", tokenScope: "https://vault.microsoftazure.de/.default" }
] as const;

const allowedAuthorityHosts = new Set([
  "login.microsoftonline.com",
  "login.microsoftonline.us",
  "login.chinacloudapi.cn",
  "login.microsoftonline.de"
]);

const objectSegmentPattern = /^[0-9A-Za-z-]{1,127}$/;
const dnsLabelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const guidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

export function normalizeKeyVaultBaseUrl(value: string): string {
  const candidate = parseAbsoluteUrl(value, "Key Vault Base URL");
  if (candidate.protocol !== "https:"
    || candidate.username
    || candidate.password
    || candidate.port
    || candidate.pathname !== "/"
    || candidate.search
    || candidate.hash
    || !vaultClouds.some((cloud) => isSingleVaultHostLabel(candidate.hostname, cloud.hostSuffix))) {
    throw new Error("Key Vault Base URL must be an HTTPS Azure Key Vault origin without a path, query, fragment, user info, or custom port.");
  }

  return candidate.origin;
}

function isSingleVaultHostLabel(hostname: string, suffix: string): boolean {
  if (!hostname.endsWith(suffix)) {
    return false;
  }

  const vaultName = hostname.slice(0, -suffix.length);
  return dnsLabelPattern.test(vaultName);
}

export function getKeyVaultTokenScope(baseUrl: string): string {
  const hostname = new URL(normalizeKeyVaultBaseUrl(baseUrl)).hostname;
  const cloud = vaultClouds.find((candidate) => hostname.endsWith(candidate.hostSuffix));
  if (!cloud) {
    throw new Error("Key Vault cloud is not supported.");
  }

  return cloud.tokenScope;
}

export function normalizeKeyVaultKeyPath(baseUrl: string, keyIdentifier: string): string {
  const vaultOrigin = normalizeKeyVaultBaseUrl(baseUrl);
  const trimmedIdentifier = keyIdentifier.trim();
  if (!trimmedIdentifier) {
    throw new Error("Key identifier is required.");
  }

  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmedIdentifier) || trimmedIdentifier.startsWith("//") || trimmedIdentifier.startsWith("/")) {
    const identifier = new URL(trimmedIdentifier, `${vaultOrigin}/`);
    assertSameOrigin(identifier, vaultOrigin, "Key identifier");
    if (identifier.search || identifier.hash) {
      throw new Error("Key identifier must not contain a query or fragment.");
    }

    const segments = splitAndValidatePath(identifier.pathname);
    if (segments.length < 2 || segments.length > 3 || segments[0] !== "keys") {
      throw new Error("Key identifier must have the form /keys/{name}/{version?}.");
    }

    return `${vaultOrigin}/keys/${segments.slice(1).join("/")}`;
  }

  const relativeSegments = trimmedIdentifier.replace(/^\/+|\/+$/g, "").split("/");
  const keySegments = relativeSegments[0]?.toLowerCase() === "keys" ? relativeSegments.slice(1) : relativeSegments;
  validateKeySegments(keySegments);
  return `${vaultOrigin}/keys/${keySegments.join("/")}`;
}

export function assertKeyVaultRequestUrl(value: string, baseUrl: string): void {
  const vaultOrigin = normalizeKeyVaultBaseUrl(baseUrl);
  const candidate = parseAbsoluteUrl(value, "Key Vault request URL");
  assertSameOrigin(candidate, vaultOrigin, "Key Vault request");

  if (!candidate.pathname.startsWith("/keys/") && !candidate.pathname.startsWith("/secrets/")) {
    throw new Error("Key Vault bearer tokens may only be sent to key or secret data-plane endpoints on the configured vault.");
  }

  if (candidate.hash || candidate.searchParams.size !== 1 || candidate.searchParams.get("api-version") !== "7.5") {
    throw new Error("Key Vault request URL contains an unexpected query or fragment.");
  }
}

export function normalizeEntraAuthorityHost(value: string): string {
  const candidate = parseAbsoluteUrl(value, "Authority Host");
  if (candidate.protocol !== "https:"
    || candidate.username
    || candidate.password
    || candidate.port
    || candidate.pathname !== "/"
    || candidate.search
    || candidate.hash
    || !allowedAuthorityHosts.has(candidate.hostname)) {
    throw new Error("Authority Host must be a supported Microsoft Entra HTTPS login origin.");
  }

  return candidate.origin;
}

export function assertGuid(value: string, label: string): string {
  const normalized = value.trim();
  if (!guidPattern.test(normalized)) {
    throw new Error(`${label} must be a GUID.`);
  }

  return normalized.toLowerCase();
}

export function assertOAuthRedirect(value: string, expectedRedirectUri: string, expectedState: string): URL {
  const response = parseAbsoluteUrl(value, "OAuth redirect");
  const expected = parseAbsoluteUrl(expectedRedirectUri, "OAuth redirect URI");
  if (response.origin !== expected.origin
    || response.pathname !== expected.pathname
    || response.username
    || response.password
    || response.hash) {
    throw new Error("OAuth redirect did not match the extension redirect URI.");
  }

  if (response.searchParams.get("state") !== expectedState) {
    throw new Error("OAuth state validation failed.");
  }

  return response;
}

function parseAbsoluteUrl(value: string, label: string): URL {
  try {
    return new URL(value.trim());
  } catch {
    throw new Error(`${label} must be an absolute URL.`);
  }
}

function assertSameOrigin(candidate: URL, expectedOrigin: string, label: string): void {
  if (candidate.protocol !== "https:"
    || candidate.username
    || candidate.password
    || candidate.port
    || candidate.origin !== expectedOrigin) {
    throw new Error(`${label} destination does not match the configured vault origin.`);
  }
}

function splitAndValidatePath(pathname: string): string[] {
  const segments = pathname.split("/").filter(Boolean).map((segment) => {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error("Key identifier contains invalid path encoding.");
    }

    if (decoded.includes("/") || decoded.includes("\\")) {
      throw new Error("Key identifier contains an encoded path separator.");
    }

    return decoded;
  });

  if (segments[0] === "keys") {
    validateKeySegments(segments.slice(1));
  }

  return segments;
}

function validateKeySegments(segments: string[]): void {
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !objectSegmentPattern.test(segment))) {
    throw new Error("Key identifier must contain a valid key name and optional version.");
  }
}
