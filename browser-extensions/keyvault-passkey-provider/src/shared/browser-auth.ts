import { toBase64Url } from "./base64url";
import type { AccessToken } from "./key-vault-client";
import type { BrowserAuthStatus, BrowserExtensionConfig } from "./protocol";

const keyVaultScope = "https://vault.azure.net/.default";
const cachedTokenStorageKey = "kvpp.auth.cachedToken";
const lastErrorStorageKey = "kvpp.auth.lastError";

type CachedToken = AccessToken & {
  scopeKey: string;
};

type TokenResponse = {
  access_token?: string;
  expires_in?: number | string;
  error?: string;
  error_description?: string;
};

type AuthorizationCodeFlowOptions = {
  interactive: boolean;
  prompt: "none" | "select_account";
  loginHint?: string;
};

class InteractiveSignInRequiredError extends Error {
  public constructor(message = "Interactive sign-in is required before the extension can call the configured service.") {
    super(message);
    this.name = "InteractiveSignInRequiredError";
  }
}

export class BrowserEntraTokenBroker {
  private cachedToken: CachedToken | null = null;
  private lastError: string | null = null;
  private hydrated = false;
  private hydrationPromise: Promise<void> | null = null;

  public async getHydratedStatus(config: BrowserExtensionConfig): Promise<BrowserAuthStatus> {
    await this.ensureHydrated();
    return this.getStatus(config);
  }

  public getStatus(config: BrowserExtensionConfig): BrowserAuthStatus {
    if (config.metadataTransportMode === "LocalCacheOnly") {
      return {
        mode: "local-only",
        expiresOn: null,
        message: "Local cache mode does not require an access token."
      };
    }

    const missingFields = getMissingAuthFields(config);
    if (missingFields.length > 0) {
      return {
        mode: "not-configured",
        expiresOn: null,
        message: `Missing auth config: ${missingFields.join(", ")}.`
      };
    }

    if (this.cachedToken && !isExpired(this.cachedToken.expiresOn)) {
      return {
        mode: "signed-in",
        expiresOn: this.cachedToken.expiresOn ?? null,
        message: "Function API token is cached in the extension background session."
      };
    }

    return {
      mode: "signed-out",
      expiresOn: null,
      message: this.lastError ?? "Interactive sign-in is required before the extension can call the Function API."
    };
  }

  public async clear(): Promise<void> {
    this.cachedToken = null;
    this.lastError = null;
    this.hydrated = true;
    await removeSessionValue(cachedTokenStorageKey);
    await removeSessionValue(lastErrorStorageKey);
  }

  public async beginInteractiveSignIn(config: BrowserExtensionConfig): Promise<BrowserAuthStatus> {
    ensureAuthConfig(config);
    await this.ensureHydrated();

    try {
      const scopes = getPrimaryScopes(config);
      const token = await this.runAuthorizationCodeFlow(config, scopes, {
        interactive: true,
        prompt: "select_account"
      });
      await this.storeCachedToken(normalizeScopes(scopes), token);
      return this.getStatus(config);
    } catch (error) {
      await this.storeLastError(error instanceof Error ? error.message : "Interactive sign-in failed.");
      throw error;
    }
  }

  public async beginSilentSignIn(config: BrowserExtensionConfig): Promise<BrowserAuthStatus | null> {
    const token = await this.acquireTokenSilently(config, getPrimaryScopes(config));
    return token ? this.getStatus(config) : null;
  }

  public async acquireToken(config: BrowserExtensionConfig, scopes: string[]): Promise<AccessToken> {
    ensureAuthConfig(config);
    await this.ensureHydrated();

    const scopeKey = normalizeScopes(scopes);
    if (this.cachedToken && this.cachedToken.scopeKey === scopeKey && !isExpired(this.cachedToken.expiresOn, 5 * 60 * 1000)) {
      return this.cachedToken;
    }

    const silentToken = await this.acquireTokenSilently(config, scopes);
    if (silentToken) {
      return silentToken;
    }

    throw new InteractiveSignInRequiredError(this.lastError ?? "Interactive sign-in is required before the extension can call the configured service.");
  }

  public async acquireTokenSilently(config: BrowserExtensionConfig, scopes: string[]): Promise<AccessToken | null> {
    ensureAuthConfig(config);
    await this.ensureHydrated();

    const scopeKey = normalizeScopes(scopes);
    if (this.cachedToken && this.cachedToken.scopeKey === scopeKey && !isExpired(this.cachedToken.expiresOn, 5 * 60 * 1000)) {
      return this.cachedToken;
    }

    try {
      const token = await this.runAuthorizationCodeFlow(config, scopes, {
        interactive: false,
        prompt: "none"
      });
      await this.storeCachedToken(scopeKey, token);
      return token;
    } catch (error) {
      if (isInteractiveSignInRequired(error)) {
        await this.clearCachedToken();
        await this.storeLastError("Interactive sign-in is required before the extension can call the configured service.");
        return null;
      }

      await this.clearCachedToken();
      await this.storeLastError(error instanceof Error ? error.message : "Silent sign-in failed.");
      throw error;
    }
  }

  private async ensureHydrated(): Promise<void> {
    if (this.hydrated) {
      return;
    }

    if (!this.hydrationPromise) {
      this.hydrationPromise = this.hydrateFromSession();
    }

    await this.hydrationPromise;
  }

  private async hydrateFromSession(): Promise<void> {
    try {
      const [storedToken, storedError] = await Promise.all([
        getSessionValue<Partial<CachedToken>>(cachedTokenStorageKey),
        getSessionValue<string>(lastErrorStorageKey)
      ]);

      this.cachedToken = isCachedToken(storedToken)
        && !hasLegacyRefreshToken(storedToken)
        && !isExpired(storedToken.expiresOn)
        ? storedToken
        : null;
      this.lastError = typeof storedError === "string" && storedError.length > 0 ? storedError : null;
      if (!this.cachedToken && storedToken) {
        await removeSessionValue(cachedTokenStorageKey);
      }
    } finally {
      this.hydrated = true;
      this.hydrationPromise = null;
    }
  }

  private async runAuthorizationCodeFlow(
    config: BrowserExtensionConfig,
    scopes: string[],
    options: AuthorizationCodeFlowOptions
  ): Promise<AccessToken> {
    const authorityBase = buildAuthorityBase(config);
    const redirectUri = chrome.identity.getRedirectURL("aad");
    const codeVerifier = createCodeVerifier();
    const codeChallenge = await createCodeChallenge(codeVerifier);

    const authorizationUrl = new URL(`${authorityBase}/oauth2/v2.0/authorize`);
    const authorizationParams = new URLSearchParams({
      client_id: config.clientId,
      response_type: "code",
      redirect_uri: redirectUri,
      response_mode: "query",
      scope: normalizeScopes(["openid", "profile", ...scopes]),
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      prompt: options.prompt
    });
    if (options.loginHint) {
      authorizationParams.set("login_hint", options.loginHint);
    }
    authorizationUrl.search = authorizationParams.toString();

    const redirectResponse = await launchAuthFlow(authorizationUrl.toString(), options.interactive);
    const redirectUrl = new URL(redirectResponse);
    const authError = redirectUrl.searchParams.get("error");
    if (authError) {
      const description = redirectUrl.searchParams.get("error_description") ?? authError;
      if (!options.interactive && isInteractiveRequiredCode(authError)) {
        throw new InteractiveSignInRequiredError();
      }

      throw new Error(`Entra sign-in failed: ${description}`);
    }

    const code = redirectUrl.searchParams.get("code");
    if (!code) {
      throw new Error("Entra sign-in did not return an authorization code.");
    }

    const tokenResponse = await fetch(`${authorityBase}/oauth2/v2.0/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: config.clientId,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        scope: normalizeScopes(["openid", "profile", ...scopes])
      })
    });

    const tokenJson = await tokenResponse.json() as TokenResponse;
    if (!tokenResponse.ok || !tokenJson.access_token) {
      const description = tokenJson.error_description ?? tokenJson.error ?? `${tokenResponse.status} ${tokenResponse.statusText}`;
      throw new Error(`Token exchange failed: ${description}`);
    }

    const expiresInSeconds = Number(tokenJson.expires_in ?? 3600);
    return {
      accessToken: tokenJson.access_token,
      expiresOn: new Date(Date.now() + (Number.isFinite(expiresInSeconds) ? expiresInSeconds : 3600) * 1000).toISOString()
    };
  }

  private async storeCachedToken(scopeKey: string, token: AccessToken): Promise<void> {
    this.cachedToken = {
      ...token,
      scopeKey
    };
    this.lastError = null;
    await setSessionValue(cachedTokenStorageKey, this.cachedToken);
    await removeSessionValue(lastErrorStorageKey);
  }

  private async clearCachedToken(): Promise<void> {
    this.cachedToken = null;
    await removeSessionValue(cachedTokenStorageKey);
  }

  private async storeLastError(message: string): Promise<void> {
    this.lastError = message;
    await setSessionValue(lastErrorStorageKey, message);
  }
}

function buildAuthorityBase(config: BrowserExtensionConfig): string {
  const authorityHost = config.authorityHost.trim().replace(/\/+$/, "");
  return authorityHost.endsWith(`/${config.tenantId}`)
    ? authorityHost
    : `${authorityHost}/${config.tenantId}`;
}

function createCodeVerifier(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function createCodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  return toBase64Url(new Uint8Array(digest));
}

async function launchAuthFlow(url: string, interactive: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow({ url, interactive }, (responseUrl) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        const runtimeMessage = runtimeError.message ?? "Identity flow failed.";
        reject(interactive || !isInteractiveRequiredMessage(runtimeMessage)
          ? new Error(runtimeMessage)
          : new InteractiveSignInRequiredError());
        return;
      }

      if (!responseUrl) {
        reject(new Error("Interactive auth flow did not return a redirect URL."));
        return;
      }

      resolve(responseUrl);
    });
  });
}

function ensureAuthConfig(config: BrowserExtensionConfig): void {
  const missingFields = getMissingAuthFields(config);
  if (missingFields.length > 0) {
    throw new Error(`Missing auth config: ${missingFields.join(", ")}.`);
  }
}

function getMissingAuthFields(config: BrowserExtensionConfig): string[] {
  const missingFields: string[] = [];

  if (!config.tenantId.trim()) {
    missingFields.push("Tenant ID");
  }

  if (!config.clientId.trim()) {
    missingFields.push("Client ID");
  }

  if (!config.authorityHost.trim()) {
    missingFields.push("Authority Host");
  }

  return missingFields;
}

function getPrimaryScopes(config: BrowserExtensionConfig): string[] {
  return config.metadataTransportMode === "FunctionCatalog"
    ? [`api://${config.clientId.trim()}/access_as_user`]
    : [keyVaultScope];
}

function normalizeScopes(scopes: string[]): string {
  return [...new Set(scopes.map((scope) => scope.trim()).filter((scope) => scope.length > 0))].join(" ");
}

function isExpired(expiresOn: string | undefined, bufferMs = 0): boolean {
  if (!expiresOn) {
    return true;
  }

  return Date.parse(expiresOn) <= Date.now() + bufferMs;
}

function isCachedToken(value: Partial<CachedToken> | undefined): value is CachedToken {
  return Boolean(
    value
    && typeof value.accessToken === "string"
    && typeof value.expiresOn === "string"
    && typeof value.scopeKey === "string"
  );
}

function hasLegacyRefreshToken(value: Partial<CachedToken> | undefined): boolean {
  return Boolean(value && "refreshToken" in value);
}

function isInteractiveRequiredCode(code: string): boolean {
  return ["interaction_required", "login_required", "consent_required"].includes(code);
}

function isInteractiveRequiredMessage(message: string): boolean {
  return /interaction required|requires user interaction|user interaction required|not granted or revoked/i.test(message);
}

function isInteractiveSignInRequired(error: unknown): boolean {
  return error instanceof InteractiveSignInRequiredError
    || (error instanceof Error && isInteractiveRequiredMessage(error.message));
}

async function getSessionValue<TValue>(key: string): Promise<TValue | undefined> {
  return new Promise((resolve, reject) => {
    chrome.storage.session.get([key], (items) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve(items[key] as TValue | undefined);
    });
  });
}

async function setSessionValue(key: string, value: unknown): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.storage.session.set({ [key]: value }, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

async function removeSessionValue(key: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.storage.session.remove(key, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}
