import {
  fromBase64Url,
} from "./shared/base64url";
import {
  type CredentialSelectionOption,
  extensionResponseSource,
  pageRequestSource,
  type PageRequestMessage,
  type PageResponseMessage,
  type SerializedPublicKeyCredential,
  type WebAuthnClientData,
  type WebAuthnOperation
} from "./shared/protocol";

const nativeCreate = navigator.credentials.create.bind(navigator.credentials);
const nativeGet = navigator.credentials.get.bind(navigator.credentials);

navigator.credentials.create = async function create(options?: CredentialCreationOptions): Promise<Credential | null> {
  if (!options?.publicKey) {
    return nativeCreate(options);
  }

  return dispatchIntercept("create", options, (nextOptions) => nativeCreate(nextOptions));
};

navigator.credentials.get = async function get(options?: CredentialRequestOptions): Promise<Credential | null> {
  if (!options?.publicKey) {
    return nativeGet(options);
  }

  return dispatchIntercept("get", options, (nextOptions) => nativeGet(nextOptions));
};

async function dispatchIntercept<TOptions extends CredentialCreationOptions | CredentialRequestOptions>(
  operation: WebAuthnOperation,
  options: TOptions,
  nativeHandler: (options: TOptions) => Promise<Credential | null>
): Promise<Credential | null> {
  const requestId = crypto.randomUUID();
  const clientData = describeClientData();
  const request: PageRequestMessage = {
    source: pageRequestSource,
    requestId,
    operation,
    clientData,
    options
  };

  const timeoutMs = resolveOperationTimeout(options);
  const requestSummary = operation === "create"
    ? summarizeCreateOptions(options)
    : summarizeGetOptions(options);
  console.info(`[kvpp] ${operation} intercept start origin=${clientData.origin} timeoutMs=${timeoutMs} details=${JSON.stringify(requestSummary)}`);

  const response = await waitForResponse(requestId, timeoutMs, () => {
    window.postMessage(request, window.location.origin);
  });

  if (response.action === "fallback") {
    console.info(`[kvpp] ${operation} intercept fallback reason=${response.reason}`);
    return nativeHandler(options);
  }

  if (response.action === "select-account") {
    console.info(`[kvpp] ${operation} intercept select-account options=${response.options.length}`);
    const selected = await promptForCredentialSelection(response.options);
    if (!selected) {
      console.info(`[kvpp] ${operation} intercept selection canceled`);
      throw new DOMException("User canceled account selection.", "NotAllowedError");
    }

    console.info(`[kvpp] ${operation} intercept replay selectedCredentialId=${selected.credentialId}`);
    const replayOptions = cloneCredentialOptionsWithSelection(options, selected);
    return dispatchIntercept(operation, replayOptions, nativeHandler);
  }

  if (response.action === "complete") {
    const completionSummary = summarizeCredentialResponse(response.credential);
    console.info(`[kvpp] ${operation} intercept complete credentialId=${response.credential.id} details=${JSON.stringify(completionSummary)}`);
    return reconstructPublicKeyCredential(response.credential);
  }

  console.info(`[kvpp] ${operation} intercept reject name=${response.error.name} message=${response.error.message}`);
  throw new DOMException(response.error.message, response.error.name);
}

function waitForResponse(requestId: string, timeoutMs: number, send: () => void): Promise<PageResponseMessage> {
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      cleanup();
      reject(new DOMException("Extension did not respond before timeout.", "TimeoutError"));
    }, timeoutMs);

    const listener = (event: MessageEvent<PageResponseMessage>) => {
      if (event.source !== window) {
        return;
      }

      if (event.data?.source !== extensionResponseSource || event.data.requestId !== requestId) {
        return;
      }

      cleanup();
      resolve(event.data);
    };

    const cleanup = () => {
      window.clearTimeout(timeout);
      window.removeEventListener("message", listener);
    };

    window.addEventListener("message", listener);
    send();
  });
}

function resolveOperationTimeout(options: CredentialCreationOptions | CredentialRequestOptions): number {
  const publicKey = options.publicKey;
  const requestedTimeout = typeof publicKey?.timeout === "number" && Number.isFinite(publicKey.timeout)
    ? publicKey.timeout
    : 120000;

  return Math.max(1000, requestedTimeout);
}

async function promptForCredentialSelection(options: CredentialSelectionOption[]): Promise<CredentialSelectionOption | null> {
  if (options.length === 1) {
    return options[0] ?? null;
  }

  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.setAttribute("role", "presentation");
    Object.assign(overlay.style, {
      position: "fixed",
      inset: "0",
      background: "rgba(17, 24, 39, 0.48)",
      backdropFilter: "blur(4px)",
      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "16px"
    } satisfies Partial<CSSStyleDeclaration>);

    const panel = document.createElement("section");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.setAttribute("aria-label", "Choose passkey account");
    Object.assign(panel.style, {
      width: "min(420px, 100%)",
      maxHeight: "min(70vh, 520px)",
      overflow: "auto",
      borderRadius: "20px",
      border: "1px solid rgba(148, 163, 184, 0.3)",
      background: "linear-gradient(180deg, rgba(255,255,255,0.98), rgba(248,250,252,0.98))",
      boxShadow: "0 32px 80px rgba(15, 23, 42, 0.26)",
      color: "#0f172a",
      fontFamily: '"Segoe UI", "Aptos", sans-serif',
      padding: "20px"
    } satisfies Partial<CSSStyleDeclaration>);

    const title = document.createElement("h2");
    title.textContent = "Choose a passkey account";
    Object.assign(title.style, {
      margin: "0 0 8px",
      fontSize: "20px"
    } satisfies Partial<CSSStyleDeclaration>);

    const subtitle = document.createElement("p");
    subtitle.textContent = "This site requested a discoverable credential. Select which stored account should answer the challenge.";
    Object.assign(subtitle.style, {
      margin: "0 0 16px",
      color: "#475569",
      fontSize: "14px",
      lineHeight: "1.45"
    } satisfies Partial<CSSStyleDeclaration>);

    const list = document.createElement("div");
    Object.assign(list.style, {
      display: "grid",
      gap: "10px"
    } satisfies Partial<CSSStyleDeclaration>);

    const cleanup = (value: CredentialSelectionOption | null) => {
      window.removeEventListener("keydown", onKeyDown, true);
      overlay.remove();
      resolve(value);
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        cleanup(null);
      }
    };

    for (const option of options) {
      const button = document.createElement("button");
      button.type = "button";
      Object.assign(button.style, {
        display: "grid",
        gap: "4px",
        textAlign: "left",
        width: "100%",
        border: "1px solid rgba(148, 163, 184, 0.36)",
        borderRadius: "16px",
        background: "rgba(255,255,255,0.96)",
        padding: "14px 16px",
        cursor: "pointer"
      } satisfies Partial<CSSStyleDeclaration>);

      const displayName = document.createElement("strong");
      displayName.textContent = option.userDisplayName || option.userName;
      displayName.style.fontSize = "14px";

      const userName = document.createElement("span");
      userName.textContent = option.userName;
      Object.assign(userName.style, {
        color: "#334155",
        fontSize: "13px"
      } satisfies Partial<CSSStyleDeclaration>);

      const rpId = document.createElement("span");
      rpId.textContent = option.rpId;
      Object.assign(rpId.style, {
        color: "#64748b",
        fontSize: "12px"
      } satisfies Partial<CSSStyleDeclaration>);

      button.append(displayName, userName, rpId);
      button.addEventListener("click", () => cleanup(option));
      list.appendChild(button);
    }

    const footer = document.createElement("div");
    Object.assign(footer.style, {
      display: "flex",
      justifyContent: "flex-end",
      marginTop: "14px"
    } satisfies Partial<CSSStyleDeclaration>);

    const cancelButton = document.createElement("button");
    cancelButton.type = "button";
    cancelButton.textContent = "Cancel";
    Object.assign(cancelButton.style, {
      border: "0",
      borderRadius: "999px",
      background: "rgba(15, 23, 42, 0.08)",
      color: "#0f172a",
      padding: "10px 16px",
      cursor: "pointer"
    } satisfies Partial<CSSStyleDeclaration>);
    cancelButton.addEventListener("click", () => cleanup(null));
    footer.appendChild(cancelButton);

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        cleanup(null);
      }
    });

    panel.append(title, subtitle, list, footer);
    overlay.appendChild(panel);
    window.addEventListener("keydown", onKeyDown, true);
    (document.body || document.documentElement).appendChild(overlay);
  });
}

function cloneCredentialOptionsWithSelection<TOptions extends CredentialCreationOptions | CredentialRequestOptions>(
  options: TOptions,
  selected: CredentialSelectionOption
): TOptions {
  if (!options.publicKey || "pubKeyCredParams" in options.publicKey || "rp" in options.publicKey || "user" in options.publicKey) {
    throw new DOMException("Unable to replay WebAuthn selection for this request shape.", "TypeError");
  }

  const selectedId = toArrayBuffer(fromBase64Url(selected.credentialId));
  const nextOptions: CredentialRequestOptions = {
    ...options,
    publicKey: {
      ...options.publicKey,
      allowCredentials: [{
        type: "public-key",
        id: selectedId
      }]
    }
  };

  return nextOptions as TOptions;
}

function describeClientData(): WebAuthnClientData {
  const origin = window.location.origin;
  const ancestorOrigins = readAncestorOrigins();
  if (ancestorOrigins.length > 0) {
    const topOrigin = ancestorOrigins[ancestorOrigins.length - 1] ?? null;
    const crossOrigin = ancestorOrigins.some((value) => value !== origin);
    return {
      origin,
      crossOrigin,
      topOrigin: crossOrigin ? topOrigin : null
    };
  }

  if (window.top === window) {
    return {
      origin,
      crossOrigin: false,
      topOrigin: null
    };
  }

  try {
    const topOrigin = window.top?.location.origin ?? null;
    return {
      origin,
      crossOrigin: topOrigin !== null && topOrigin !== origin,
      topOrigin: topOrigin !== null && topOrigin !== origin ? topOrigin : null
    };
  } catch {
    return {
      origin,
      crossOrigin: true,
      topOrigin: null
    };
  }
}

function readAncestorOrigins(): string[] {
  const origins: string[] = [];
  const ancestorOrigins = window.location.ancestorOrigins;
  for (let index = 0; index < ancestorOrigins.length; index += 1) {
    const value = ancestorOrigins.item(index);
    if (value) {
      origins.push(value);
    }
  }

  return origins;
}

function summarizeCreateOptions(options: CredentialCreationOptions | CredentialRequestOptions): Record<string, unknown> {
  const publicKey = options.publicKey;
  if (!publicKey || !("rp" in publicKey) || !("user" in publicKey)) {
    return {};
  }

  return {
    rpId: publicKey.rp.id,
    attestation: publicKey.attestation ?? "none",
    authenticatorAttachment: publicKey.authenticatorSelection?.authenticatorAttachment ?? null,
    residentKey: publicKey.authenticatorSelection?.residentKey ?? null,
    requireResidentKey: publicKey.authenticatorSelection?.requireResidentKey ?? null,
    userVerification: publicKey.authenticatorSelection?.userVerification ?? null,
    extensions: summarizeExtensions(publicKey.extensions)
  };
}

function summarizeGetOptions(options: CredentialCreationOptions | CredentialRequestOptions): Record<string, unknown> {
  const publicKey = options.publicKey;
  if (!publicKey || !("allowCredentials" in publicKey || "rpId" in publicKey)) {
    return {};
  }

  return {
    rpId: publicKey.rpId ?? null,
    allowCredentialsCount: publicKey.allowCredentials?.length ?? 0,
    userVerification: publicKey.userVerification ?? null,
    extensions: summarizeExtensions(publicKey.extensions)
  };
}

function summarizeExtensions(extensions: AuthenticationExtensionsClientInputs | undefined): Record<string, unknown> | null {
  if (!extensions) {
    return null;
  }

  return Object.fromEntries(Object.entries(extensions).map(([key, value]) => [key, normalizeExtensionValue(value)]));
}

function normalizeExtensionValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (ArrayBuffer.isView(value)) {
    return { kind: value.constructor.name, byteLength: value.byteLength };
  }

  if (value instanceof ArrayBuffer) {
    return { kind: "ArrayBuffer", byteLength: value.byteLength };
  }

  if (Array.isArray(value)) {
    return value.map((entry) => normalizeExtensionValue(entry));
  }

  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, normalizeExtensionValue(entry)]));
  }

  return value;
}

function summarizeCredentialResponse(credential: SerializedPublicKeyCredential): Record<string, unknown> {
  if (credential.response.kind === "attestation") {
    return {
      kind: credential.response.kind,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.clientExtensionResults,
      authenticatorDataFlags: readAuthenticatorFlags(credential.response.authenticatorData),
      publicKeyAlgorithm: credential.response.publicKeyAlgorithm,
      transports: credential.response.transports
    };
  }

  return {
    kind: credential.response.kind,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.clientExtensionResults,
    authenticatorDataFlags: readAuthenticatorFlags(credential.response.authenticatorData)
  };
}

function readAuthenticatorFlags(authenticatorDataBase64Url: string): Record<string, boolean> | null {
  const authenticatorData = fromBase64Url(authenticatorDataBase64Url);
  if (authenticatorData.length < 33) {
    return null;
  }

  const flags = authenticatorData[32];
  return {
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
    attestedCredentialData: (flags & 0x40) !== 0,
    extensionDataIncluded: (flags & 0x80) !== 0
  };
}

function reconstructPublicKeyCredential(credential: SerializedPublicKeyCredential): PublicKeyCredential {
  const rawId = toArrayBuffer(fromBase64Url(credential.rawId));

  if (credential.response.kind === "attestation") {
    const response = credential.response;
    const attestationResponse = applyPrototype({
      clientDataJSON: toArrayBuffer(fromBase64Url(response.clientDataJSON)),
      attestationObject: toArrayBuffer(fromBase64Url(response.attestationObject)),
      getAuthenticatorData: () => toArrayBuffer(fromBase64Url(response.authenticatorData)),
      getPublicKey: () => toArrayBuffer(fromBase64Url(response.publicKey)),
      getPublicKeyAlgorithm: () => response.publicKeyAlgorithm,
      getTransports: () => response.transports
    }, globalThis.AuthenticatorAttestationResponse?.prototype) as AuthenticatorAttestationResponse;

    return applyPrototype({
      id: credential.id,
      rawId,
      response: attestationResponse,
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      getClientExtensionResults: () => credential.clientExtensionResults,
      toJSON: () => ({
        id: credential.id,
        rawId: credential.rawId,
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: credential.clientExtensionResults,
        response: {
          clientDataJSON: response.clientDataJSON,
          attestationObject: response.attestationObject,
          transports: response.transports,
          publicKeyAlgorithm: response.publicKeyAlgorithm,
          publicKey: response.publicKey,
          authenticatorData: response.authenticatorData
        }
      })
    }, globalThis.PublicKeyCredential?.prototype) as PublicKeyCredential;
  }

  const response = credential.response;
  const assertionResponse = applyPrototype({
    clientDataJSON: toArrayBuffer(fromBase64Url(response.clientDataJSON)),
    authenticatorData: toArrayBuffer(fromBase64Url(response.authenticatorData)),
    signature: toArrayBuffer(fromBase64Url(response.signature)),
    userHandle: response.userHandle ? toArrayBuffer(fromBase64Url(response.userHandle)) : null
  }, globalThis.AuthenticatorAssertionResponse?.prototype) as AuthenticatorAssertionResponse;

  return applyPrototype({
    id: credential.id,
    rawId,
    response: assertionResponse,
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    getClientExtensionResults: () => credential.clientExtensionResults,
    toJSON: () => ({
      id: credential.id,
      rawId: credential.rawId,
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.clientExtensionResults,
      response: {
          clientDataJSON: response.clientDataJSON,
          authenticatorData: response.authenticatorData,
          signature: response.signature,
          userHandle: response.userHandle
      }
    })
  }, globalThis.PublicKeyCredential?.prototype) as PublicKeyCredential;
}

function applyPrototype<T extends object>(value: T, prototype: object | undefined): T {
  if (!prototype) {
    return value;
  }

  try {
    Object.setPrototypeOf(value, prototype);
  }
  catch {
    // Some pages may freeze or wrap objects; keep the plain object shape as a fallback.
  }

  return value;
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}
