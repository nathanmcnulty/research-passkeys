import {
  fromBase64Url,
} from "./shared/base64url";
import {
  extensionResponseSource,
  pageCancelSource,
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
  const { signal: _signal, ...relayOptions } = options;
  const request: PageRequestMessage = {
    source: pageRequestSource,
    requestId,
    operation,
    options: relayOptions as TOptions
  };

  const timeoutMs = resolveOperationTimeout(options);
  const requestSummary = operation === "create"
    ? summarizeCreateOptions(options)
    : summarizeGetOptions(options);
  console.info(`[kvpp] ${operation} intercept start origin=${clientData.origin} timeoutMs=${timeoutMs} details=${JSON.stringify(requestSummary)}`);

  const response = await waitForResponse(requestId, timeoutMs, options.signal, () => {
    window.postMessage(request, window.location.origin);
  });

  if (response.action === "fallback") {
    console.info(`[kvpp] ${operation} intercept fallback reason=${response.reason}`);
    return nativeHandler(options);
  }

  if (response.action === "complete") {
    const completionSummary = summarizeCredentialResponse(response.credential);
    console.info(`[kvpp] ${operation} intercept complete credentialId=${response.credential.id} details=${JSON.stringify(completionSummary)}`);
    return reconstructPublicKeyCredential(response.credential);
  }

  console.info(`[kvpp] ${operation} intercept reject name=${response.error.name} message=${response.error.message}`);
  throw new DOMException(response.error.message, response.error.name);
}

function waitForResponse(
  requestId: string,
  timeoutMs: number,
  signal: AbortSignal | undefined,
  send: () => void
): Promise<PageResponseMessage> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(toAbortException(signal));
      return;
    }

    const sendCancellation = () => {
      window.postMessage({ source: pageCancelSource, requestId }, window.location.origin);
    };
    const cleanup = () => {
      window.clearTimeout(timeout);
      window.removeEventListener("message", listener);
      signal?.removeEventListener("abort", abortListener);
    };
    const abortListener = () => {
      sendCancellation();
      cleanup();
      reject(toAbortException(signal!));
    };

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

    const timeout = window.setTimeout(() => {
      sendCancellation();
      cleanup();
      reject(new DOMException("Extension did not respond before timeout.", "TimeoutError"));
    }, timeoutMs);

    window.addEventListener("message", listener);
    signal?.addEventListener("abort", abortListener, { once: true });
    send();
  });
}

function toAbortException(signal: AbortSignal): DOMException {
  return signal.reason instanceof DOMException
    ? signal.reason
    : new DOMException("The WebAuthn request was aborted.", "AbortError");
}

function resolveOperationTimeout(options: CredentialCreationOptions | CredentialRequestOptions): number {
  const publicKey = options.publicKey;
  const requestedTimeout = typeof publicKey?.timeout === "number" && Number.isFinite(publicKey.timeout)
    ? publicKey.timeout
    : 120000;

  return Math.max(1000, requestedTimeout);
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
