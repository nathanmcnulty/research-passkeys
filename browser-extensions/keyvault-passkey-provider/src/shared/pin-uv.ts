import { fromBase64Url, toBase64Url } from "./base64url";
import { BrowserLocalMetadataKeyProtector, KeyVaultMetadataKeyProtector, type MetadataKeyProtector, type ProtectedContentKey } from "./metadata-key-protector";
import type { KeyVaultClient } from "./key-vault-client";
import type { PinUvStatus } from "./protocol";

const pinUvStateStorageKey = "kvpp.pinUvState";
const pinUvMinLength = 6;
const pinUvPbkdf2Iterations = 310000;

type StoredPinUvState = {
  version: 1;
  iterations: number;
  salt: string;
  hash: string;
  createdAt: string;
  updatedAt: string;
};

type StoredPinUvEnvelope = {
  version: 2 | 3;
  verificationMode: "local-pin";
  protectedContentKey: ProtectedContentKey;
  iv: string;
  ciphertext: string;
  localVerifier?: EncryptedStoredPinUvVerifierState;
  createdAt: string;
  updatedAt: string;
};

type EncryptedStoredPinUvVerifierState = {
  protectedContentKey: ProtectedContentKey;
  iv: string;
  ciphertext: string;
};

type StoredPinUvVerifierState = {
  version: 1;
  iterations: number;
  salt: string;
  hash: string;
  createdAt: string;
  updatedAt: string;
};

export type PinUvContext = {
  keyVaultClient?: KeyVaultClient;
  requireKeyVaultProtection?: boolean;
};

export async function getPinUvStatus(context: PinUvContext = {}): Promise<PinUvStatus> {
  const state = await getStoredPinUvEnvelope();
  const usableState = isPinUvStateUsable(state, context) ? state : null;
  return {
    isConfigured: Boolean(usableState),
    verificationMode: "local-pin",
    protectionMode: usableState
      ? getPinUvProtectionMode(usableState)
      : context.requireKeyVaultProtection
        ? "key-vault-wrap"
        : "browser-local-wrap",
    lastUpdatedAt: usableState?.updatedAt ?? null
  };
}

export async function hasConfiguredPinUv(context: PinUvContext = {}): Promise<boolean> {
  return isPinUvStateUsable(await getStoredPinUvEnvelope(), context);
}

export async function setPinUv(newPin: string, currentPin?: string, context: PinUvContext = {}): Promise<PinUvStatus> {
  assertValidPin(newPin);

  const existing = await getStoredPinUvVerifierState(context);
  if (existing) {
    if (!currentPin || !(await verifyPinAgainstState(existing, currentPin))) {
      throw new DOMException("The current PIN is incorrect.", "NotAllowedError");
    }
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePinHash(newPin, salt, pinUvPbkdf2Iterations);
  const now = new Date().toISOString();
  const nextState: StoredPinUvState = {
    version: 1,
    iterations: pinUvPbkdf2Iterations,
    salt: toBase64Url(salt),
    hash: toBase64Url(hash),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now
  };

  const protector = resolveProtector(context);
  await setInLocalStorage(pinUvStateStorageKey, await protectPinUvState(nextState, protector));
  return getPinUvStatus(context);
}

export async function removePinUv(currentPin: string, context: PinUvContext = {}): Promise<PinUvStatus> {
  const existing = await getStoredPinUvVerifierState(context);
  if (!existing) {
    return getPinUvStatus(context);
  }

  if (!(await verifyPinAgainstState(existing, currentPin))) {
    throw new DOMException("The current PIN is incorrect.", "NotAllowedError");
  }

  await removeFromLocalStorage(pinUvStateStorageKey);
  return getPinUvStatus(context);
}

export async function verifyPinUv(pin: string, context: PinUvContext = {}): Promise<boolean> {
  const state = await getStoredPinUvVerifierState(context);
  if (!state) {
    throw new DOMException("No PIN is configured for user verification.", "NotSupportedError");
  }

  return verifyPinAgainstState(state, pin);
}

export async function resetPinUvState(): Promise<void> {
  await removeFromLocalStorage(pinUvStateStorageKey);
}

export async function ensurePinUvLocalVerifier(context: PinUvContext = {}): Promise<void> {
  const envelope = await getStoredPinUvEnvelope();
  if (!envelope || envelope.localVerifier) {
    return;
  }

  const verifierState = await getStoredPinUvVerifierState(context);
  if (!verifierState) {
    return;
  }

  await setInLocalStorage(pinUvStateStorageKey, {
    ...envelope,
    version: 3,
    localVerifier: await protectStoredPinUvVerifierState(verifierState, new BrowserLocalMetadataKeyProtector())
  } satisfies StoredPinUvEnvelope);
}

async function getStoredPinUvVerifierState(context: PinUvContext): Promise<StoredPinUvVerifierState | null> {
  const state = await getStoredPinUvEnvelope();
  if (!isPinUvStateUsable(state, context) || !state) {
    return null;
  }

  const localVerifierState = await getLocalStoredPinUvVerifierState(state);
  if (localVerifierState) {
    return localVerifierState;
  }

  const protector = resolveStoredStateProtector(state, context);
  return decryptStoredPinUvVerifierState(
    {
      protectedContentKey: state.protectedContentKey,
      iv: state.iv,
      ciphertext: state.ciphertext
    },
    protector,
    state
  );
}

async function getStoredPinUvEnvelope(): Promise<StoredPinUvEnvelope | null> {
  const state = await getFromLocalStorage<Partial<StoredPinUvState | StoredPinUvEnvelope>>(pinUvStateStorageKey);
  if (!state || typeof state.version !== "number") {
    return null;
  }

  const localVerifier = parseEncryptedStoredPinUvVerifierState((state as Partial<StoredPinUvEnvelope>).localVerifier);

  if (
    (state.version === 2 || state.version === 3)
    && state.verificationMode === "local-pin"
    && typeof state.iv === "string"
    && typeof state.ciphertext === "string"
    && state.protectedContentKey
    && typeof state.protectedContentKey === "object"
    && typeof state.protectedContentKey.protectionMode === "string"
    && typeof state.protectedContentKey.value === "string"
  ) {
    return {
      version: state.version,
      verificationMode: "local-pin",
      protectedContentKey: {
        protectionMode: state.protectedContentKey.protectionMode,
        keyId: typeof state.protectedContentKey.keyId === "string" ? state.protectedContentKey.keyId : null,
        value: state.protectedContentKey.value
      },
      iv: state.iv,
      ciphertext: state.ciphertext,
      localVerifier,
      createdAt: typeof state.createdAt === "string" ? state.createdAt : new Date(0).toISOString(),
      updatedAt: typeof state.updatedAt === "string" ? state.updatedAt : new Date(0).toISOString()
    };
  }

  return null;
}

function isPinUvStateUsable(state: StoredPinUvEnvelope | null, context: PinUvContext): state is StoredPinUvEnvelope {
  if (!state) {
    return false;
  }

  if (context.requireKeyVaultProtection) {
    return state.protectedContentKey.protectionMode === "KeyVaultWrap";
  }

  return true;
}

async function protectPinUvState(state: StoredPinUvVerifierState, protector: MetadataKeyProtector): Promise<StoredPinUvEnvelope> {
  const encryptedState = await protectStoredPinUvVerifierState(state, protector);

  return {
    version: 3,
    verificationMode: "local-pin",
    protectedContentKey: encryptedState.protectedContentKey,
    iv: encryptedState.iv,
    ciphertext: encryptedState.ciphertext,
    localVerifier: await protectStoredPinUvVerifierState(state, new BrowserLocalMetadataKeyProtector()),
    createdAt: state.createdAt,
    updatedAt: state.updatedAt
  };
}

async function getLocalStoredPinUvVerifierState(state: StoredPinUvEnvelope): Promise<StoredPinUvVerifierState | null> {
  if (!state.localVerifier) {
    return null;
  }

  return decryptStoredPinUvVerifierState(state.localVerifier, new BrowserLocalMetadataKeyProtector(), state);
}

async function protectStoredPinUvVerifierState(
  state: StoredPinUvVerifierState,
  protector: MetadataKeyProtector
): Promise<EncryptedStoredPinUvVerifierState> {
  const contentKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(state));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toPlainArrayBuffer(iv) },
    contentKey,
    plaintext
  ));

  return {
    protectedContentKey: await protector.protectContentKey(contentKey),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext)
  };
}

async function decryptStoredPinUvVerifierState(
  encryptedState: EncryptedStoredPinUvVerifierState,
  protector: MetadataKeyProtector,
  fallbackState: Pick<StoredPinUvEnvelope, "createdAt" | "updatedAt">
): Promise<StoredPinUvVerifierState> {
  const contentKey = await protector.unprotectContentKey(encryptedState.protectedContentKey);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toPlainArrayBuffer(fromBase64Url(encryptedState.iv)) },
    contentKey,
    toPlainArrayBuffer(fromBase64Url(encryptedState.ciphertext))
  );
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Partial<StoredPinUvVerifierState>;
  if (parsed.version !== 1 || typeof parsed.salt !== "string" || typeof parsed.hash !== "string") {
    throw new DOMException("The stored PIN verifier is invalid.", "InvalidStateError");
  }

  return {
    version: 1,
    iterations: typeof parsed.iterations === "number" ? parsed.iterations : pinUvPbkdf2Iterations,
    salt: parsed.salt,
    hash: parsed.hash,
    createdAt: typeof parsed.createdAt === "string" ? parsed.createdAt : fallbackState.createdAt,
    updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : fallbackState.updatedAt
  };
}

function parseEncryptedStoredPinUvVerifierState(value: unknown): EncryptedStoredPinUvVerifierState | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }

  const candidate = value as Partial<EncryptedStoredPinUvVerifierState>;
  if (
    !candidate.protectedContentKey
    || typeof candidate.protectedContentKey !== "object"
    || typeof candidate.protectedContentKey.protectionMode !== "string"
    || typeof candidate.protectedContentKey.value !== "string"
    || typeof candidate.iv !== "string"
    || typeof candidate.ciphertext !== "string"
  ) {
    return undefined;
  }

  return {
    protectedContentKey: {
      protectionMode: candidate.protectedContentKey.protectionMode,
      keyId: typeof candidate.protectedContentKey.keyId === "string" ? candidate.protectedContentKey.keyId : null,
      value: candidate.protectedContentKey.value
    },
    iv: candidate.iv,
    ciphertext: candidate.ciphertext
  };
}

function resolveProtector(context: PinUvContext): MetadataKeyProtector {
  if (context.requireKeyVaultProtection) {
    if (!context.keyVaultClient) {
      throw new DOMException("Sign in to Key Vault before setting or rotating the extension PIN.", "NotAllowedError");
    }

    return new KeyVaultMetadataKeyProtector(context.keyVaultClient);
  }

  return new BrowserLocalMetadataKeyProtector();
}

function resolveStoredStateProtector(
  state: StoredPinUvEnvelope,
  context: PinUvContext
): MetadataKeyProtector {
  if (context.requireKeyVaultProtection && state.protectedContentKey.protectionMode !== "KeyVaultWrap") {
    throw new DOMException("Set the extension PIN after Key Vault sign-in so it can be protected by Key Vault.", "NotSupportedError");
  }

  if (state.protectedContentKey.protectionMode === "KeyVaultWrap") {
    if (!context.keyVaultClient) {
      throw new DOMException("Key Vault sign-in is required before the extension can verify the configured PIN.", "NotAllowedError");
    }

    return new KeyVaultMetadataKeyProtector(context.keyVaultClient);
  }

  return new BrowserLocalMetadataKeyProtector();
}

function getPinUvProtectionMode(state: StoredPinUvEnvelope): PinUvStatus["protectionMode"] {
  return state.protectedContentKey.protectionMode === "KeyVaultWrap"
    ? "key-vault-wrap"
    : "browser-local-wrap";
}

async function verifyPinAgainstState(state: StoredPinUvState, pin: string): Promise<boolean> {
  const salt = fromBase64Url(state.salt);
  const expected = fromBase64Url(state.hash);
  const actual = await derivePinHash(pin, salt, state.iterations);
  return constantTimeEqual(actual, expected);
}

async function derivePinHash(pin: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  assertValidPin(pin);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    hash: "SHA-256",
    salt: toPlainArrayBuffer(salt),
    iterations
  }, material, 256);
  return new Uint8Array(bits);
}

async function getFromLocalStorage<TValue>(key: string): Promise<TValue | undefined> {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (items: Record<string, unknown>) => resolve(items[key] as TValue | undefined));
  });
}

async function setInLocalStorage(key: string, value: unknown): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [key]: value }, () => resolve());
  });
}

async function removeFromLocalStorage(key: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.remove(key, () => resolve());
  });
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }

  return difference === 0;
}

function assertValidPin(pin: string): void {
  if (pin.length < pinUvMinLength) {
    throw new DOMException(`PIN must be at least ${pinUvMinLength} characters long.`, "TypeError");
  }

  if (!/\S/.test(pin)) {
    throw new DOMException("PIN cannot be blank.", "TypeError");
  }
}

function toPlainArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}
