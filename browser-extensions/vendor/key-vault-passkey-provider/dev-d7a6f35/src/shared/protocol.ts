export const pageRequestSource = "kvpp-page-request";
export const extensionResponseSource = "kvpp-extension-response";
export const pageCancelSource = "kvpp-page-cancel";

export type WebAuthnOperation = "create" | "get";

export type SerializableDomException = {
  name: string;
  message: string;
};

export type BrowserExtensionConfig = {
  tenantId: string;
  clientId: string;
  authorityHost: string;
  keyVaultBaseUrl: string;
  signingKeyName: string;
  signingKeyType: "EC" | "EC-HSM";
  metadataWrappingKeyName: string;
  metadataTransportMode: "LocalCacheOnly" | "KeyVaultSecrets";
  metadataSecretPrefix: string;
};

export type LockReason = "idle" | "browser-start" | "manual-lock" | "manual-sign-out" | "token-expired";

export type UnlockOutcome = "unlocked" | "interactive-sign-in-required";

export type ExtensionState = {
  enabled: boolean;
  config: BrowserExtensionConfig;
  lockTimeoutMinutes: number;
  lockedAt: string | null;
  lastUnlockedAt: string | null;
  lastActivityAt: string | null;
  lockReason: LockReason | null;
  rememberedLoginHint: string | null;
  interactiveUnlockExpiresAt: string | null;
  lastInterceptedAt: string | null;
  lastOrigin: string | null;
};

export type MetadataSummary = {
  storedCredentialCount: number;
  relyingPartyCount: number;
  lastUpdatedAt: string | null;
};

export type CredentialSelectionOption = {
  credentialId: string;
  rpId: string;
  userName: string;
  userDisplayName: string;
};

export type StoredCredentialSummary = {
  recordId: string;
  credentialId: string;
  rpId: string;
  userName: string;
  userDisplayName: string;
  backendKind: string;
  createdAt: string;
  updatedAt: string;
  signCount: number;
  state: "pending" | "active" | "disabled" | "deleting" | "deleted";
};

export type SerializedAttestationResponse = {
  kind: "attestation";
  clientDataJSON: string;
  attestationObject: string;
  authenticatorData: string;
  publicKeyAlgorithm: number;
  publicKey: string;
  transports: AuthenticatorTransport[];
};

export type SerializedAssertionResponse = {
  kind: "assertion";
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle: string | null;
};

export type SerializedPublicKeyCredential = {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: AuthenticatorAttachment | null;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  response: SerializedAttestationResponse | SerializedAssertionResponse;
};

export type BrowserAuthStatus = {
  mode: "local-only" | "not-configured" | "signed-out" | "signed-in";
  expiresOn: string | null;
  message: string | null;
};

export type PinUvStatus = {
  isConfigured: boolean;
  verificationMode: "local-pin";
  protectionMode: "browser-local-wrap" | "key-vault-wrap";
  lastUpdatedAt: string | null;
};

export type CeremonyAuthorizationSessionView = {
  sessionId: string;
  ceremonyId: string;
  operation: WebAuthnOperation;
  rpId: string;
  origin: string;
  topOrigin: string | null;
  accountName: string | null;
  credentialOptions: CredentialSelectionOption[];
  expiresAt: string;
};

export type WebAuthnClientData = {
  origin: string;
  crossOrigin: boolean;
  topOrigin: string | null;
};

export type SerializedPublicKeyCredentialDescriptor = Omit<PublicKeyCredentialDescriptor, "id"> & {
  id: string;
};

export type SerializedPublicKeyCredentialUserEntity = Omit<PublicKeyCredentialUserEntity, "id"> & {
  id: string;
};

export type SerializedCredentialCreationOptions = Omit<CredentialCreationOptions, "publicKey"> & {
  publicKey: Omit<PublicKeyCredentialCreationOptions, "challenge" | "user" | "excludeCredentials"> & {
    challenge: string;
    user: SerializedPublicKeyCredentialUserEntity;
    excludeCredentials?: SerializedPublicKeyCredentialDescriptor[];
  };
};

export type SerializedCredentialRequestOptions = Omit<CredentialRequestOptions, "publicKey"> & {
  publicKey: Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
    challenge: string;
    allowCredentials?: SerializedPublicKeyCredentialDescriptor[];
  };
};

export type SerializedCredentialOptions = SerializedCredentialCreationOptions | SerializedCredentialRequestOptions;

export type PageRequestMessage = {
  source: typeof pageRequestSource;
  requestId: string;
  operation: WebAuthnOperation;
  options: CredentialCreationOptions | CredentialRequestOptions;
};

export type PageCancelMessage = {
  source: typeof pageCancelSource;
  requestId: string;
};

export type PageBridgeMessage = PageRequestMessage | PageCancelMessage;

export type PageResponseMessage =
  | {
      source: typeof extensionResponseSource;
      requestId: string;
      action: "complete";
      credential: SerializedPublicKeyCredential;
    }
  | {
      source: typeof extensionResponseSource;
      requestId: string;
      action: "fallback";
      reason: string;
    }
  | {
      source: typeof extensionResponseSource;
      requestId: string;
      action: "reject";
      error: SerializableDomException;
    };

export type RuntimeRequest =
  | { kind: "get-state" }
  | { kind: "get-auth-status" }
  | { kind: "begin-sign-in" }
  | { kind: "lock-extension" }
  | { kind: "unlock-extension"; pin: string }
  | { kind: "sign-out" }
  | { kind: "get-metadata-summary" }
  | { kind: "get-stored-credentials" }
  | { kind: "set-stored-credential-enabled"; recordId: string; enabled: boolean }
  | { kind: "delete-stored-credential"; recordId: string }
  | { kind: "get-pin-uv-status" }
  | { kind: "set-pin-uv"; newPin: string; currentPin?: string }
  | { kind: "remove-pin-uv"; currentPin: string }
  | { kind: "get-ceremony-authorization-session"; sessionId: string }
  | { kind: "approve-ceremony-authorization-session"; sessionId: string; credentialId?: string }
  | { kind: "cancel-ceremony-authorization-session"; sessionId: string }
  | { kind: "set-enabled"; enabled: boolean }
  | { kind: "save-config"; config: BrowserExtensionConfig; lockTimeoutMinutes?: number }
  | { kind: "cancel-webauthn-request"; requestId: string; origin: string }
  | { kind: "webauthn-request"; requestId: string; operation: WebAuthnOperation; clientData: WebAuthnClientData; options: SerializedCredentialOptions };

export type RuntimeResponse =
  | { ok: true; state: ExtensionState }
  | { ok: true; state: ExtensionState; interactiveUnlockAllowed: boolean }
  | { ok: true; authStatus: BrowserAuthStatus }
  | { ok: true; state: ExtensionState; authStatus: BrowserAuthStatus; unlockOutcome: UnlockOutcome }
  | { ok: true; state: ExtensionState; authStatus: BrowserAuthStatus; locked: boolean }
  | { ok: true; summary: MetadataSummary }
  | { ok: true; storedCredentials: StoredCredentialSummary[] }
  | { ok: true; pinUvStatus: PinUvStatus }
  | { ok: true; ceremonyAuthorizationSession: CeremonyAuthorizationSessionView }
  | { ok: true; approved: boolean }
  | { ok: true; cancelled: boolean }
  | { ok: true; credential: SerializedPublicKeyCredential }
  | { ok: true; action: "fallback"; reason: string }
  | { ok: false; error: SerializableDomException };

export const defaultExtensionState: ExtensionState = {
  enabled: false,
  config: {
    tenantId: "",
    clientId: "",
    authorityHost: "https://login.microsoftonline.com",
    keyVaultBaseUrl: "",
    signingKeyName: "passkey-signing-key",
    signingKeyType: "EC",
    metadataWrappingKeyName: "passkey-metadata-wrap-key",
    metadataTransportMode: "KeyVaultSecrets",
    metadataSecretPrefix: "kvpp-md"
  },
  lockTimeoutMinutes: 15,
  lockedAt: null,
  lastUnlockedAt: null,
  lastActivityAt: null,
  lockReason: null,
  rememberedLoginHint: null,
  interactiveUnlockExpiresAt: null,
  lastInterceptedAt: null,
  lastOrigin: null
};
