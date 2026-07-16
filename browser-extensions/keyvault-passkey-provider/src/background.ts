import "reflect-metadata";
import { BrowserEntraTokenBroker } from "./shared/browser-auth";
import { getDomain, parse } from "tldts";
import * as x509 from "@peculiar/x509";
import { fromBase64Url, toBase64Url } from "./shared/base64url";
import { getCachedMetadataSummary } from "./shared/metadata-cache-store";
import type { FunctionBrowserContext } from "./shared/function-catalog-client";
import { createMetadataEnvironment, deleteCredentialRecord, getMetadataSummary, loadCredentialRecords, saveCredentialRecord } from "./shared/metadata-store";
import type { BrowserStoredCredentialRecord } from "./shared/models";
import { defaultExtensionState, type BrowserAuthStatus, type CredentialSelectionOption, type ExtensionState, type LockReason, type PinUvSessionView, type RuntimeRequest, type RuntimeResponse, type SerializedPublicKeyCredential, type StoredCredentialSummary, type WebAuthnClientData, type WebAuthnOperation } from "./shared/protocol";
import { ensurePinUvLocalVerifier, getPinUvStatus, hasConfiguredPinUv, removePinUv, resetPinUvState, setPinUv, type PinUvContext, verifyPinUv } from "./shared/pin-uv";
import { evaluateSetupProgress, getSetupIncompleteMessage, isConfigReady } from "./shared/setup-state";
import { deserializeRuntimeCredentialOptions } from "./shared/runtime-credential-options";
import { clearLockState, ensureExtensionStateInitialized, loadExtensionState, resetLockStateTracking, saveExtensionState, setLockState, touchLastActivity, updateConfig, updateEnabled, updateInterceptTelemetry, updateInteractiveUnlockExpiresAt, updateLockTimeoutMinutes } from "./shared/storage";
import { buildAssertionAuthenticatorDataWithFlags, buildEcP256SubjectPublicKeyInfo, buildMakeCredentialAuthenticatorData, buildNoneAttestationObject, buildPackedAttestationObject } from "./shared/webauthn-data";

x509.cryptoProvider.set(globalThis.crypto);

const batchAttestationSubject = "CN=Batch Certificate, OU=Authenticator Attestation, O=Chromium, C=US";
const batchAttestationNotBefore = new Date("2017-07-14T02:40:00.000Z");
const batchAttestationNotAfter = new Date("2046-02-06T06:33:07.000Z");
const compatibilityPackedAttestationRpIds = new Set(["login.microsoft.com"]);
const compatibilityAuthenticatorAaguidHex = "33867143325B48D0ADFCE7AE975FE068";
const opaqueAuthenticatorAaguidHex = "00000000000000000000000000000000";

const tokenBroker = new BrowserEntraTokenBroker();
const createDebugPhaseStorageKey = "kvpp.debug.createPhase";
const createDebugStateStorageKey = "kvpp.debug.createState";
const getDebugStateStorageKey = "kvpp.debug.getState";
const pinUvSessionWindowMs = 2 * 60 * 1000;
const dynamicContentScriptId = "kvpp-webauthn-intercept";
const compatibilityUserAgentRuleIdBase = 1_000_000;

type CredentialSelectionDirective = {
  kind: "select-account";
  options: CredentialSelectionOption[];
};

type PendingPinUvSession = {
  view: PinUvSessionView;
  resolve: (verified: boolean) => void;
  timeoutHandle: number;
  windowId: number | null;
};

const pendingPinUvSessions = new Map<string, PendingPinUvSession>();

void syncDynamicContentScriptRegistration();
void syncActionPresentation();
void syncSidePanelBehavior();

chrome.runtime.onInstalled.addListener((details) => {
  void handleInstalled(details.reason);
});

chrome.runtime.onStartup.addListener(() => {
  void handleStartup();
  void syncSidePanelBehavior();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void removeCompatibilityUserAgentRule(tabId);
});

chrome.permissions.onAdded.addListener(() => {
  void syncDynamicContentScriptRegistration();
});

chrome.permissions.onRemoved.addListener(() => {
  void syncDynamicContentScriptRegistration();
});

chrome.windows.onRemoved.addListener((windowId) => {
  for (const session of pendingPinUvSessions.values()) {
    if (session.windowId === windowId) {
      settlePinUvSession(session.view.sessionId, false);
      break;
    }
  }
});

chrome.runtime.onMessage.addListener((message: RuntimeRequest, _sender, sendResponse: (response: RuntimeResponse) => void) => {
  void handleMessage(message)
    .then(sendResponse)
    .catch((error: unknown) => {
      sendResponse({ ok: false, error: serializeError(error) });
    });

  return true;
});

async function handleMessage(message: RuntimeRequest): Promise<RuntimeResponse> {
  switch (message.kind) {
    case "get-state": {
      const { state } = await resolveRuntimeContext();
      return { ok: true, state, interactiveUnlockAllowed: hasInteractiveUnlockPermission(state) };
    }
    case "set-enabled": {
      if (message.enabled) {
        const { state } = await resolveRuntimeContext();
        await ensureSetupComplete(state.config);
      }

      const state = await updateEnabled(message.enabled);
      await syncActionPresentation();
      return { ok: true, state };
    }
    case "get-auth-status": {
      const { state } = await resolveRuntimeContext();
      return { ok: true, authStatus: await tokenBroker.getHydratedStatus(state.config) };
    }
    case "begin-sign-in": {
      const { state, pinConfigured } = await resolveRuntimeContext();
      if (
        state.lockedAt
        && canUseLockedState(state.config, pinConfigured)
        && state.lockReason !== "token-expired"
        && !hasInteractiveUnlockPermission(state)
      ) {
        throw new DOMException("Unlock the extension PIN first. If the cached API session has expired, sign in again.", "NotAllowedError");
      }

      const authStatus = await tokenBroker.beginInteractiveSignIn(state.config);
      if (canUseLockedState(state.config, pinConfigured)) {
        await clearLockState();
        await clearInteractiveUnlockPermission();
      }
      await syncActionPresentation();
      return { ok: true, authStatus };
    }
    case "lock-extension": {
      const { state, pinConfigured } = await resolveRuntimeContext();
      if (!canUseLockedState(state.config, pinConfigured)) {
        throw new DOMException("Finish setup before locking the extension.", "NotAllowedError");
      }

      const lockedState = await enterLockedState("manual-lock");
      const authStatus = await tokenBroker.getHydratedStatus(lockedState.config);
      await syncActionPresentation();
      return { ok: true, state: lockedState, authStatus, locked: true };
    }
    case "unlock-extension": {
      const { state, pinConfigured } = await resolveRuntimeContext();
      if (!canUseLockedState(state.config, pinConfigured)) {
        throw new DOMException("Finish setup before unlocking the extension.", "NotAllowedError");
      }

      if (!state.lockedAt) {
        const authStatus = await tokenBroker.getHydratedStatus(state.config);
        return { ok: true, state, authStatus, unlockOutcome: "unlocked" };
      }

      const verified = await verifyPinForUnlock(state.config, message.pin);
      if (!verified) {
        throw new DOMException("The extension PIN is incorrect.", "NotAllowedError");
      }

      if (state.config.metadataTransportMode === "LocalCacheOnly") {
        const unlockedState = await clearLockState();
        await clearInteractiveUnlockPermission();
        const authStatus = await tokenBroker.getHydratedStatus(unlockedState.config);
        await touchLastActivity();
        await syncActionPresentation();
        return { ok: true, state: unlockedState, authStatus, unlockOutcome: "unlocked" };
      }

      const silentAuthStatus = await tokenBroker.beginSilentSignIn(state.config);
      if (!silentAuthStatus) {
        await armInteractiveUnlockPermission();
        const lockedState = await setLockState("token-expired");
        await syncActionPresentation();
        return {
          ok: true,
          state: lockedState,
          authStatus: await tokenBroker.getHydratedStatus(lockedState.config),
          unlockOutcome: "interactive-sign-in-required"
        };
      }

      const unlockedState = await clearLockState();
      await clearInteractiveUnlockPermission();
      await touchLastActivity();
      await syncActionPresentation();
      return { ok: true, state: unlockedState, authStatus: silentAuthStatus, unlockOutcome: "unlocked" };
    }
    case "sign-out": {
      const { state, pinConfigured } = await resolveRuntimeContext();
      await tokenBroker.clear();
      if (canUseLockedState(state.config, pinConfigured)) {
        await setLockState("manual-sign-out");
        await clearInteractiveUnlockPermission();
      } else if (state.enabled) {
        await updateEnabled(false);
      }

      await syncActionPresentation();
      return { ok: true, authStatus: await tokenBroker.getHydratedStatus(state.config) };
    }
    case "get-metadata-summary": {
      const { state } = await resolveRuntimeContext();
      const authStatus = await tokenBroker.getHydratedStatus(state.config);
      if (state.lockedAt || (state.config.metadataTransportMode === "KeyVaultSecrets" && authStatus.mode !== "signed-in")) {
        const summary = await getCachedMetadataSummary();
        return { ok: true, summary };
      }

      let summary: Awaited<ReturnType<typeof getCachedMetadataSummary>>;
      try {
        summary = await getMetadataSummary(createMetadataEnvironment(state.config, (scopes) => tokenBroker.acquireToken(state.config, scopes)));
      } catch {
        summary = await getCachedMetadataSummary();
      }

      return { ok: true, summary };
    }
    case "get-stored-credentials": {
      const { state } = await resolveRuntimeContext();
      if (state.lockedAt) {
        throw new DOMException("Unlock the extension before viewing stored passkeys.", "NotAllowedError");
      }

      const authStatus = await tokenBroker.getHydratedStatus(state.config);
      if (state.config.metadataTransportMode === "KeyVaultSecrets" && authStatus.mode !== "signed-in") {
        throw new DOMException("Sign in to Key Vault before viewing stored passkeys.", "NotAllowedError");
      }

      const environment = createMetadataEnvironment(state.config, (scopes) => tokenBroker.acquireToken(state.config, scopes));
      const records = await loadCredentialRecords(environment);
      return { ok: true, storedCredentials: records.map(toStoredCredentialSummary).sort(compareStoredCredentialSummaries) };
    }
    case "delete-stored-credential": {
      const { state } = await resolveRuntimeContext();
      if (state.lockedAt) {
        throw new DOMException("Unlock the extension before removing stored passkeys.", "NotAllowedError");
      }

      const authStatus = await tokenBroker.getHydratedStatus(state.config);
      if (state.config.metadataTransportMode === "KeyVaultSecrets" && authStatus.mode !== "signed-in") {
        throw new DOMException("Sign in to Key Vault before removing stored passkeys.", "NotAllowedError");
      }

      const environment = createMetadataEnvironment(state.config, (scopes) => tokenBroker.acquireToken(state.config, scopes));
      await deleteCredentialRecord(message.recordId, environment);
      const records = await loadCredentialRecords(environment);
      return { ok: true, storedCredentials: records.map(toStoredCredentialSummary).sort(compareStoredCredentialSummaries) };
    }
    case "open-stored-credential": {
      const { state } = await resolveRuntimeContext();
      if (state.lockedAt) {
        throw new DOMException("Unlock the extension before opening a passkey login.", "NotAllowedError");
      }
      if (state.config.metadataTransportMode !== "FunctionCatalog") {
        throw new DOMException("Context-aware login opening is available only in Function catalog mode.", "NotSupportedError");
      }

      const environment = createMetadataEnvironment(state.config, (scopes) => tokenBroker.acquireToken(state.config, scopes));
      if (!environment.developmentCatalog) {
        throw new DOMException("The Function catalog client is not configured.", "InvalidStateError");
      }
      const context = await environment.developmentCatalog.loadBrowserContext(message.recordId);
      const openedUrl = buildStoredCredentialLoginUrl(context);
      const requestDomains = context.provider === "entra"
        ? ["outlook.office.com", "outlook.office365.com", "outlook.cloud.microsoft", "login.microsoftonline.com", "login.microsoft.com"]
        : [context.rpId];
      const tab = await createCompatibilityTab();
      try {
        const userAgentApplied = context.userAgent
          ? await applyCompatibilityUserAgentRule(tab.id, context.userAgent, requestDomains)
          : false;
        await navigateTab(tab.id, openedUrl);
        return { ok: true, openedTabId: tab.id, openedUrl, userAgentApplied };
      } catch (error) {
        await chrome.tabs.remove(tab.id).catch(() => undefined);
        throw error;
      }
    }
    case "get-pin-uv-status": {
      const { state } = await resolveRuntimeContext();
      await tokenBroker.getHydratedStatus(state.config);
      return { ok: true, pinUvStatus: await getPinUvStatus(createPinUvContext(state.config)) };
    }
    case "set-pin-uv": {
      const { state } = await resolveRuntimeContext();
      const authStatus = await tokenBroker.getHydratedStatus(state.config);
      const pinContext = createPinUvContext(state.config);
      const pinWasConfigured = await hasConfiguredPinUv(pinContext);
      const setupWasComplete = evaluateSetupProgress(state.config, authStatus.mode, pinWasConfigured).isComplete;
      const pinUvStatus = await setPinUv(message.newPin, message.currentPin, pinContext);
      const setupIsComplete = evaluateSetupProgress(state.config, authStatus.mode, pinUvStatus.isConfigured).isComplete;

      if (!setupWasComplete && setupIsComplete) {
        await updateEnabled(true);
        await clearLockState();
      }

      await syncActionPresentation();
      return { ok: true, pinUvStatus };
    }
    case "remove-pin-uv": {
      const { state } = await resolveRuntimeContext();
      const pinUvStatus = await removePinUv(message.currentPin, createPinUvContext(state.config));
      await resetLockStateTracking();
      if (!pinUvStatus.isConfigured && state.enabled) {
        await updateEnabled(false);
      }

      await syncActionPresentation();
      return { ok: true, pinUvStatus };
    }
    case "get-pin-uv-session": {
      const session = pendingPinUvSessions.get(message.sessionId);
      if (!session) {
        throw new DOMException("The PIN verification request is no longer available.", "NotAllowedError");
      }

      return { ok: true, pinUvSession: session.view };
    }
    case "verify-pin-uv-session": {
      const verified = await verifyPinUvSession(message.sessionId, message.pin);
      return { ok: true, verified };
    }
    case "cancel-pin-uv-session": {
      cancelPinUvSession(message.sessionId);
      return { ok: true, cancelled: true };
    }
    case "save-config": {
      await updateConfig(message.config);
      if (message.lockTimeoutMinutes !== undefined) {
        await updateLockTimeoutMinutes(message.lockTimeoutMinutes);
      }
      await tokenBroker.clear();
      await resetLockStateTracking();
      const state = await updateEnabled(false);
      await syncDynamicContentScriptRegistration();
      await syncActionPresentation();
      return { ok: true, state };
    }
    case "webauthn-request": {
      const { state, authStatus, pinConfigured } = await resolveRuntimeContext();
      if (!state.enabled) {
        return { ok: true, action: "fallback", reason: "Extension intercept is disabled." };
      }

      const setupProgress = evaluateSetupProgress(state.config, authStatus.mode, pinConfigured);
      if (!canUseLockedState(state.config, pinConfigured) && !setupProgress.isComplete) {
        await updateEnabled(false);
        await syncActionPresentation();
        return { ok: true, action: "fallback", reason: getSetupIncompleteMessage(setupProgress, state.config) };
      }

      if (state.lockedAt) {
        return { ok: true, action: "fallback", reason: "Extension is locked. Unlock it from the side panel before using passkeys." };
      }

      const clientData = normalizeClientData(message.clientData);
      const options = deserializeRuntimeCredentialOptions(message.options);

      await updateInterceptTelemetry(clientData.origin);

      if (message.operation === "create" && state.config.metadataTransportMode === "FunctionCatalog") {
        return { ok: true, action: "fallback", reason: "Function-backed mode uses the browser authenticator for passkey registration." };
      }

      const credential = message.operation === "create"
        ? await handleCreateRequest(state.config, clientData, options)
        : await handleGetRequest(state.config, clientData, options);

      if (isSelectionDirective(credential)) {
        return { ok: true, action: "select-account", options: credential.options };
      }

      return { ok: true, credential };
    }
  }

  throw new Error(`Unhandled runtime message kind: ${(message as { kind: string }).kind}`);
}

async function handleCreateRequest(
  config: typeof defaultExtensionState.config,
  clientData: WebAuthnClientData,
  options: CredentialCreationOptions | CredentialRequestOptions
): Promise<SerializedPublicKeyCredential> {
  const publicKey = getCreationOptions(options);
  if (!publicKey) {
    throw new DOMException("Expected publicKey creation options.", "TypeError");
  }
  ensureEs256Supported(publicKey.pubKeyCredParams);

  const rpId = resolveEffectiveRpId(publicKey.rp?.id, clientData.origin);
  assertRpIdAllowedForOrigin(rpId, clientData.origin);
  const userVerified = await resolveUserVerification(config, publicKey.authenticatorSelection?.userVerification, {
    operation: "create",
    rpId,
    origin: clientData.origin
  });

  if (!publicKey.user?.id || !publicKey.user.name) {
    throw new DOMException("User information is required.", "TypeError");
  }

  const environment = createMetadataEnvironment(config, (scopes) => tokenBroker.acquireToken(config, scopes));
  const keyVaultClient = environment.keyVaultClient;
  await setCreateDebugPhase("load-records");
  await setCreateDebugState(null);
  const records = await loadCredentialRecords(environment);
  const excludedCredentialIds = new Set((publicKey.excludeCredentials ?? [])
    .map((descriptor: PublicKeyCredentialDescriptor) => descriptor.id)
    .filter((value): value is BufferSource => Boolean(value))
    .map((value) => toBase64Url(toUint8Array(value))));
  const matchedExcludedCredentialIds = records
    .map((record) => record.credentialId)
    .filter((credentialId) => excludedCredentialIds.has(credentialId));

  if (matchedExcludedCredentialIds.length > 0) {
    await setCreateDebugState({
      rpId,
      excludedCredentialIds: Array.from(excludedCredentialIds),
      matchedExcludedCredentialIds,
      storedCredentialIds: records.map((record) => record.credentialId)
    });
    await setCreateDebugPhase("duplicate-excluded-credential");
    throw new DOMException("The relying party excluded a passkey that is already stored locally. Delete the existing passkey or reauthenticate before retrying registration.", "InvalidStateError");
  }

  const credentialIdBytes = crypto.getRandomValues(new Uint8Array(32));
  const keyName = buildKeyName(config.signingKeyName);
  let createdKeyId: string | null = null;

  try {
    if (!keyVaultClient) {
      throw new DOMException("Local cache mode cannot create passkeys because it has no signing backend.", "NotSupportedError");
    }

    await setCreateDebugPhase("create-key");
    const key = await keyVaultClient.createEcP256Key(keyName, config.signingKeyType);
    createdKeyId = key.keyId;

    const clientDataJSON = buildClientDataJson("webauthn.create", publicKey.challenge, clientData);
    const extensionOutputs = buildCreateExtensionOutputs(publicKey);
    const authenticatorProfile = resolveAuthenticatorProfile(rpId);
    const authenticatorData = await buildMakeCredentialAuthenticatorData(
      rpId,
      credentialIdBytes,
      key.x,
      key.y,
      0,
      userVerified,
      false,
      false,
      extensionOutputs.authenticatorDataExtensions,
      authenticatorProfile.aaguidHex
    );
    const attestationObject = await buildAttestationObject(rpId, publicKey.attestation, authenticatorData, clientDataJSON);
    const record = buildStoredCredentialRecord(publicKey, rpId, credentialIdBytes, key.keyId);

    await setCreateDebugPhase("save-record");
    await saveCredentialRecord(record, environment);
    await setCreateDebugPhase("complete");

    return {
      id: record.credentialId,
      rawId: record.credentialId,
      type: "public-key",
      authenticatorAttachment: authenticatorProfile.authenticatorAttachment,
      clientExtensionResults: extensionOutputs.clientExtensionResults,
      response: {
        kind: "attestation",
        clientDataJSON: toBase64Url(clientDataJSON),
        attestationObject: toBase64Url(attestationObject),
        authenticatorData: toBase64Url(authenticatorData),
        publicKeyAlgorithm: -7,
        publicKey: toBase64Url(buildEcP256SubjectPublicKeyInfo(key.x, key.y)),
        transports: authenticatorProfile.transports
      }
    };
  } catch (error) {
    await setCreateDebugPhase(`error:${error instanceof Error ? error.message : "unknown"}`);
    if (createdKeyId && keyVaultClient) {
      try {
        await keyVaultClient.deleteKey(createdKeyId);
      } catch {
        // Best-effort cleanup only.
      }
    }

    throw error;
  }
}

async function buildAttestationObject(
  rpId: string,
  attestationPreference: AttestationConveyancePreference | undefined,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array
): Promise<Uint8Array> {
  if (!shouldEmitSyntheticPackedAttestation(rpId, attestationPreference)) {
    return buildNoneAttestationObject(authenticatorData);
  }

  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", toPlainArrayBuffer(clientDataJSON)));
  const signedBytes = combine(authenticatorData, clientDataHash);
  const batchMaterial = await createBatchAttestationMaterial(signedBytes);
  return buildPackedAttestationObject(authenticatorData, batchMaterial.signature, [batchMaterial.certificate]);
}

async function createBatchAttestationMaterial(signedBytes: Uint8Array): Promise<{
  certificate: Uint8Array;
  signature: Uint8Array;
}> {
  const keyAlgorithm: EcKeyGenParams = {
    name: "ECDSA",
    namedCurve: "P-256"
  };
  const signingAlgorithm: EcdsaParams = {
    name: "ECDSA",
    hash: "SHA-256"
  };
  const keys = await crypto.subtle.generateKey(keyAlgorithm, true, ["sign", "verify"]);
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomUUID().replace(/-/g, ""),
    name: batchAttestationSubject,
    notBefore: batchAttestationNotBefore,
    notAfter: batchAttestationNotAfter,
    keys,
    signingAlgorithm,
    extensions: [
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey)
    ]
  }, globalThis.crypto);

  const signature = await crypto.subtle.sign(signingAlgorithm, keys.privateKey, toPlainArrayBuffer(signedBytes));
  const asnSignature = new x509.AsnEcSignatureFormatter().toAsnSignature(
    { ...keyAlgorithm, hash: "SHA-256" } as EcKeyGenParams & EcdsaParams,
    signature
  );
  if (!asnSignature) {
    throw new Error("Failed to encode packed attestation signature.");
  }

  return {
    certificate: new Uint8Array(certificate.rawData),
    signature: new Uint8Array(asnSignature)
  };
}

async function setCreateDebugPhase(phase: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [createDebugPhaseStorageKey]: phase }, () => resolve());
  });
}

async function setCreateDebugState(value: unknown): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [createDebugStateStorageKey]: value }, () => resolve());
  });
}

async function setGetDebugState(value: unknown): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({ [getDebugStateStorageKey]: value }, () => resolve());
  });
}

async function getFromLocalStorage<TValue>(key: string): Promise<TValue | undefined> {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (items: Record<string, unknown>) => resolve(items[key] as TValue | undefined));
  });
}

async function removeFromLocalStorage(key: string): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.storage.local.remove(key, () => resolve());
  });
}

async function handleGetRequest(
  config: typeof defaultExtensionState.config,
  clientData: WebAuthnClientData,
  options: CredentialCreationOptions | CredentialRequestOptions
): Promise<SerializedPublicKeyCredential | CredentialSelectionDirective> {
  const publicKey = getRequestOptions(options);
  if (!publicKey) {
    throw new DOMException("Expected publicKey request options.", "TypeError");
  }

  const rpId = resolveEffectiveRpId(publicKey.rpId, clientData.origin);
  assertRpIdAllowedForOrigin(rpId, clientData.origin);
  const userVerified = await resolveUserVerification(config, publicKey.userVerification, {
    operation: "get",
    rpId,
    origin: clientData.origin
  });
  const environment = createMetadataEnvironment(config, (scopes) => tokenBroker.acquireToken(config, scopes));
  const records = await loadCredentialRecords(environment);
  const allowList = new Set((publicKey.allowCredentials ?? [])
    .map((descriptor: PublicKeyCredentialDescriptor) => descriptor.id)
    .filter((value): value is BufferSource => Boolean(value))
    .map((value) => toBase64Url(toUint8Array(value))));
  const rpRecords = records
    .filter((record) => record.rpId === rpId)
    .sort((left, right) => left.userName.localeCompare(right.userName));

  const matches = rpRecords
    .filter((record) => allowList.size === 0 || allowList.has(record.credentialId))
    .sort((left, right) => left.userName.localeCompare(right.userName));

  await setGetDebugState({
    rpId,
    allowList: Array.from(allowList),
    rpCredentialIds: rpRecords.map((record) => record.credentialId),
    matchedCredentialIds: matches.map((record) => record.credentialId)
  });

  if (allowList.size === 0 && matches.length > 1) {
    return {
      kind: "select-account",
      options: matches.map((record) => ({
        credentialId: record.credentialId,
        rpId: record.rpId,
        userName: record.userName,
        userDisplayName: record.userDisplayName
      }))
    };
  }

  const selected = matches[0];
  if (!selected) {
    throw new DOMException("No stored passkey matched this request.", "NotAllowedError");
  }

  const nextSignCount = selected.signCount + 1;
  const authenticatorProfile = resolveAuthenticatorProfile(selected.rpId);
  const authenticatorData = await buildAssertionAuthenticatorDataWithFlags(rpId, nextSignCount, userVerified);
  const clientDataJSON = buildClientDataJson("webauthn.get", publicKey.challenge, clientData);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", toPlainArrayBuffer(clientDataJSON)));

  if (config.metadataTransportMode === "FunctionCatalog") {
    if (!environment.developmentCatalog) {
      throw new DOMException("The Function assertion service is not configured.", "NotSupportedError");
    }
    const assertion = await environment.developmentCatalog.assert(
      selected.recordId,
      rpId,
      clientDataHash,
      userVerified
    );
    const signature = new x509.AsnEcSignatureFormatter().toAsnSignature(
      { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as EcKeyGenParams & EcdsaParams,
      toPlainArrayBuffer(assertion.signature)
    );
    if (!signature) {
      throw new Error("Failed to encode the Function assertion signature.");
    }
    return {
      id: selected.credentialId,
      rawId: selected.credentialId,
      type: "public-key",
      authenticatorAttachment: authenticatorProfile.authenticatorAttachment,
      clientExtensionResults: {},
      response: {
        kind: "assertion",
        clientDataJSON: toBase64Url(clientDataJSON),
        authenticatorData: toBase64Url(assertion.authenticatorData),
        signature: toBase64Url(new Uint8Array(signature)),
        userHandle: selected.userHandle
      }
    };
  }

  const signedBytes = combine(authenticatorData, clientDataHash);
  const keyVaultClient = environment.keyVaultClient;
  if (!keyVaultClient) {
    throw new DOMException("Local cache mode cannot produce assertion signatures because it has no signing backend.", "NotSupportedError");
  }

  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toPlainArrayBuffer(signedBytes)));
  const signature = await keyVaultClient.signDigest(selected.signingKeyId, digest);
  const updatedRecord: BrowserStoredCredentialRecord = {
    ...selected,
    signCount: nextSignCount,
    updatedAt: new Date().toISOString()
  };

  await saveCredentialRecord(updatedRecord, environment);

  return {
    id: selected.credentialId,
    rawId: selected.credentialId,
    type: "public-key",
    authenticatorAttachment: authenticatorProfile.authenticatorAttachment,
    clientExtensionResults: {},
    response: {
      kind: "assertion",
      clientDataJSON: toBase64Url(clientDataJSON),
      authenticatorData: toBase64Url(authenticatorData),
      signature: toBase64Url(signature),
      userHandle: selected.userHandle
    }
  };
}

function ensureEs256Supported(parameters: PublicKeyCredentialParameters[]): void {
  if (!parameters.some((parameter) => parameter.type === "public-key" && parameter.alg === -7)) {
    throw new DOMException("Only ES256 passkeys are supported by this Key Vault spike.", "NotSupportedError");
  }
}

async function resolveUserVerification(
  _config: typeof defaultExtensionState.config,
  userVerification: UserVerificationRequirement | undefined,
  context: {
    operation: WebAuthnOperation;
    rpId: string;
    origin: string;
  }
): Promise<boolean> {
  if (userVerification === "required") {
    if (await hasConfiguredPinUv(createPinUvContext(_config))) {
      const verified = await requestPinUserVerification(context);
      await setUserVerificationDebugState(context.operation, {
        requestedUserVerification: userVerification,
        userVerificationSatisfied: verified,
        reason: verified ? "pin-verified" : "pin-cancelled",
        rpId: context.rpId,
        origin: context.origin
      });

      if (verified) {
        return true;
      }

      throw new DOMException(
        "This request requires user verification. Complete the PIN prompt to continue.",
        "NotAllowedError"
      );
    }

    await setUserVerificationDebugState(context.operation, {
      requestedUserVerification: userVerification,
      userVerificationSatisfied: false,
      reason: "pin-not-configured"
    });
    throw new DOMException(
      "This request requires user verification. Sign in to Key Vault, set the extension PIN in the side panel, then retry.",
      "NotSupportedError"
    );
  }

  return false;
}

async function requestPinUserVerification(context: {
  operation: WebAuthnOperation;
  rpId: string;
  origin: string;
}): Promise<boolean> {
  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + pinUvSessionWindowMs).toISOString();

  return new Promise<boolean>(async (resolve, reject) => {
    const timeoutHandle = globalThis.setTimeout(() => {
      settlePinUvSession(sessionId, false);
    }, pinUvSessionWindowMs);

    pendingPinUvSessions.set(sessionId, {
      view: {
        sessionId,
        operation: context.operation,
        rpId: context.rpId,
        origin: context.origin,
        expiresAt
      },
      resolve,
      timeoutHandle,
      windowId: null
    });

    try {
      const url = chrome.runtime.getURL(`uv-dialog.html?sessionId=${encodeURIComponent(sessionId)}`);
      const popupWindow = await createPopupWindow(url);
      const session = pendingPinUvSessions.get(sessionId);
      if (session) {
        session.windowId = popupWindow.id ?? null;
      }
    } catch (error) {
      settlePinUvSession(sessionId, false);
      reject(error);
    }
  });
}

async function verifyPinUvSession(sessionId: string, pin: string): Promise<boolean> {
  const session = pendingPinUvSessions.get(sessionId);
  if (!session) {
    throw new DOMException("The PIN verification request expired or was cancelled.", "NotAllowedError");
  }

  const state = await loadExtensionState();
  await tokenBroker.getHydratedStatus(state.config);
  await ensurePinUvLocalVerifier(createPinUvContext(state.config));
  const verified = await verifyPinUv(pin, createPinUvContext(state.config));
  if (verified) {
    settlePinUvSession(sessionId, true);
  }

  return verified;
}

async function verifyPinForUnlock(config: typeof defaultExtensionState.config, pin: string): Promise<boolean> {
  try {
    return await verifyPinUv(pin);
  } catch (error) {
    if (!requiresLegacyPinSilentSignIn(error) || config.metadataTransportMode !== "KeyVaultSecrets") {
      throw error;
    }

    const silentAuthStatus = await tokenBroker.beginSilentSignIn(config);
    if (!silentAuthStatus) {
      throw new DOMException("Silent sign-in could not restore the Key Vault session needed to unlock this legacy PIN state.", "NotAllowedError");
    }

    await ensurePinUvLocalVerifier(createPinUvContext(config));
    return verifyPinUv(pin);
  }
}

function cancelPinUvSession(sessionId: string): void {
  settlePinUvSession(sessionId, false);
}

function settlePinUvSession(sessionId: string, verified: boolean): void {
  const session = pendingPinUvSessions.get(sessionId);
  if (!session) {
    return;
  }

  pendingPinUvSessions.delete(sessionId);
  globalThis.clearTimeout(session.timeoutHandle);
  if (session.windowId != null) {
    void removeWindowById(session.windowId);
  }

  session.resolve(verified);
}

async function createPopupWindow(url: string): Promise<chrome.windows.Window> {
  return new Promise((resolve, reject) => {
    chrome.windows.create({
      url,
      type: "popup",
      width: 440,
      height: 520,
      focused: true
    }, (popupWindow) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      if (!popupWindow) {
        reject(new Error("Failed to open the PIN verification window."));
        return;
      }

      resolve(popupWindow);
    });
  });
}

async function removeWindowById(windowId: number): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.windows.remove(windowId, () => resolve());
  });
}

async function setUserVerificationDebugState(operation: "create" | "get", value: unknown): Promise<void> {
  if (operation === "create") {
    await setCreateDebugPhase("uv-check");
    await setCreateDebugState(value);
    return;
  }

  await setGetDebugState(value);
}

function createPinUvContext(config: typeof defaultExtensionState.config): PinUvContext {
  if (config.metadataTransportMode !== "KeyVaultSecrets") {
    return {};
  }

  const authStatus = tokenBroker.getStatus(config);
  if (authStatus.mode !== "signed-in") {
    return {
      requireKeyVaultProtection: true
    };
  }

  const environment = createMetadataEnvironment(config, (scopes) => tokenBroker.acquireToken(config, scopes));
  return {
    keyVaultClient: environment.keyVaultClient ?? undefined,
    requireKeyVaultProtection: true
  };
}

async function ensureSetupComplete(config: typeof defaultExtensionState.config): Promise<void> {
  const authStatus = await tokenBroker.getHydratedStatus(config);
  const pinConfigured = await hasConfiguredPinUv(createPinUvContext(config));
  if (canUseLockedState(config, pinConfigured)) {
    return;
  }

  const setupProgress = evaluateSetupProgress(config, authStatus.mode, pinConfigured);
  if (!setupProgress.isComplete) {
    throw new DOMException(getSetupIncompleteMessage(setupProgress, config), "NotAllowedError");
  }
}

async function resetInitialInstallState(): Promise<void> {
  await tokenBroker.clear();
  await resetPinUvState();
  await clearInteractiveUnlockPermission();
  await saveExtensionState(structuredClone(defaultExtensionState));
}

async function handleInstalled(reason: chrome.runtime.OnInstalledReason): Promise<void> {
  if (reason === "install") {
    await resetInitialInstallState();
    await syncDynamicContentScriptRegistration();
    await syncActionPresentation();
    chrome.runtime.openOptionsPage();
    return;
  }

  await ensureExtensionStateInitialized();
  await syncDynamicContentScriptRegistration();
  await syncActionPresentation();
}

async function handleStartup(): Promise<void> {
  await syncDynamicContentScriptRegistration();
  await resolveRuntimeContext({ browserStart: true });
  await syncActionPresentation();
}

async function syncDynamicContentScriptRegistration(): Promise<void> {
  const matches = await getGrantedSitePermissionPatterns();
  await unregisterDynamicContentScript();
  if (matches.length === 0) {
    return;
  }

  await registerDynamicContentScript(matches);
}

async function getGrantedSitePermissionPatterns(): Promise<string[]> {
  const permissions = await new Promise<chrome.permissions.Permissions>((resolve, reject) => {
    chrome.permissions.getAll((result) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve(result);
    });
  });

  const origins = permissions.origins ?? [];
  const state = await loadExtensionState();
  const functionOrigin = getDevelopmentFunctionOriginPattern(state.config.developmentFunctionAppBaseUrl);
  return Array.from(new Set(origins.filter((origin) =>
    (origin.startsWith("http://") || origin.startsWith("https://"))
    && origin !== functionOrigin
  ))).sort();
}

function getDevelopmentFunctionOriginPattern(baseUrl: string): string | null {
  if (!baseUrl.trim()) {
    return null;
  }

  try {
    const url = new URL(baseUrl);
    return `${url.protocol}//${url.hostname}/*`;
  } catch {
    return null;
  }
}

async function unregisterDynamicContentScript(): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.scripting.unregisterContentScripts({ ids: [dynamicContentScriptId] }, () => {
      // On extension reload Chrome may already have discarded the persisted
      // registration. Reading lastError is required even when that is the
      // expected, harmless outcome; otherwise DevTools reports an unchecked
      // runtime.lastError warning.
      void chrome.runtime.lastError;
      resolve();
    });
  });
}

async function registerDynamicContentScript(matches: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.scripting.registerContentScripts([
      {
        id: dynamicContentScriptId,
        matches,
        js: ["content.js"],
        runAt: "document_start",
        persistAcrossSessions: true
      }
    ], () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

function buildStoredCredentialRecord(
  publicKey: PublicKeyCredentialCreationOptions,
  rpId: string,
  credentialIdBytes: Uint8Array,
  signingKeyId: string
): BrowserStoredCredentialRecord {
  const now = new Date().toISOString();
  return {
    recordId: crypto.randomUUID().replace(/-/g, ""),
    credentialId: toBase64Url(credentialIdBytes),
    rpId,
    userHandle: toBase64Url(toUint8Array(publicKey.user.id)),
    userName: publicKey.user.name,
    userDisplayName: publicKey.user.displayName || publicKey.user.name,
    signingKeyId,
    backendKind: "key-vault",
    createdAt: now,
    updatedAt: now,
    signCount: 0
  };
}

function toStoredCredentialSummary(record: BrowserStoredCredentialRecord): StoredCredentialSummary {
  return {
    recordId: record.recordId,
    credentialId: record.credentialId,
    rpId: record.rpId,
    userName: record.userName,
    userDisplayName: record.userDisplayName,
    backendKind: record.backendKind,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    signCount: record.signCount
  };
}

function compareStoredCredentialSummaries(left: StoredCredentialSummary, right: StoredCredentialSummary): number {
  return right.updatedAt.localeCompare(left.updatedAt);
}

function buildCreateExtensionOutputs(
  publicKey: PublicKeyCredentialCreationOptions
): {
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  authenticatorDataExtensions: Array<[string, Uint8Array]>;
} {
  const result: AuthenticationExtensionsClientOutputs = {};
  const clientExtensionResults = result as Record<string, unknown>;
  const extensions = (publicKey.extensions ?? {}) as Record<string, unknown>;

  if (extensions.credProps === true) {
    result.credProps = { rk: true };
  }

  if (extensions.hmacCreateSecret === true) {
    clientExtensionResults.hmacCreateSecret = false;
  }

  return {
    clientExtensionResults: result,
    authenticatorDataExtensions: []
  };
}

function resolveAuthenticatorProfile(rpId: string): {
  authenticatorAttachment: AuthenticatorAttachment | null;
  transports: AuthenticatorTransport[];
  aaguidHex: string;
} {
  if (compatibilityPackedAttestationRpIds.has(rpId)) {
    return {
      authenticatorAttachment: "cross-platform",
      transports: ["usb"],
      aaguidHex: compatibilityAuthenticatorAaguidHex
    };
  }

  return {
    authenticatorAttachment: null,
    transports: [],
    aaguidHex: opaqueAuthenticatorAaguidHex
  };
}

function shouldEmitSyntheticPackedAttestation(
  rpId: string,
  attestationPreference: AttestationConveyancePreference | undefined
): boolean {
  return (attestationPreference ?? "none") !== "none"
    && compatibilityPackedAttestationRpIds.has(rpId);
}

function buildKeyName(prefix: string): string {
  const candidate = `${prefix}-${crypto.randomUUID().replace(/-/g, "")}`;
  return candidate.length <= 127 ? candidate : candidate.slice(0, 127);
}

function buildClientDataJson(
  type: "webauthn.create" | "webauthn.get",
  challenge: BufferSource,
  clientData: WebAuthnClientData
): Uint8Array {
  const jsonShape: Record<string, string | boolean> = {
    type,
    challenge: toBase64Url(toUint8Array(challenge)),
    origin: clientData.origin,
    crossOrigin: clientData.crossOrigin
  };

  if (clientData.crossOrigin && clientData.topOrigin) {
    jsonShape.topOrigin = clientData.topOrigin;
  }

  const json = JSON.stringify(jsonShape);

  return new TextEncoder().encode(json);
}

function normalizeClientData(clientData: WebAuthnClientData): WebAuthnClientData {
  const origin = new URL(clientData.origin).origin;
  const topOrigin = clientData.crossOrigin && clientData.topOrigin ? new URL(clientData.topOrigin).origin : null;
  return {
    origin,
    crossOrigin: clientData.crossOrigin,
    topOrigin
  };
}

function resolveEffectiveRpId(rpId: string | undefined, origin: string): string {
  return normalizeHostname(rpId ?? new URL(origin).hostname);
}

function assertRpIdAllowedForOrigin(rpId: string, origin: string): void {
  const originHostname = normalizeHostname(new URL(origin).hostname);
  const candidateRpId = normalizeHostname(rpId);

  if (!candidateRpId) {
    throw new DOMException("Relying party ID is required.", "TypeError");
  }

  if (originHostname === candidateRpId) {
    return;
  }

  const parsedRpId = parse(candidateRpId);
  if (parsedRpId.isIp || isLocalDevelopmentHost(candidateRpId)) {
    throw new DOMException("The relying party ID is not valid for this origin.", "SecurityError");
  }

  if (!originHostname.endsWith(`.${candidateRpId}`)) {
    throw new DOMException("The relying party ID is not valid for this origin.", "SecurityError");
  }

  const registrableDomain = getDomain(candidateRpId, { allowPrivateDomains: true });
  if (registrableDomain !== candidateRpId) {
    throw new DOMException("The relying party ID is not valid for this origin.", "SecurityError");
  }
}

function normalizeHostname(value: string): string {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

function isLocalDevelopmentHost(value: string): boolean {
  return value === "localhost" || value === "[::1]";
}

function isSelectionDirective(value: SerializedPublicKeyCredential | CredentialSelectionDirective): value is CredentialSelectionDirective {
  return "kind" in value && value.kind === "select-account";
}

function serializeError(error: unknown): { name: string; message: string } {
  if (error instanceof DOMException) {
    return { name: error.name, message: error.message };
  }

  if (error instanceof Error) {
    return { name: error.name || "Error", message: error.message };
  }

  return { name: "Error", message: "Unexpected background failure." };
}

function getCreationOptions(options: CredentialCreationOptions | CredentialRequestOptions): PublicKeyCredentialCreationOptions | null {
  const candidate = options.publicKey;
  if (!candidate || !("pubKeyCredParams" in candidate) || !("rp" in candidate) || !("user" in candidate)) {
    return null;
  }

  return candidate;
}

function getRequestOptions(options: CredentialCreationOptions | CredentialRequestOptions): PublicKeyCredentialRequestOptions | null {
  const candidate = options.publicKey;
  if (!candidate || "pubKeyCredParams" in candidate || "rp" in candidate || "user" in candidate) {
    return null;
  }

  return candidate;
}

function toUint8Array(value: BufferSource): Uint8Array {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

function toPlainArrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}

function combine(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left, 0);
  result.set(right, left.length);
  return result;
}

type ActionTone = "inactive" | "configured" | "active" | "locked";

async function syncSidePanelBehavior(): Promise<void> {
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
}

function buildStoredCredentialLoginUrl(context: FunctionBrowserContext): string {
  if (context.provider !== "entra") {
    const url = new URL(`https://${context.rpId}/`);
    url.searchParams.set("login_hint", context.userName);
    return url.toString();
  }

  const url = new URL("https://outlook.office.com/mail/");
  url.searchParams.set("login_hint", context.userName);
  url.searchParams.set("prompt", "none");
  return url.toString();
}

async function createCompatibilityTab(): Promise<{ id: number }> {
  const tab = await chrome.tabs.create({ url: chrome.runtime.getURL("opening.html"), active: true });
  if (tab.id === undefined) {
    throw new Error("The browser did not return an ID for the compatibility tab.");
  }
  return { id: tab.id };
}

async function navigateTab(tabId: number, url: string): Promise<void> {
  await chrome.tabs.update(tabId, { url });
}

async function applyCompatibilityUserAgentRule(
  tabId: number,
  userAgent: string,
  requestDomains: string[]
): Promise<boolean> {
  const origins = requestDomains.map((domain) => `https://${domain}/*`);
  const hasHostAccess = await chrome.permissions.contains({ origins });
  if (!hasHostAccess) {
    return false;
  }

  const ruleId = compatibilityUserAgentRuleIdBase + tabId;
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: 1,
      action: {
        type: "modifyHeaders" as chrome.declarativeNetRequest.RuleActionType,
        requestHeaders: [{
          header: "User-Agent",
          operation: "set" as chrome.declarativeNetRequest.HeaderOperation,
          value: userAgent
        }]
      },
      condition: {
        tabIds: [tabId],
        requestDomains
      }
    }]
  });
  return true;
}

async function removeCompatibilityUserAgentRule(tabId: number): Promise<void> {
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [compatibilityUserAgentRuleIdBase + tabId]
    });
  } catch {
    // The rule may already have been removed by an extension reload.
  }
}

async function syncActionPresentation(): Promise<void> {
  const { state, authStatus, pinConfigured } = await resolveRuntimeContext();
  const progress = evaluateSetupProgress(state.config, authStatus.mode, pinConfigured);
  const tone: ActionTone = canUseLockedState(state.config, pinConfigured) && Boolean(state.lockedAt)
    ? "locked"
    : !canUseLockedState(state.config, pinConfigured) && !progress.isComplete
    ? "inactive"
    : state.enabled
      ? "active"
      : "configured";

  chrome.action.setIcon({
    imageData: {
      16: createActionIcon(16, tone),
      32: createActionIcon(32, tone)
    }
  });

  chrome.action.setTitle({
    title: canUseLockedState(state.config, pinConfigured) && state.lockedAt
      ? "Key Vault Passkey Provider: locked"
      : progress.isComplete
        ? (state.enabled ? "Key Vault Passkey Provider: active" : "Key Vault Passkey Provider: configured")
        : "Key Vault Passkey Provider: setup required"
  });
}

function createActionIcon(size: number, tone: ActionTone): ImageData {
  const palette = tone === "active"
    ? { background: "#0f6b63", foreground: "#f7fcfb" }
    : tone === "locked"
      ? { background: "#8b3d1f", foreground: "#fff5ef" }
    : tone === "configured"
      ? { background: "#d7eee9", foreground: "#0f6b63" }
      : { background: "#d9dde2", foreground: "#54606c" };

  const canvas = new OffscreenCanvas(size, size);
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("Unable to create extension action icon.");
  }

  context.clearRect(0, 0, size, size);
  drawRoundedRect(context, size * 0.12, size * 0.12, size * 0.76, size * 0.76, size * 0.2);
  context.fillStyle = palette.background;
  context.fill();

  context.fillStyle = palette.foreground;
  context.beginPath();
  context.arc(size * 0.42, size * 0.4, size * 0.14, 0, Math.PI * 2);
  context.fill();

  drawRoundedRect(context, size * 0.36, size * 0.5, size * 0.12, size * 0.24, size * 0.06);
  context.fill();

  drawRoundedRect(context, size * 0.46, size * 0.58, size * 0.2, size * 0.08, size * 0.04);
  context.fill();

  drawRoundedRect(context, size * 0.56, size * 0.64, size * 0.08, size * 0.08, size * 0.03);
  context.fill();

  return context.getImageData(0, 0, size, size);
}

async function resolveRuntimeContext(
  options?: {
    browserStart?: boolean;
  }
): Promise<{
  state: ExtensionState;
  authStatus: BrowserAuthStatus;
  pinConfigured: boolean;
}> {
  let state = await loadExtensionState();

  if (state.interactiveUnlockExpiresAt && !hasInteractiveUnlockPermission(state)) {
    state = await clearInteractiveUnlockPermission();
  }

  const pinConfigured = await hasConfiguredPinUv(createPinUvContext(state.config));
  let authStatus = await tokenBroker.getHydratedStatus(state.config);

  if (pinConfigured && (authStatus.mode === "signed-in" || authStatus.mode === "local-only")) {
    await ensurePinUvLocalVerifier(createPinUvContext(state.config));
  }

  if (!canUseLockedState(state.config, pinConfigured)) {
    return { state, authStatus, pinConfigured };
  }

  if (options?.browserStart) {
    state = await enterLockedState("browser-start");
    authStatus = await tokenBroker.getHydratedStatus(state.config);
    return { state, authStatus, pinConfigured };
  }

  if (!state.lockedAt && authStatus.mode === "signed-out") {
    state = await enterLockedState("token-expired");
    authStatus = await tokenBroker.getHydratedStatus(state.config);
    return { state, authStatus, pinConfigured };
  }

  if (!state.lockedAt && hasIdleTimedOut(state)) {
    state = await enterLockedState("idle");
    authStatus = await tokenBroker.getHydratedStatus(state.config);
  }

  return { state, authStatus, pinConfigured };
}

function canUseLockedState(config: typeof defaultExtensionState.config, pinConfigured: boolean): boolean {
  return isConfigReady(config) && pinConfigured;
}

function hasIdleTimedOut(state: ExtensionState): boolean {
  if (state.lockedAt || !state.lastActivityAt) {
    return false;
  }

  const lastActivityAt = Date.parse(state.lastActivityAt);
  if (Number.isNaN(lastActivityAt)) {
    return false;
  }

  return lastActivityAt <= Date.now() - state.lockTimeoutMinutes * 60 * 1000;
}

async function enterLockedState(reason: LockReason): Promise<ExtensionState> {
  await tokenBroker.clear();
  await clearInteractiveUnlockPermission();
  return setLockState(reason);
}

function requiresLegacyPinSilentSignIn(error: unknown): boolean {
  return error instanceof DOMException
    && error.name === "NotAllowedError"
    && /Key Vault sign-in is required before the extension can verify the configured PIN/i.test(error.message);
}

async function armInteractiveUnlockPermission(): Promise<void> {
  await updateInteractiveUnlockExpiresAt(new Date(Date.now() + 2 * 60 * 1000).toISOString());
}

async function clearInteractiveUnlockPermission(): Promise<ExtensionState> {
  return updateInteractiveUnlockExpiresAt(null);
}

function hasInteractiveUnlockPermission(state: ExtensionState): boolean {
  return Boolean(state.interactiveUnlockExpiresAt && Date.parse(state.interactiveUnlockExpiresAt) > Date.now());
}

function drawRoundedRect(
  context: OffscreenCanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number
): void {
  const right = x + width;
  const bottom = y + height;
  const clampedRadius = Math.min(radius, width / 2, height / 2);

  context.beginPath();
  context.moveTo(x + clampedRadius, y);
  context.lineTo(right - clampedRadius, y);
  context.quadraticCurveTo(right, y, right, y + clampedRadius);
  context.lineTo(right, bottom - clampedRadius);
  context.quadraticCurveTo(right, bottom, right - clampedRadius, bottom);
  context.lineTo(x + clampedRadius, bottom);
  context.quadraticCurveTo(x, bottom, x, bottom - clampedRadius);
  context.lineTo(x, y + clampedRadius);
  context.quadraticCurveTo(x, y, x + clampedRadius, y);
  context.closePath();
}
