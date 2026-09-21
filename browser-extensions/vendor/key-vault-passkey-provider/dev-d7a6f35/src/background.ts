import { BrowserEntraTokenBroker } from "./shared/browser-auth";
import { getDomain, parse } from "tldts";
import { fromBase64Url, toBase64Url } from "./shared/base64url";
import { CeremonyAuthorizationRegistry } from "./shared/ceremony-authorization-registry";
import { isActiveCredential, transitionCredential } from "./shared/credential-lifecycle";
import { getCachedMetadataSummary } from "./shared/metadata-cache-store";
import { createMetadataEnvironment, getMetadataSummary, loadCredentialRecords, saveCredentialRecord } from "./shared/metadata-store";
import type { BrowserStoredCredentialRecord } from "./shared/models";
import { defaultExtensionState, type BrowserAuthStatus, type CredentialSelectionOption, type ExtensionState, type LockReason, type RuntimeRequest, type RuntimeResponse, type SerializedPublicKeyCredential, type StoredCredentialSummary, type WebAuthnClientData, type WebAuthnOperation } from "./shared/protocol";
import { ensurePinUvLocalVerifier, getPinUvStatus, hasConfiguredPinUv, removePinUv, resetPinUvState, setPinUv, type PinUvContext, verifyPinUv } from "./shared/pin-uv";
import { evaluateSetupProgress, getSetupIncompleteMessage, isConfigReady } from "./shared/setup-state";
import { deserializeRuntimeCredentialOptions } from "./shared/runtime-credential-options";
import { assertGuid, normalizeEntraAuthorityHost, normalizeKeyVaultBaseUrl, normalizeKeyVaultKeyPath } from "./shared/security-boundaries";
import { runSerializedCredentialMutation } from "./shared/serialized-operation-queue";
import { clearLockState, ensureExtensionStateInitialized, loadExtensionState, resetLockStateTracking, saveExtensionState, setLockState, touchLastActivity, updateConfig, updateEnabled, updateInterceptTelemetry, updateInteractiveUnlockExpiresAt, updateLockTimeoutMinutes } from "./shared/storage";
import { buildAssertionAuthenticatorDataWithFlags, buildEcP256SubjectPublicKeyInfo, buildMakeCredentialAuthenticatorData, buildNoneAttestationObject } from "./shared/webauthn-data";

const opaqueAuthenticatorAaguidHex = "00000000000000000000000000000000";

const tokenBroker = new BrowserEntraTokenBroker();
const createDebugPhaseStorageKey = "kvpp.debug.createPhase";
const createDebugStateStorageKey = "kvpp.debug.createState";
const getDebugStateStorageKey = "kvpp.debug.getState";
const ceremonyAuthorizationWindowMs = 2 * 60 * 1000;
const dynamicContentScriptId = "kvpp-webauthn-intercept";
const activeCeremonyIds = new Set<string>();
const cancelledCeremonyIds = new Set<string>();

const ceremonyAuthorizations = new CeremonyAuthorizationRegistry({
  closeWindow: (windowId) => {
    void removeWindowById(windowId);
  }
});

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

chrome.runtime.onSuspend.addListener(() => {
  ceremonyAuthorizations.cancelAll();
});

chrome.permissions.onAdded.addListener(() => {
  void syncDynamicContentScriptRegistration();
});

chrome.permissions.onRemoved.addListener(() => {
  void syncDynamicContentScriptRegistration();
});

chrome.windows.onRemoved.addListener((windowId) => {
  ceremonyAuthorizations.cancelByWindowId(windowId);
});

chrome.runtime.onMessage.addListener((message: RuntimeRequest, sender, sendResponse: (response: RuntimeResponse) => void) => {
  void handleMessage(message, sender)
    .then(sendResponse)
    .catch((error: unknown) => {
      sendResponse({ ok: false, error: serializeError(error) });
    });

  return true;
});

async function handleMessage(message: RuntimeRequest, sender: chrome.runtime.MessageSender): Promise<RuntimeResponse> {
  assertRuntimeMessageSender(message, sender);
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
        throw new DOMException("Unlock the extension PIN first. If silent SSO cannot restore the session, interactive sign-in will be enabled briefly.", "NotAllowedError");
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
      return { ok: true, storedCredentials: toVisibleStoredCredentialSummaries(records) };
    }
    case "set-stored-credential-enabled": {
      const { state } = await resolveRuntimeContext();
      if (state.lockedAt) {
        throw new DOMException("Unlock the extension before changing stored passkeys.", "NotAllowedError");
      }

      const authStatus = await tokenBroker.getHydratedStatus(state.config);
      if (state.config.metadataTransportMode === "KeyVaultSecrets" && authStatus.mode !== "signed-in") {
        throw new DOMException("Sign in to Key Vault before changing stored passkeys.", "NotAllowedError");
      }

      const environment = createMetadataEnvironment(state.config, (scopes) => tokenBroker.acquireToken(state.config, scopes));
      const records = await runSerializedCredentialMutation(async () => {
        const existingRecords = await loadCredentialRecords(environment);
        const record = existingRecords.find((candidate) => candidate.recordId === message.recordId);
        if (!record || record.state === "deleted") {
          throw new DOMException("The stored passkey no longer exists.", "NotFoundError");
        }
        if (record.state !== "active" && record.state !== "disabled") {
          throw new DOMException("The stored passkey cannot change availability in its current state.", "InvalidStateError");
        }

        const requestedState = message.enabled ? "active" : "disabled";
        if (record.state !== requestedState) {
          await saveCredentialRecord(transitionCredential(record, requestedState), environment);
        }
        return loadCredentialRecords(environment);
      });
      return { ok: true, storedCredentials: toVisibleStoredCredentialSummaries(records) };
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
      const records = await runSerializedCredentialMutation(async () => {
        const existingRecords = await loadCredentialRecords(environment);
        const recordToDelete = existingRecords.find((record) => record.recordId === message.recordId);
        if (!recordToDelete || recordToDelete.state === "deleted") {
          throw new DOMException("The stored passkey no longer exists.", "NotFoundError");
        }
        if (!environment.keyVaultClient) {
          throw new DOMException("Restore Key Vault mode before removing this passkey so its signing key is not orphaned.", "NotSupportedError");
        }

        const deletingRecord = recordToDelete.state === "deleting"
          ? recordToDelete
          : transitionCredential(recordToDelete, "deleting");
        if (deletingRecord !== recordToDelete) {
          await saveCredentialRecord(deletingRecord, environment);
        }

        await environment.keyVaultClient.deleteKey(deletingRecord.signingKeyId);
        await saveCredentialRecord(transitionCredential(deletingRecord, "deleted"), environment);
        return loadCredentialRecords(environment);
      });
      return { ok: true, storedCredentials: toVisibleStoredCredentialSummaries(records) };
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
    case "get-ceremony-authorization-session": {
      return { ok: true, ceremonyAuthorizationSession: ceremonyAuthorizations.getView(message.sessionId) };
    }
    case "approve-ceremony-authorization-session": {
      ceremonyAuthorizations.approve(message.sessionId, message.credentialId);
      return { ok: true, approved: true };
    }
    case "cancel-ceremony-authorization-session": {
      return { ok: true, cancelled: ceremonyAuthorizations.cancel(message.sessionId) };
    }
    case "save-config": {
      validateSecurityConfiguration(message.config);
      await updateConfig(message.config);
      if (message.lockTimeoutMinutes !== undefined) {
        await updateLockTimeoutMinutes(message.lockTimeoutMinutes);
      }
      await tokenBroker.clear();
      await resetLockStateTracking();
      const state = await updateEnabled(false);
      await syncActionPresentation();
      return { ok: true, state };
    }
    case "cancel-webauthn-request": {
      markCeremonyCancelled(message.requestId);
      return { ok: true, cancelled: true };
    }
    case "webauthn-request": {
      return handleWebAuthnRuntimeRequest(message);
    }
  }

  throw new Error(`Unhandled runtime message kind: ${(message as { kind: string }).kind}`);
}

async function handleWebAuthnRuntimeRequest(
  message: Extract<RuntimeRequest, { kind: "webauthn-request" }>
): Promise<RuntimeResponse> {
  activeCeremonyIds.add(message.requestId);
  try {
    assertCeremonyNotCancelled(message.requestId);
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
      return { ok: true, action: "fallback", reason: "Extension is locked. Unlock it from the popup before using passkeys." };
    }

    const clientData = normalizeClientData(message.clientData);
    const options = deserializeRuntimeCredentialOptions(message.options);
    await updateInterceptTelemetry(clientData.origin);
    assertCeremonyNotCancelled(message.requestId);

    const credential = message.operation === "create"
      ? await handleCreateRequest(state.config, clientData, options, message.requestId)
      : await handleGetRequest(state.config, clientData, options, message.requestId);

    assertCeremonyNotCancelled(message.requestId);
    return { ok: true, credential };
  } finally {
    activeCeremonyIds.delete(message.requestId);
    cancelledCeremonyIds.delete(message.requestId);
  }
}

async function handleCreateRequest(
  config: typeof defaultExtensionState.config,
  clientData: WebAuthnClientData,
  options: CredentialCreationOptions | CredentialRequestOptions,
  ceremonyId: string
): Promise<SerializedPublicKeyCredential> {
  const publicKey = getCreationOptions(options);
  if (!publicKey) {
    throw new DOMException("Expected publicKey creation options.", "TypeError");
  }
  ensureEs256Supported(publicKey.pubKeyCredParams);

  const rpId = resolveEffectiveRpId(publicKey.rp?.id, clientData.origin);
  assertRpIdAllowedForOrigin(rpId, clientData.origin);
  assertUserVerificationSupported(publicKey.authenticatorSelection?.userVerification);

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
    .filter(isActiveCredential)
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

  await requestUserPresence({
    ceremonyId,
    operation: "create",
    rpId,
    origin: clientData.origin,
    topOrigin: clientData.topOrigin,
    accountName: publicKey.user.displayName || publicKey.user.name,
    authorizationWindowMs: resolveCeremonyAuthorizationWindowMs(publicKey.timeout)
  });
  assertCeremonyNotCancelled(ceremonyId);

  const credentialIdBytes = crypto.getRandomValues(new Uint8Array(32));
  const keyName = buildKeyName(config.signingKeyName);
  let createdKeyId: string | null = null;
  let stagedRecord: BrowserStoredCredentialRecord | null = null;

  try {
    if (!keyVaultClient) {
      throw new DOMException("Local cache mode cannot create passkeys because it has no signing backend.", "NotSupportedError");
    }

    await setCreateDebugPhase("create-key");
    const key = await keyVaultClient.createEcP256Key(keyName, config.signingKeyType);
    createdKeyId = key.keyId;
    assertCeremonyNotCancelled(ceremonyId);

    const clientDataJSON = buildClientDataJson("webauthn.create", publicKey.challenge, clientData);
    const extensionOutputs = buildCreateExtensionOutputs(publicKey);
    const authenticatorProfile = resolveAuthenticatorProfile(rpId);
    const authenticatorData = await buildMakeCredentialAuthenticatorData(
      rpId,
      credentialIdBytes,
      key.x,
      key.y,
      0,
      true,
      false,
      false,
      false,
      extensionOutputs.authenticatorDataExtensions,
      authenticatorProfile.aaguidHex
    );
    const attestationObject = buildNoneAttestationObject(authenticatorData);
    const pendingRecord = buildStoredCredentialRecord(publicKey, rpId, credentialIdBytes, key.keyId);
    stagedRecord = pendingRecord;

    await setCreateDebugPhase("save-record");
    const record = transitionCredential(pendingRecord, "active");
    await runSerializedCredentialMutation(async () => {
      await saveCredentialRecord(pendingRecord, environment);
      await saveCredentialRecord(record, environment);
    });
    stagedRecord = record;
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
    if (stagedRecord) {
      try {
        const deletingRecord = transitionCredential(stagedRecord, "deleting");
        await runSerializedCredentialMutation(() => saveCredentialRecord(deletingRecord, environment));
        stagedRecord = deletingRecord;
      } catch {
        // Cleanup remains best effort in direct Key Vault mode. A pending
        // record is never eligible for an assertion.
      }
    }

    let keyDeleted = false;
    if (createdKeyId && keyVaultClient) {
      try {
        await keyVaultClient.deleteKey(createdKeyId);
        keyDeleted = true;
      } catch {
        // Best-effort cleanup only.
      }
    }

    if (keyDeleted && stagedRecord) {
      try {
        await runSerializedCredentialMutation(() => saveCredentialRecord(
          transitionCredential(stagedRecord as BrowserStoredCredentialRecord, "deleted"),
          environment
        ));
      } catch {
        // A deleting record remains fail-closed and can be reconciled later.
      }
    }

    throw error;
  }
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
  options: CredentialCreationOptions | CredentialRequestOptions,
  ceremonyId: string
): Promise<SerializedPublicKeyCredential> {
  const publicKey = getRequestOptions(options);
  if (!publicKey) {
    throw new DOMException("Expected publicKey request options.", "TypeError");
  }

  const rpId = resolveEffectiveRpId(publicKey.rpId, clientData.origin);
  assertRpIdAllowedForOrigin(rpId, clientData.origin);
  assertUserVerificationSupported(publicKey.userVerification);
  const environment = createMetadataEnvironment(config, (scopes) => tokenBroker.acquireToken(config, scopes));
  const records = await loadCredentialRecords(environment);
  const allowList = new Set((publicKey.allowCredentials ?? [])
    .map((descriptor: PublicKeyCredentialDescriptor) => descriptor.id)
    .filter((value): value is BufferSource => Boolean(value))
    .map((value) => toBase64Url(toUint8Array(value))));
  const rpRecords = records
    .filter((record) => isActiveCredential(record) && record.rpId === rpId)
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

  let selected: BrowserStoredCredentialRecord | undefined;
  if (allowList.size === 0 && matches.length > 1) {
    const credentialOptions: CredentialSelectionOption[] = matches.map((record) => ({
        credentialId: record.credentialId,
        rpId: record.rpId,
        userName: record.userName,
        userDisplayName: record.userDisplayName
    }));
    const selectedCredentialId = await requestUserPresence({
      ceremonyId,
      operation: "get",
      rpId,
      origin: clientData.origin,
      topOrigin: clientData.topOrigin,
      accountName: null,
      credentialOptions,
      authorizationWindowMs: resolveCeremonyAuthorizationWindowMs(publicKey.timeout)
    });
    selected = matches.find((record) => record.credentialId === selectedCredentialId);
    if (!selected) {
      throw new DOMException("The selected passkey is no longer available.", "NotAllowedError");
    }
  } else {
    selected = matches[0];
  }

  if (!selected) {
    throw new DOMException("No stored passkey matched this request.", "NotAllowedError");
  }

  if (matches.length <= 1 || allowList.size > 0) {
    await requestUserPresence({
      ceremonyId,
      operation: "get",
      rpId,
      origin: clientData.origin,
      topOrigin: clientData.topOrigin,
      accountName: selected.userDisplayName || selected.userName,
      authorizationWindowMs: resolveCeremonyAuthorizationWindowMs(publicKey.timeout)
    });
  }
  assertCeremonyNotCancelled(ceremonyId);

  return runSerializedCredentialMutation(async () => {
    assertCeremonyNotCancelled(ceremonyId);
    const refreshedRecords = await loadCredentialRecords(environment);
    const currentRecord = refreshedRecords.find((record) =>
      record.recordId === selected.recordId && isActiveCredential(record));
    if (!currentRecord) {
      throw new DOMException("The selected passkey is no longer active.", "NotAllowedError");
    }
    if (currentRecord.signCount >= 0xffff_ffff) {
      throw new DOMException("The passkey signature counter is exhausted.", "NotAllowedError");
    }

    const nextSignCount = currentRecord.signCount + 1;
    const authenticatorProfile = resolveAuthenticatorProfile(currentRecord.rpId);
    const authenticatorData = await buildAssertionAuthenticatorDataWithFlags(rpId, nextSignCount, true, false);
    const clientDataJSON = buildClientDataJson("webauthn.get", publicKey.challenge, clientData);
    const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", toPlainArrayBuffer(clientDataJSON)));
    const signedBytes = combine(authenticatorData, clientDataHash);
    const keyVaultClient = environment.keyVaultClient;
    if (!keyVaultClient) {
      throw new DOMException("Local cache mode cannot produce assertion signatures because it has no signing backend.", "NotSupportedError");
    }

    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toPlainArrayBuffer(signedBytes)));
    const signature = await keyVaultClient.signDigest(currentRecord.signingKeyId, digest);
    assertCeremonyNotCancelled(ceremonyId);
    const updatedRecord: BrowserStoredCredentialRecord = {
      ...currentRecord,
      signCount: nextSignCount,
      updatedAt: new Date().toISOString()
    };

    await saveCredentialRecord(updatedRecord, environment);

    return {
      id: currentRecord.credentialId,
      rawId: currentRecord.credentialId,
      type: "public-key",
      authenticatorAttachment: authenticatorProfile.authenticatorAttachment,
      clientExtensionResults: {},
      response: {
        kind: "assertion",
        clientDataJSON: toBase64Url(clientDataJSON),
        authenticatorData: toBase64Url(authenticatorData),
        signature: toBase64Url(signature),
        userHandle: currentRecord.userHandle
      }
    } satisfies SerializedPublicKeyCredential;
  });
}

function ensureEs256Supported(parameters: PublicKeyCredentialParameters[]): void {
  if (!parameters.some((parameter) => parameter.type === "public-key" && parameter.alg === -7)) {
    throw new DOMException("Only ES256 passkeys are supported by this Key Vault spike.", "NotSupportedError");
  }
}

function assertUserVerificationSupported(userVerification: UserVerificationRequirement | undefined): void {
  if (userVerification === "required") {
    throw new DOMException(
      "This software-only extension cannot truthfully satisfy required WebAuthn user verification. Use a platform authenticator or a future native Windows Hello companion.",
      "NotSupportedError"
    );
  }
}

async function requestUserPresence(context: {
  ceremonyId: string;
  operation: WebAuthnOperation;
  rpId: string;
  origin: string;
  topOrigin: string | null;
  accountName: string | null;
  credentialOptions?: CredentialSelectionOption[];
  authorizationWindowMs: number;
}): Promise<string | null> {
  assertCeremonyNotCancelled(context.ceremonyId);
  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + context.authorizationWindowMs).toISOString();
  const decisionPromise = ceremonyAuthorizations.begin({
    sessionId,
    ceremonyId: context.ceremonyId,
    operation: context.operation,
    rpId: context.rpId,
    origin: context.origin,
    topOrigin: context.topOrigin,
    accountName: context.accountName,
    credentialOptions: context.credentialOptions ?? [],
    expiresAt
  });

  const url = chrome.runtime.getURL(`uv-dialog.html?sessionId=${encodeURIComponent(sessionId)}`);
  try {
    const popupWindow = await createPopupWindow(url);
    if (popupWindow.id != null && !ceremonyAuthorizations.attachWindow(sessionId, popupWindow.id)) {
      void removeWindowById(popupWindow.id);
    }
  } catch (error) {
    ceremonyAuthorizations.fail(sessionId, error);
  }

  const decision = await decisionPromise;

  if (!decision.approved) {
    throw new DOMException("The user cancelled or did not approve the passkey request.", "NotAllowedError");
  }

  assertCeremonyNotCancelled(context.ceremonyId);
  return decision.credentialId;
}

function resolveCeremonyAuthorizationWindowMs(requestedTimeout: number | undefined): number {
  if (typeof requestedTimeout !== "number" || !Number.isFinite(requestedTimeout)) {
    return ceremonyAuthorizationWindowMs;
  }

  return Math.max(1_000, Math.min(ceremonyAuthorizationWindowMs, requestedTimeout));
}

function markCeremonyCancelled(ceremonyId: string): void {
  if (!activeCeremonyIds.has(ceremonyId)) {
    return;
  }

  cancelledCeremonyIds.add(ceremonyId);
  ceremonyAuthorizations.cancelByCeremonyId(ceremonyId);
}

function assertCeremonyNotCancelled(ceremonyId: string): void {
  if (cancelledCeremonyIds.has(ceremonyId)) {
    throw new DOMException("The WebAuthn request was cancelled.", "AbortError");
  }
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
        reject(new Error("Failed to open the passkey authorization window."));
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
  return Array.from(new Set(origins.filter((origin) => origin.startsWith("http://") || origin.startsWith("https://")))).sort();
}

async function unregisterDynamicContentScript(): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.scripting.unregisterContentScripts({ ids: [dynamicContentScriptId] }, () => {
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
        allFrames: true,
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
    signCount: 0,
    state: "pending"
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
    signCount: record.signCount,
    state: record.state
  };
}

function toVisibleStoredCredentialSummaries(records: BrowserStoredCredentialRecord[]): StoredCredentialSummary[] {
  return records
    .filter((record) => record.state !== "deleted")
    .map(toStoredCredentialSummary)
    .sort(compareStoredCredentialSummaries);
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
  void rpId;
  return {
    authenticatorAttachment: null,
    transports: [],
    aaguidHex: opaqueAuthenticatorAaguidHex
  };
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
  const originUrl = new URL(origin);
  const originHostname = normalizeHostname(originUrl.hostname);
  const candidateRpId = normalizeHostname(rpId);

  if (originUrl.protocol !== "https:" && !(originUrl.protocol === "http:" && isLocalDevelopmentHost(originHostname))) {
    throw new DOMException("WebAuthn interception requires HTTPS except on loopback development origins.", "SecurityError");
  }

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
  return value === "localhost" || value === "127.0.0.1" || value === "[::1]";
}

function assertRuntimeMessageSender(message: RuntimeRequest, sender: chrome.runtime.MessageSender): void {
  if (sender.id !== chrome.runtime.id || !sender.url) {
    throw new DOMException("Rejected a runtime message from an unknown sender.", "SecurityError");
  }

  const senderUrl = new URL(sender.url);
  if (message.kind === "webauthn-request" || message.kind === "cancel-webauthn-request") {
    const claimedOrigin = message.kind === "webauthn-request" ? message.clientData.origin : message.origin;
    if (!sender.tab || senderUrl.protocol === "chrome-extension:" || senderUrl.origin !== claimedOrigin) {
      throw new DOMException("WebAuthn requests must originate from the extension content script.", "SecurityError");
    }
    return;
  }

  const extensionOrigin = new URL(chrome.runtime.getURL("/")).origin;
  if (senderUrl.origin !== extensionOrigin) {
    throw new DOMException("Extension control messages must originate from an extension-owned page.", "SecurityError");
  }

  if (message.kind === "get-ceremony-authorization-session"
    || message.kind === "approve-ceremony-authorization-session"
    || message.kind === "cancel-ceremony-authorization-session") {
    const authorizationPath = new URL(chrome.runtime.getURL("uv-dialog.html")).pathname;
    if (senderUrl.pathname !== authorizationPath) {
      throw new DOMException("Passkey authorization messages must originate from the authorization window.", "SecurityError");
    }
  }
}

function validateSecurityConfiguration(config: typeof defaultExtensionState.config): void {
  assertGuid(config.tenantId, "Tenant ID");
  assertGuid(config.clientId, "Client ID");
  normalizeEntraAuthorityHost(config.authorityHost);

  if (config.metadataTransportMode === "KeyVaultSecrets") {
    const vaultBaseUrl = normalizeKeyVaultBaseUrl(config.keyVaultBaseUrl);
    normalizeKeyVaultKeyPath(vaultBaseUrl, config.signingKeyName);
    normalizeKeyVaultKeyPath(vaultBaseUrl, config.metadataWrappingKeyName);
  }
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
