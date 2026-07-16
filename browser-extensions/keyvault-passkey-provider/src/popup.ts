import { type BrowserAuthStatus, type ExtensionState, type MetadataSummary, type PinUvStatus, type RuntimeRequest, type RuntimeResponse, type StoredCredentialSummary } from "./shared/protocol";
import { evaluateSetupProgress, getSetupIncompleteMessage, isConfigReady } from "./shared/setup-state";

const enabledInput = requireElement<HTMLInputElement>("#enabled");
const openSetupWizardButton = requireElement<HTMLButtonElement>("#openSetupWizard");
const refreshPopupButton = requireElement<HTMLButtonElement>("#refreshPopup");
const signInButton = requireElement<HTMLButtonElement>("#signIn");
const signOutButton = requireElement<HTMLButtonElement>("#signOut");
const lockNowButton = requireElement<HTMLButtonElement>("#lockNow");
const unlockPanelElement = requireElement<HTMLElement>("#unlockPanel");
const unlockPinInput = requireElement<HTMLInputElement>("#unlockPin");
const unlockButton = requireElement<HTMLButtonElement>("#unlockButton");
const unlockHintElement = requireElement<HTMLElement>("#unlockHint");
const statusElement = requireElement<HTMLElement>("#status");
const setupSummaryElement = requireElement<HTMLElement>("#setupSummary");
const setupDetailElement = requireElement<HTMLElement>("#setupDetail");
const configStatusElement = requireElement<HTMLElement>("#configStatus");
const authStatusElement = requireElement<HTMLElement>("#authStatus");
const pinStatusElement = requireElement<HTMLElement>("#pinUvStatus");
const interceptStatusElement = requireElement<HTMLElement>("#interceptStatus");
const storedCredentialCountElement = requireElement<HTMLElement>("#storedCredentialCount");
const relyingPartyCountElement = requireElement<HTMLElement>("#relyingPartyCount");
const metadataLastUpdatedAtElement = requireElement<HTMLElement>("#metadataLastUpdatedAt");
const currentSiteOriginElement = requireElement<HTMLElement>("#currentSiteOrigin");
const currentSiteAccessElement = requireElement<HTMLElement>("#currentSiteAccess");
const currentSitePasskeysElement = requireElement<HTMLElement>("#currentSitePasskeys");
const allowCurrentSiteButton = requireElement<HTMLButtonElement>("#allowCurrentSite");
const removeCurrentSiteButton = requireElement<HTMLButtonElement>("#removeCurrentSite");
const reloadCurrentSiteButton = requireElement<HTMLButtonElement>("#reloadCurrentSite");
const storedCredentialListStatusElement = requireElement<HTMLElement>("#storedCredentialListStatus");
const storedCredentialListElement = requireElement<HTMLElement>("#storedCredentialList");
const refreshStoredCredentialsButton = requireElement<HTMLButtonElement>("#refreshStoredCredentials");

let latestState: ExtensionState | null = null;
let latestAuthStatus: BrowserAuthStatus | null = null;
let latestPinUvStatus: PinUvStatus | null = null;
let latestStoredCredentials: StoredCredentialSummary[] = [];
let interactiveUnlockRequired = false;
let currentSiteUrl: URL | null = null;
let currentSiteTabId: number | null = null;
let siteReloadNotice: { origin: string; reason: "grant" | "remove" } | null = null;

void initialize().catch((error) => {
  setStatus(error instanceof Error ? error.message : "Unable to initialize the extension popup.", true);
  document.body.dataset.popupReady = "error";
});

async function initialize() {
  const state = await loadPopupState();
  if (!state.ok || !("state" in state)) {
    setStatus(state.ok ? "Unable to load extension state." : state.error.message, true);
    document.body.dataset.popupReady = "error";
    return;
  }

  renderState(state.state);
  interactiveUnlockRequired = "interactiveUnlockAllowed" in state && state.interactiveUnlockAllowed;
  await runStartupRefresh(() => refreshAll());

  openSetupWizardButton.addEventListener("click", async () => {
    try {
      await openSetupWizard();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to open the setup wizard.", true);
    }
  });

  refreshPopupButton.addEventListener("click", async () => {
    await refreshAll();
    setStatus("Refreshed extension status.");
  });

  enabledInput.addEventListener("change", async () => {
    const response = await sendRuntimeMessage({ kind: "set-enabled", enabled: enabledInput.checked });
    if (!response.ok || !("state" in response)) {
      await refreshState();
      setStatus(response.ok ? "Unable to update enabled state." : response.error.message, true);
      return;
    }

    renderState(response.state);
    await refreshPinUvStatus();
    await refreshStoredCredentials();
    setStatus(response.state.enabled ? "Extension intercept enabled." : "Extension intercept disabled.");
  });

  signInButton.addEventListener("click", async () => {
    setStatus("Starting interactive Entra sign-in...");
    const response = await sendRuntimeMessage({ kind: "begin-sign-in" });
    if (!response.ok || !("authStatus" in response)) {
      setStatus(response.ok ? "Unable to complete sign-in." : response.error.message, true);
      return;
    }

    interactiveUnlockRequired = false;
    clearUnlockInput();
    await refreshAll();
    setStatus("Interactive sign-in completed.");
  });

  lockNowButton.addEventListener("click", async () => {
    const response = await sendRuntimeMessage({ kind: "lock-extension" });
    if (!response.ok || !("locked" in response)) {
      setStatus(response.ok ? "Unable to lock the extension." : response.error.message, true);
      return;
    }

    interactiveUnlockRequired = false;
    clearUnlockInput();
    renderState(response.state);
    renderAuthStatus(response.authStatus);
    setStatus("Extension locked. Unlock with the extension PIN to continue.");
  });

  unlockButton.addEventListener("click", async () => {
    const pin = unlockPinInput.value;
    if (!pin) {
      setStatus("Enter the extension PIN to unlock.", true);
      return;
    }

    const response = await sendRuntimeMessage({ kind: "unlock-extension", pin });
    if (!response.ok || !("unlockOutcome" in response)) {
      setStatus(response.ok ? "Unable to unlock the extension." : response.error.message, true);
      return;
    }

    interactiveUnlockRequired = response.unlockOutcome === "interactive-sign-in-required";
    clearUnlockInput();
    renderState(response.state);
    renderAuthStatus(response.authStatus);
    await refreshStoredCredentials();
    setStatus(response.unlockOutcome === "unlocked"
      ? "Extension unlocked."
      : "PIN verified. Browser SSO could not restore the session. Use Sign In to finish unlocking.");
  });

  signOutButton.addEventListener("click", async () => {
    const response = await sendRuntimeMessage({ kind: "sign-out" });
    if (!response.ok || !("authStatus" in response)) {
      setStatus(response.ok ? "Unable to clear cached sign-in state." : response.error.message, true);
      return;
    }

    interactiveUnlockRequired = false;
    clearUnlockInput();
    await refreshAll();
    setStatus("Cleared the cached API token for this extension. Unlock with the extension PIN to continue.");
  });

  refreshStoredCredentialsButton.addEventListener("click", async () => {
    await refreshStoredCredentials();
    setStatus("Refreshed stored passkeys.");
  });

  allowCurrentSiteButton.addEventListener("click", async () => {
    if (!currentSiteUrl) {
      setStatus("Open a regular website tab to grant site access.", true);
      return;
    }

    const granted = await requestCurrentSiteAccess(currentSiteUrl);
    if (!granted) {
      setStatus("Site access was not granted.", true);
      return;
    }

    if (currentSiteTabId !== null) {
      try {
        await injectContentScriptIntoTab(currentSiteTabId);
      } catch {
        // A reload remains the reliable fallback for document-start interception.
      }
    }

    siteReloadNotice = { origin: currentSiteUrl.origin, reason: "grant" };
    await refreshCurrentSite();
    setStatus("Granted site access. Reload if this page already loaded before the grant.");
  });

  removeCurrentSiteButton.addEventListener("click", async () => {
    if (!currentSiteUrl) {
      setStatus("Open a regular website tab to remove site access.", true);
      return;
    }

    const removed = await removeCurrentSiteAccess(currentSiteUrl);
    if (!removed) {
      setStatus("Site access was not removed.", true);
      return;
    }

    siteReloadNotice = { origin: currentSiteUrl.origin, reason: "remove" };
    await refreshCurrentSite();
    setStatus("Removed site access. Reload this page to clear the current-page injection.");
  });

  reloadCurrentSiteButton.addEventListener("click", async () => {
    if (currentSiteTabId === null) {
      setStatus("No reloadable website tab is active.", true);
      return;
    }

    await reloadCurrentSite(currentSiteTabId);
    siteReloadNotice = null;
    await refreshCurrentSite();
  });

  storedCredentialListElement.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLButtonElement)) {
      return;
    }

    const recordId = target.dataset.recordId;
    const action = target.dataset.action;
    if (!recordId) {
      return;
    }

    const entry = latestStoredCredentials.find((item) => item.recordId === recordId);
    if (!entry) {
      setStatus("The selected passkey could not be found.", true);
      return;
    }

    if (action === "open") {
      target.disabled = true;
      try {
        const granted = await requestCredentialLoginAccess(entry);
        if (!granted) {
          setStatus("Host access is required to apply the captured User-Agent on the login tab.", true);
          return;
        }
        setStatus(`Opening a login tab for ${entry.userName}...`);
        const response = await sendRuntimeMessage({ kind: "open-stored-credential", recordId });
        if (!response.ok || !("openedTabId" in response)) {
          setStatus(response.ok ? "Unable to open the passkey login." : response.error.message, true);
          return;
        }
        setStatus(response.userAgentApplied
          ? `Opened login for ${entry.userName} with its captured User-Agent.`
          : `Opened login for ${entry.userName}, but no captured User-Agent was available.`);
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Unable to open the passkey login.", true);
      } finally {
        target.disabled = false;
      }
      return;
    }

    if (action !== "remove") {
      return;
    }

    const confirmed = window.confirm(`Remove the stored passkey for ${entry.rpId} (${entry.userDisplayName})? This deletes its Key Vault signing key, Function catalog metadata, and stored login context.`);
    if (!confirmed) {
      return;
    }

    target.disabled = true;
    const response = await sendRuntimeMessage({ kind: "delete-stored-credential", recordId });
    if (!response.ok || !("storedCredentials" in response)) {
      target.disabled = false;
      setStatus(response.ok ? "Unable to remove the stored passkey." : response.error.message, true);
      return;
    }

    renderStoredCredentials(response.storedCredentials);
    await refreshMetadataSummary();
    setStatus(`Removed stored passkey for ${entry.rpId}.`);
  });

  chrome.tabs.onActivated.addListener(() => {
    void refreshCurrentSite();
  });
  chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
    if (tab.active && (changeInfo.url || changeInfo.status === "complete")) {
      void refreshCurrentSite();
    }
  });

  document.body.dataset.popupReady = "true";
}

async function loadPopupState(attempts = 20): Promise<RuntimeResponse> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await sendRuntimeMessage({ kind: "get-state" });
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      await delay(250 * (attempt + 1));
    }
  }

  throw lastError ?? new Error("Unable to initialize the extension popup.");
}

function renderState(state: ExtensionState) {
  latestState = state;
  enabledInput.checked = state.enabled;
  renderOverview();
}

async function refreshMetadataSummary() {
  const response = await sendRuntimeMessage({ kind: "get-metadata-summary" });
  if (!response.ok || !("summary" in response)) {
    setStatus(response.ok ? "Unable to read metadata summary." : response.error.message, true);
    return;
  }

  renderMetadataSummary(response.summary);
}

async function refreshAuthStatus() {
  const response = await sendRuntimeMessage({ kind: "get-auth-status" });
  if (!response.ok || !("authStatus" in response)) {
    setStatus(response.ok ? "Unable to read auth status." : response.error.message, true);
    return;
  }

  renderAuthStatus(response.authStatus);
}

function renderMetadataSummary(summary: MetadataSummary) {
  storedCredentialCountElement.textContent = summary.storedCredentialCount.toString();
  relyingPartyCountElement.textContent = summary.relyingPartyCount.toString();
  metadataLastUpdatedAtElement.textContent = summary.lastUpdatedAt ?? "never";
}

async function refreshStoredCredentials() {
  const state = latestState;
  const authStatus = latestAuthStatus;
  if (!state || !authStatus) {
    return;
  }

  if (state.config.metadataTransportMode === "KeyVaultSecrets" && authStatus.mode !== "signed-in") {
    renderStoredCredentials([]);
    storedCredentialListStatusElement.textContent = state.lockedAt
      ? "Unlock the extension before viewing stored passkeys."
      : "Sign in to view stored passkeys.";
    return;
  }

  const response = await sendRuntimeMessage({ kind: "get-stored-credentials" });
  if (!response.ok || !("storedCredentials" in response)) {
    renderStoredCredentials([]);
    storedCredentialListStatusElement.textContent = response.ok ? "Unable to read stored passkeys." : response.error.message;
    return;
  }

  renderStoredCredentials(response.storedCredentials);
}

function renderStoredCredentials(records: StoredCredentialSummary[]) {
  latestStoredCredentials = records;
  storedCredentialListElement.replaceChildren();

  if (records.length === 0) {
    const emptyState = document.createElement("p");
    emptyState.className = "credential-list-empty";
    emptyState.textContent = "No stored passkeys yet.";
    storedCredentialListElement.append(emptyState);
    storedCredentialListStatusElement.textContent = "No stored passkeys yet.";
    return;
  }

  storedCredentialListStatusElement.textContent = `${records.length} stored passkey${records.length === 1 ? "" : "s"}.`;

  const groupedRecords = groupStoredCredentials(records);

  for (const [rpId, groupRecords] of groupedRecords.entries()) {
    const group = document.createElement("section");
    group.className = "credential-group";

    const header = document.createElement("div");
    header.className = "credential-group-header";

    const titleBlock = document.createElement("div");
    titleBlock.className = "field-stack";

    const title = document.createElement("strong");
    title.textContent = rpId;

    const summary = document.createElement("span");
    summary.className = "credential-item-subtitle";
    summary.textContent = `${groupRecords.length} account${groupRecords.length === 1 ? "" : "s"}`;

    titleBlock.append(title, summary);
    header.append(titleBlock);

    if (currentSiteUrl && matchesRelyingParty(currentSiteUrl.hostname, rpId)) {
      const badge = document.createElement("span");
      badge.className = "credential-group-badge";
      badge.textContent = "Current site";
      header.append(badge);
    }

    group.append(header);

    for (const record of groupRecords) {
      const item = document.createElement("article");
      item.className = "credential-item";

      const titleRow = document.createElement("div");
      titleRow.className = "credential-item-header";

      const credentialTitleBlock = document.createElement("div");
      credentialTitleBlock.className = "field-stack";

      const credentialTitle = document.createElement("strong");
      credentialTitle.textContent = record.userDisplayName || record.userName;

      const subtitle = document.createElement("span");
      subtitle.className = "credential-item-subtitle";
      subtitle.textContent = record.userDisplayName && record.userDisplayName !== record.userName
        ? record.userName
        : `Credential ${record.credentialId.slice(0, 10)}...`;

      credentialTitleBlock.append(credentialTitle, subtitle);

      const controls = document.createElement("div");
      controls.className = "credential-item-actions";

      const openButton = document.createElement("button");
      openButton.type = "button";
      openButton.className = "compact";
      openButton.dataset.action = "open";
      openButton.dataset.recordId = record.recordId;
      openButton.textContent = "Open";
      openButton.title = "Open Outlook with this passkey's username hint and captured User-Agent";

      const removeButton = document.createElement("button");
      removeButton.type = "button";
      removeButton.className = "secondary compact";
      removeButton.dataset.action = "remove";
      removeButton.dataset.recordId = record.recordId;
      removeButton.textContent = "Remove";

      controls.append(openButton, removeButton);

      titleRow.append(credentialTitleBlock, controls);

      const details = document.createElement("p");
      details.className = "credential-item-details";
      details.textContent = `Updated ${record.updatedAt}. Sign count ${record.signCount}.`;

      item.append(titleRow, details);
      group.append(item);
    }

    storedCredentialListElement.append(group);
  }
}

function renderAuthStatus(authStatus: BrowserAuthStatus) {
  latestAuthStatus = authStatus;
  const state = latestState;
  const pinStatus = latestPinUvStatus;
  const locked = Boolean(state && pinStatus && isLockReady(state, pinStatus) && state.lockedAt);
  const interactiveRecoveryActive = Boolean(
    interactiveUnlockRequired
    || (state?.lockReason === "token-expired" && locked)
  );
  const setupNeedsInteractiveSignIn = Boolean(
    state
    && pinStatus
    && !isLockReady(state, pinStatus)
    && state.config.metadataTransportMode === "KeyVaultSecrets"
    && authStatus.mode !== "signed-in"
  );
  signInButton.hidden = !(interactiveRecoveryActive || setupNeedsInteractiveSignIn);
  signInButton.disabled = authStatus.mode === "local-only"
    || authStatus.mode === "signed-in"
    || (locked && !interactiveRecoveryActive);
  signOutButton.disabled = authStatus.mode === "local-only" || authStatus.mode === "not-configured" || authStatus.mode === "signed-out";
  renderOverview();
}

async function refreshPinUvStatus() {
  const response = await sendRuntimeMessage({ kind: "get-pin-uv-status" });
  if (!response.ok || !("pinUvStatus" in response)) {
    setStatus(response.ok ? "Unable to read PIN UV status." : response.error.message, true);
    return;
  }

  renderPinUvStatus(response.pinUvStatus);
}

function renderPinUvStatus(status: PinUvStatus) {
  latestPinUvStatus = status;
  renderOverview();
}

async function refreshAll() {
  await refreshState();
  await refreshAuthStatus();
  await refreshPinUvStatus();
  await refreshMetadataSummary();
  await refreshStoredCredentials();
  await refreshCurrentSite();
}

function sendRuntimeMessage(message: RuntimeRequest): Promise<RuntimeResponse> {
  return sendRuntimeMessageWithRetry(message);
}

async function sendRuntimeMessageWithRetry(message: RuntimeRequest, attempts = 6): Promise<RuntimeResponse> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await new Promise<RuntimeResponse>((resolve, reject) => {
        chrome.runtime.sendMessage(message, (response: RuntimeResponse | undefined) => {
          const runtimeError = chrome.runtime.lastError;
          if (runtimeError) {
            reject(new Error(runtimeError.message));
            return;
          }

          if (!response) {
            reject(new Error("Extension did not return a popup response."));
            return;
          }

          resolve(response);
        });
      });
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      await delay(150 * (attempt + 1));
    }
  }

  throw lastError ?? new Error("Extension did not return a popup response.");
}

function setStatus(message: string, isError = false) {
  statusElement.textContent = message;
  statusElement.style.color = isError ? "#9a2f2f" : "#54606c";
}

function requireElement<TElement extends Element>(selector: string): TElement {
  const element = document.querySelector<TElement>(selector);
  if (!element) {
    throw new Error(`Popup UI element not found: ${selector}`);
  }

  return element;
}

function delay(timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, timeoutMs);
  });
}

function openSetupWizard(): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.runtime.openOptionsPage(() => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

function renderOverview() {
  const state = latestState;
  const authStatus = latestAuthStatus;
  const pinStatus = latestPinUvStatus;
  if (!state || !authStatus || !pinStatus) {
    return;
  }

  const setupProgress = evaluateSetupProgress(state.config, authStatus.mode, pinStatus.isConfigured);
  const lockReady = isLockReady(state, pinStatus);
  const locked = lockReady && Boolean(state.lockedAt);
  const interactiveRecoveryActive = interactiveUnlockRequired || state.lockReason === "token-expired";
  const authSummary = authStatus.mode === "local-only"
    ? "Local only"
    : authStatus.mode === "signed-in"
      ? "Signed in"
      : authStatus.mode === "signed-out"
        ? "Signed out"
        : "Configuration needed";
  const pinSummary = pinStatus.isConfigured
    ? `Configured${pinStatus.protectionMode === "key-vault-wrap" ? " · Key Vault" : " · Local"}`
    : "Set in wizard";

  setupSummaryElement.textContent = locked
    ? interactiveRecoveryActive
      ? "Session expired"
      : "Locked"
    : setupProgress.isComplete
      ? (state.enabled ? "Ready" : "Configured")
      : "Setup required";
  setupDetailElement.textContent = locked
    ? interactiveRecoveryActive
      ? "PIN verified. Complete interactive sign-in to restore a fresh API session."
      : `Unlock with the extension PIN. Timeout: ${state.lockTimeoutMinutes} minutes.${formatLockReason(state.lockReason)}`
    : setupProgress.isComplete
      ? (state.enabled ? "Extension intercept is active." : "Setup is complete. Turn on intercept when you are ready.")
      : getSetupIncompleteMessage(setupProgress, state.config);
  configStatusElement.textContent = setupProgress.configReady ? "Saved" : "Needed";
  authStatusElement.textContent = locked
    ? interactiveRecoveryActive
      ? "Sign in needed"
      : "Locked"
    : setupProgress.authReady
      ? authSummary
      : (state.config.metadataTransportMode === "LocalCacheOnly" ? "Local only" : "Sign in required");
  pinStatusElement.textContent = pinSummary;
  interceptStatusElement.textContent = locked ? "Locked" : state.enabled ? "On" : setupProgress.isComplete ? "Off" : "Locked";
  enabledInput.disabled = !setupProgress.isComplete || locked;
  unlockPanelElement.hidden = !locked;
  unlockButton.hidden = !locked;
  lockNowButton.hidden = !lockReady || locked;
  unlockHintElement.textContent = interactiveRecoveryActive
    ? "PIN verified. Browser SSO could not restore the session. Use Sign In to complete unlock."
    : "Enter the extension PIN to unlock. A still-valid cached API session will be restored without another sign-in.";
}

async function refreshCurrentSite() {
  const activeTab = await getActiveTab();
  if (!activeTab?.url) {
    currentSiteUrl = null;
    currentSiteTabId = null;
    siteReloadNotice = null;
    currentSiteOriginElement.textContent = "No active website";
    currentSiteAccessElement.textContent = "Open a regular http or https tab to inspect current-site status.";
    currentSitePasskeysElement.textContent = "Current-site passkeys are shown when a website tab is active.";
    renderCurrentSiteActions(false, false, false);
    return;
  }

  const parsedUrl = tryParseHttpUrl(activeTab.url);
  if (!parsedUrl) {
    currentSiteUrl = null;
    currentSiteTabId = null;
    siteReloadNotice = null;
    currentSiteOriginElement.textContent = activeTab.url;
    currentSiteAccessElement.textContent = "This tab does not expose website host access information.";
    currentSitePasskeysElement.textContent = "Switch to a regular website tab to inspect current-site passkeys.";
    renderCurrentSiteActions(false, false, false);
    return;
  }

  currentSiteUrl = parsedUrl;
  currentSiteTabId = activeTab.id ?? null;
  const siteHost = parsedUrl.hostname;
  currentSiteOriginElement.textContent = parsedUrl.origin;

  const hasSiteAccess = await hasCurrentSiteAccess(toHostPermissionPattern(parsedUrl));
  const reloadRecommended = siteReloadNotice?.origin === parsedUrl.origin;
  currentSiteAccessElement.textContent = hasSiteAccess
    ? reloadRecommended && siteReloadNotice?.reason === "grant"
      ? "Host access is granted for this site. Reload if you need document-start interception on this already-open page."
      : "Host access is granted for this site. The extension can inject only on explicitly allowed websites now."
    : reloadRecommended && siteReloadNotice?.reason === "remove"
      ? "Host access was removed for this site. Reload this page to clear the current-page injection."
      : "Host access is not granted for this site. Allow access to enable interception here.";
  renderCurrentSiteActions(!hasSiteAccess, hasSiteAccess, reloadRecommended);

  const matchingPasskeys = latestStoredCredentials.filter((record) => matchesRelyingParty(siteHost, record.rpId));
  currentSitePasskeysElement.textContent = matchingPasskeys.length > 0
    ? `${matchingPasskeys.length} stored passkey${matchingPasskeys.length === 1 ? "" : "s"} match this site.`
    : latestState?.lockedAt
      ? "Unlock the extension to inspect current-site passkeys."
      : "No stored passkeys currently match this site.";
}

async function runStartupRefresh(action: () => Promise<void>, attempts = 12): Promise<void> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await action();
      return;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      await delay(200 * (attempt + 1));
    }
  }

  throw lastError ?? new Error("Unable to refresh popup startup state.");
}

async function refreshState() {
  const response = await sendRuntimeMessage({ kind: "get-state" });
  if (!response.ok || !("state" in response)) {
    setStatus(response.ok ? "Unable to load extension state." : response.error.message, true);
    return;
  }

  interactiveUnlockRequired = "interactiveUnlockAllowed" in response && response.interactiveUnlockAllowed;
  renderState(response.state);
}

function isLockReady(state: ExtensionState, pinStatus: PinUvStatus): boolean {
  return isConfigReady(state.config) && pinStatus.isConfigured;
}

function formatLockReason(reason: ExtensionState["lockReason"]): string {
  if (reason === "browser-start") {
    return " Locked after browser restart.";
  }

  if (reason === "idle") {
    return " Locked after inactivity.";
  }

  if (reason === "manual-lock") {
    return " Locked manually.";
  }

  if (reason === "manual-sign-out") {
    return " Auth state was cleared for this extension.";
  }

  if (reason === "token-expired") {
    return " Sign in again because the cached API session expired.";
  }

  return "";
}

function clearUnlockInput() {
  unlockPinInput.value = "";
}

async function getActiveTab(): Promise<chrome.tabs.Tab | null> {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve(tabs[0] ?? null);
    });
  });
}

async function hasCurrentSiteAccess(origin: string): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.permissions.contains({ origins: [`${origin}/*`] }, (result) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        resolve(true);
        return;
      }

      resolve(result);
    });
  });
}

function renderCurrentSiteActions(showAllow: boolean, showRemove: boolean, showReload: boolean) {
  allowCurrentSiteButton.hidden = !showAllow;
  removeCurrentSiteButton.hidden = !showRemove;
  reloadCurrentSiteButton.hidden = !showReload;
}

function toHostPermissionPattern(url: URL): string {
  return `${url.protocol}//${url.hostname}/*`;
}

async function requestCredentialLoginAccess(record: StoredCredentialSummary): Promise<boolean> {
  const origins = record.rpId.toLowerCase() === "login.microsoft.com"
    ? [
      "https://outlook.office.com/*",
      "https://outlook.office365.com/*",
      "https://outlook.cloud.microsoft/*",
      "https://login.microsoftonline.com/*",
      "https://login.microsoft.com/*"
    ]
    : [`https://${record.rpId}/*`];

  return new Promise((resolve) => {
    chrome.permissions.request({ origins }, (granted) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        setStatus(runtimeError.message || "Unable to request login-site access.", true);
        resolve(false);
        return;
      }
      resolve(granted);
    });
  });
}

async function requestCurrentSiteAccess(url: URL): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.permissions.request({ origins: [toHostPermissionPattern(url)] }, (granted) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        setStatus(runtimeError.message || "Unable to grant site access.", true);
        resolve(false);
        return;
      }

      resolve(granted);
    });
  });
}

async function removeCurrentSiteAccess(url: URL): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.permissions.remove({ origins: [toHostPermissionPattern(url)] }, (removed) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        setStatus(runtimeError.message || "Unable to remove site access.", true);
        resolve(false);
        return;
      }

      resolve(removed);
    });
  });
}

async function injectContentScriptIntoTab(tabId: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] }, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

async function reloadCurrentSite(tabId: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.tabs.reload(tabId, {}, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

function tryParseHttpUrl(value: string): URL | null {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:"
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function matchesRelyingParty(hostname: string, rpId: string): boolean {
  return hostname === rpId || hostname.endsWith(`.${rpId}`);
}

function groupStoredCredentials(records: StoredCredentialSummary[]): Map<string, StoredCredentialSummary[]> {
  const groupedRecords = new Map<string, StoredCredentialSummary[]>();

  for (const record of records) {
    const existing = groupedRecords.get(record.rpId);
    if (existing) {
      existing.push(record);
      continue;
    }

    groupedRecords.set(record.rpId, [record]);
  }

  return groupedRecords;
}
