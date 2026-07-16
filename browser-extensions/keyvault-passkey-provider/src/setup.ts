import { type BrowserAuthStatus, type BrowserExtensionConfig, type ExtensionState, type MetadataSummary, type PinUvStatus, type RuntimeRequest, type RuntimeResponse } from "./shared/protocol";
import { evaluateSetupProgress, type SetupProgress } from "./shared/setup-state";
import { clampLockTimeoutMinutes, lockTimeoutMinuteOptions } from "./shared/storage";

type SetupStep = "config" | "auth" | "pin" | "finish";

const progressSteps: SetupStep[] = ["config", "auth", "pin", "finish"];

const statusElement = requireElement<HTMLElement>("#status");
const setupOverallStatusElement = requireElement<HTMLElement>("#setupOverallStatus");
const enabledStatusElement = requireElement<HTMLElement>("#enabledStatus");
const storedCredentialCountElement = requireElement<HTMLElement>("#storedCredentialCount");
const relyingPartyCountElement = requireElement<HTMLElement>("#relyingPartyCount");
const metadataLastUpdatedAtElement = requireElement<HTMLElement>("#metadataLastUpdatedAt");

const tenantIdInput = requireElement<HTMLInputElement>("#tenantId");
const clientIdInput = requireElement<HTMLInputElement>("#clientId");
const developmentFunctionAppBaseUrlInput = requireElement<HTMLInputElement>("#developmentFunctionAppBaseUrl");
const lockTimeoutMinutesInput = requireElement<HTMLSelectElement>("#lockTimeoutMinutes");

const authStatusElement = requireElement<HTMLElement>("#authStatus");
const authStepHintElement = requireElement<HTMLElement>("#authStepHint");
const pinUvStatusElement = requireElement<HTMLElement>("#pinUvStatus");
const lockTimeoutSummaryElement = requireElement<HTMLElement>("#lockTimeoutSummary");
const currentPinFieldElement = requireElement<HTMLElement>("#currentPinField");
const currentPinInput = requireElement<HTMLInputElement>("#currentPin");
const newPinInput = requireElement<HTMLInputElement>("#newPin");
const confirmPinInput = requireElement<HTMLInputElement>("#confirmPin");
const pinHintElement = requireElement<HTMLElement>("#pinHint");

const stepElements = new Map<SetupStep, HTMLElement>([
  ["config", requireElement<HTMLElement>("#step-config")],
  ["auth", requireElement<HTMLElement>("#step-auth")],
  ["pin", requireElement<HTMLElement>("#step-pin")],
  ["finish", requireElement<HTMLElement>("#step-finish")]
]);

const progressElements = new Map<SetupStep, HTMLButtonElement>([
  ["config", requireElement<HTMLButtonElement>("#progress-config")],
  ["auth", requireElement<HTMLButtonElement>("#progress-auth")],
  ["pin", requireElement<HTMLButtonElement>("#progress-pin")],
  ["finish", requireElement<HTMLButtonElement>("#progress-finish")]
]);

const progressStatusElements = new Map<SetupStep, HTMLElement>([
  ["config", requireElement<HTMLElement>("#progress-config-status")],
  ["auth", requireElement<HTMLElement>("#progress-auth-status")],
  ["pin", requireElement<HTMLElement>("#progress-pin-status")],
  ["finish", requireElement<HTMLElement>("#progress-finish-status")]
]);

const saveConfigButton = requireElement<HTMLButtonElement>("#saveConfig");
const nextFromConfigButton = requireElement<HTMLButtonElement>("#nextFromConfig");
const backFromAuthButton = requireElement<HTMLButtonElement>("#backFromAuth");
const signInButton = requireElement<HTMLButtonElement>("#signIn");
const signOutButton = requireElement<HTMLButtonElement>("#signOut");
const nextFromAuthButton = requireElement<HTMLButtonElement>("#nextFromAuth");
const backFromPinButton = requireElement<HTMLButtonElement>("#backFromPin");
const savePinButton = requireElement<HTMLButtonElement>("#savePin");
const nextFromPinButton = requireElement<HTMLButtonElement>("#nextFromPin");
const backFromFinishButton = requireElement<HTMLButtonElement>("#backFromFinish");
const refreshSummaryButton = requireElement<HTMLButtonElement>("#refreshSummary");
const doneButton = requireElement<HTMLButtonElement>("#doneButton");

let latestState: ExtensionState | null = null;
let latestAuthStatus: BrowserAuthStatus | null = null;
let latestPinUvStatus: PinUvStatus | null = null;
let latestMetadataSummary: MetadataSummary | null = null;
let currentStep: SetupStep = "config";

void initialize().catch((error) => {
  setStatus(error instanceof Error ? error.message : "Unable to initialize the setup wizard.", true);
});

async function initialize() {
  populateLockTimeoutOptions();
  bindEvents();
  await refreshAll();
  navigateToStep(getStepFromHash() ?? deriveStepFromProgress(), true);
}

function bindEvents() {
  for (const step of progressSteps) {
    progressElements.get(step)?.addEventListener("click", () => {
      navigateToStep(step);
    });
  }

  window.addEventListener("hashchange", () => {
    const step = getStepFromHash();
    if (step) {
      navigateToStep(step, true);
    }
  });

  saveConfigButton.addEventListener("click", async () => {
    const config = readConfig();
    try {
      await updateDevelopmentFunctionHostPermission(
        latestState?.config.developmentFunctionAppBaseUrl ?? "",
        config.developmentFunctionAppBaseUrl
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to grant Function App host access.", true);
      return;
    }

    const response = await sendRuntimeMessage({ kind: "save-config", config, lockTimeoutMinutes: readLockTimeoutMinutes() });
    if (!response.ok || !("state" in response)) {
      setStatus(response.ok ? "Unable to save configuration." : response.error.message, true);
      return;
    }

    await refreshAll();
    navigateToStep(deriveStepFromProgress());
    setStatus("Saved extension configuration.");
  });

  nextFromConfigButton.addEventListener("click", () => {
    navigateToStep("auth");
  });

  backFromAuthButton.addEventListener("click", () => {
    navigateToStep("config");
  });

  signInButton.addEventListener("click", async () => {
    setStatus("Starting interactive Entra sign-in...");
    const response = await sendRuntimeMessage({ kind: "begin-sign-in" });
    if (!response.ok || !("authStatus" in response)) {
      setStatus(response.ok ? "Unable to complete sign-in." : response.error.message, true);
      return;
    }

    await refreshAll();
    navigateToStep(deriveStepFromProgress());
    setStatus("Interactive sign-in completed.");
  });

  signOutButton.addEventListener("click", async () => {
    const response = await sendRuntimeMessage({ kind: "sign-out" });
    if (!response.ok || !("authStatus" in response)) {
      setStatus(response.ok ? "Unable to clear cached sign-in state." : response.error.message, true);
      return;
    }

    await refreshAll();
    navigateToStep("auth");
    setStatus("Cleared cached Function API token state.");
  });

  nextFromAuthButton.addEventListener("click", () => {
    navigateToStep("pin");
  });

  backFromPinButton.addEventListener("click", () => {
    navigateToStep(needsAuthStep() ? "auth" : "config");
  });

  savePinButton.addEventListener("click", async () => {
    const newPin = newPinInput.value;
    if (latestPinUvStatus?.isConfigured && !currentPinInput.value) {
      setStatus("Enter the current PIN before resetting it.", true);
      return;
    }

    if (newPin !== confirmPinInput.value) {
      setStatus("The new PIN entries do not match.", true);
      return;
    }

    const response = await sendRuntimeMessage({
      kind: "set-pin-uv",
      newPin,
      currentPin: currentPinInput.value || undefined
    });
    if (!response.ok || !("pinUvStatus" in response)) {
      setStatus(response.ok ? "Unable to save the extension PIN." : response.error.message, true);
      return;
    }

    clearPinInputs();
    await refreshAll();
    navigateToStep(deriveStepFromProgress());
    setStatus("Saved the extension PIN.");
  });

  nextFromPinButton.addEventListener("click", () => {
    navigateToStep("finish");
  });

  backFromFinishButton.addEventListener("click", () => {
    navigateToStep("pin");
  });

  refreshSummaryButton.addEventListener("click", async () => {
    await refreshAll();
    setStatus("Refreshed extension summary.");
  });

  doneButton.addEventListener("click", async () => {
    try {
      await closeSetupView();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to close the setup page.", true);
    }
  });
}

async function refreshAll() {
  const [stateResponse, authResponse, pinResponse, metadataResponse] = await Promise.all([
    sendRuntimeMessage({ kind: "get-state" }),
    sendRuntimeMessage({ kind: "get-auth-status" }),
    sendRuntimeMessage({ kind: "get-pin-uv-status" }),
    sendRuntimeMessage({ kind: "get-metadata-summary" })
  ]);

  if (!stateResponse.ok || !("state" in stateResponse)) {
    throw new Error(stateResponse.ok ? "Unable to load extension state." : stateResponse.error.message);
  }

  if (!authResponse.ok || !("authStatus" in authResponse)) {
    throw new Error(authResponse.ok ? "Unable to load auth status." : authResponse.error.message);
  }

  if (!pinResponse.ok || !("pinUvStatus" in pinResponse)) {
    throw new Error(pinResponse.ok ? "Unable to load PIN state." : pinResponse.error.message);
  }

  if (!metadataResponse.ok || !("summary" in metadataResponse)) {
    throw new Error(metadataResponse.ok ? "Unable to load metadata summary." : metadataResponse.error.message);
  }

  latestState = stateResponse.state;
  latestAuthStatus = authResponse.authStatus;
  latestPinUvStatus = pinResponse.pinUvStatus;
  latestMetadataSummary = metadataResponse.summary;

  renderAll();
}

function renderAll() {
  if (!latestState || !latestAuthStatus || !latestPinUvStatus || !latestMetadataSummary) {
    return;
  }

  renderConfig(latestState);
  renderAuth(latestState.config, latestAuthStatus);
  renderPin(latestState.config, latestPinUvStatus, latestAuthStatus);
  renderSummary(latestState, latestMetadataSummary);
  renderProgress(evaluateSetupProgress(latestState.config, latestAuthStatus.mode, latestPinUvStatus.isConfigured));
}

function renderConfig(state: ExtensionState) {
  const config = state.config;
  tenantIdInput.value = config.tenantId;
  clientIdInput.value = config.clientId;
  developmentFunctionAppBaseUrlInput.value = config.developmentFunctionAppBaseUrl;
  lockTimeoutMinutesInput.value = clampLockTimeoutMinutes(state.lockTimeoutMinutes).toString();
}

function renderAuth(config: BrowserExtensionConfig, authStatus: BrowserAuthStatus) {
  const expiresSuffix = authStatus.expiresOn ? `\nExpires ${authStatus.expiresOn}.` : "";
  authStatusElement.textContent = authStatus.message
    ? `${authStatus.mode}: ${authStatus.message}${expiresSuffix}`
    : `${authStatus.mode}${expiresSuffix}`;

  const localOnly = config.metadataTransportMode === "LocalCacheOnly";
  authStepHintElement.textContent = localOnly
    ? "Local cache mode does not require Entra sign-in."
    : "Sign in to obtain an access token for the Function API. The extension never receives Key Vault access.";

  signInButton.disabled = localOnly || authStatus.mode === "signed-in";
  signOutButton.disabled = localOnly || authStatus.mode === "not-configured" || authStatus.mode === "signed-out";
}

function renderPin(config: BrowserExtensionConfig, pinStatus: PinUvStatus, authStatus: BrowserAuthStatus) {
  pinUvStatusElement.textContent = pinStatus.isConfigured
    ? `Configured${pinStatus.lastUpdatedAt ? ` since ${pinStatus.lastUpdatedAt}` : ""}. Protection: ${formatProtectionMode(pinStatus.protectionMode)}.`
    : "Not configured.";

  const requiresSignedInKeyVault = config.metadataTransportMode !== "LocalCacheOnly" && authStatus.mode !== "signed-in";
  currentPinFieldElement.hidden = !pinStatus.isConfigured;
  savePinButton.textContent = pinStatus.isConfigured ? "Reset PIN" : "Set PIN";
  savePinButton.disabled = requiresSignedInKeyVault;
  currentPinInput.placeholder = pinStatus.isConfigured ? "Required to change or remove the PIN" : "Not required for first-time setup";
  pinHintElement.textContent = pinStatus.isConfigured
    ? "Enter the current PIN, then choose a new PIN to reset it. Unlock always starts with this PIN."
    : requiresSignedInKeyVault
      ? "Complete Entra sign-in first, then set the browser-local extension PIN."
      : "Use at least 6 characters. Longer is stronger.";
}

function renderSummary(state: ExtensionState, summary: MetadataSummary) {
  enabledStatusElement.textContent = state.enabled ? "Enabled" : "Disabled";
  lockTimeoutSummaryElement.textContent = `${state.lockTimeoutMinutes} minute${state.lockTimeoutMinutes === 1 ? "" : "s"}`;
  storedCredentialCountElement.textContent = summary.storedCredentialCount.toString();
  relyingPartyCountElement.textContent = summary.relyingPartyCount.toString();
  metadataLastUpdatedAtElement.textContent = summary.lastUpdatedAt ?? "never";
}

function renderProgress(progress: SetupProgress) {
  setupOverallStatusElement.textContent = progress.isComplete ? "Complete" : "Setup required";

  progressStatusElements.get("config")!.textContent = progress.configReady ? "Saved" : "Pending";
  progressStatusElements.get("auth")!.textContent = progress.authReady ? (needsAuthStep() ? "Ready" : "Skipped") : "Pending";
  progressStatusElements.get("pin")!.textContent = progress.pinReady ? "Configured" : "Pending";
  progressStatusElements.get("finish")!.textContent = progress.isComplete ? "Ready" : "Locked";

  applyStepState("config", progress.configReady, currentStep === "config");
  applyStepState("auth", progress.authReady, currentStep === "auth");
  applyStepState("pin", progress.pinReady, currentStep === "pin");
  applyStepState("finish", progress.isComplete, currentStep === "finish");

  nextFromConfigButton.disabled = !progress.configReady;
  nextFromAuthButton.disabled = !progress.authReady;
  nextFromPinButton.disabled = !progress.pinReady;
}

function applyStepState(step: SetupStep, isComplete: boolean, isCurrent: boolean) {
  const button = progressElements.get(step);
  if (!button) {
    return;
  }

  button.classList.toggle("is-complete", isComplete);
  button.classList.toggle("is-current", isCurrent);
  button.setAttribute("aria-current", isCurrent ? "step" : "false");
}

function navigateToStep(step: SetupStep, skipHashUpdate = false) {
  currentStep = constrainStep(step);
  for (const [stepName, element] of stepElements.entries()) {
    element.hidden = stepName !== currentStep;
  }

  if (!skipHashUpdate) {
    const nextHash = `#${currentStep}`;
    if (window.location.hash !== nextHash) {
      window.location.hash = nextHash;
    }
  }

  if (latestState && latestAuthStatus && latestPinUvStatus) {
    renderProgress(evaluateSetupProgress(latestState.config, latestAuthStatus.mode, latestPinUvStatus.isConfigured));
  }
}

function constrainStep(requestedStep: SetupStep): SetupStep {
  const progress = latestState && latestAuthStatus && latestPinUvStatus
    ? evaluateSetupProgress(latestState.config, latestAuthStatus.mode, latestPinUvStatus.isConfigured)
    : null;

  if (!progress) {
    return requestedStep;
  }

  if (requestedStep === "auth" && !progress.configReady) {
    return "config";
  }

  if (requestedStep === "pin" && (!progress.configReady || !progress.authReady)) {
    return deriveStepFromProgress();
  }

  if (requestedStep === "finish" && !progress.isComplete) {
    return deriveStepFromProgress();
  }

  return requestedStep;
}

function deriveStepFromProgress(): SetupStep {
  if (!latestState || !latestAuthStatus || !latestPinUvStatus) {
    return "config";
  }

  const progress = evaluateSetupProgress(latestState.config, latestAuthStatus.mode, latestPinUvStatus.isConfigured);
  if (!progress.configReady) {
    return "config";
  }

  if (!progress.authReady) {
    return "auth";
  }

  if (!progress.pinReady) {
    return "pin";
  }

  return "finish";
}

function needsAuthStep(): boolean {
  return latestState?.config.metadataTransportMode !== "LocalCacheOnly";
}

function readConfig(): BrowserExtensionConfig {
  return {
    tenantId: tenantIdInput.value.trim(),
    clientId: clientIdInput.value.trim(),
    authorityHost: "https://login.microsoftonline.com",
    keyVaultBaseUrl: "",
    signingKeyName: "",
    signingKeyType: "EC",
    metadataWrappingKeyName: "",
    metadataTransportMode: "FunctionCatalog",
    metadataSecretPrefix: "",
    developmentFunctionAppBaseUrl: developmentFunctionAppBaseUrlInput.value.trim(),
    developmentFunctionAppKey: ""
  };
}

async function updateDevelopmentFunctionHostPermission(previousBaseUrl: string, nextBaseUrl: string): Promise<void> {
  const previousOrigin = previousBaseUrl.trim() ? toDevelopmentFunctionOriginPattern(previousBaseUrl) : null;
  const nextOrigin = nextBaseUrl.trim() ? toDevelopmentFunctionOriginPattern(nextBaseUrl) : null;

  if (nextOrigin) {
    const granted = await new Promise<boolean>((resolve, reject) => {
      chrome.permissions.request({ origins: [nextOrigin] }, (allowed) => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }
        resolve(allowed);
      });
    });

    if (!granted) {
      throw new Error("Function App host access is required when the development catalog adapter is configured.");
    }
  }

  if (previousOrigin && previousOrigin !== nextOrigin) {
    await new Promise<void>((resolve, reject) => {
      chrome.permissions.remove({ origins: [previousOrigin] }, () => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }
        resolve();
      });
    });
  }
}

function toDevelopmentFunctionOriginPattern(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error("Development Function App Base URL must be an absolute URL.");
  }

  const isLocalHttp = url.protocol === "http:"
    && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
  if (url.protocol !== "https:" && !isLocalHttp) {
    throw new Error("Development Function App Base URL must use HTTPS, except for localhost development.");
  }

  return `${url.protocol}//${url.hostname}/*`;
}

function readLockTimeoutMinutes(): number {
  return clampLockTimeoutMinutes(Number(lockTimeoutMinutesInput.value));
}

function clearPinInputs() {
  currentPinInput.value = "";
  newPinInput.value = "";
  confirmPinInput.value = "";
}

function populateLockTimeoutOptions() {
  lockTimeoutMinutesInput.replaceChildren();
  for (const timeoutMinutes of lockTimeoutMinuteOptions) {
    const option = document.createElement("option");
    option.value = timeoutMinutes.toString();
    option.textContent = `${timeoutMinutes} minutes`;
    lockTimeoutMinutesInput.append(option);
  }
}

function getStepFromHash(): SetupStep | null {
  const value = window.location.hash.replace(/^#/, "");
  return progressSteps.includes(value as SetupStep) ? value as SetupStep : null;
}

function setStatus(message: string, isError = false) {
  statusElement.textContent = message;
  statusElement.style.color = isError ? "#9a2f2f" : "#54606c";
}

function formatProtectionMode(value: PinUvStatus["protectionMode"]): string {
  return value === "key-vault-wrap" ? "Key Vault wrap" : "browser-local wrap";
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
            reject(new Error("Extension did not return a setup response."));
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

  throw lastError ?? new Error("Extension did not return a setup response.");
}

function requireElement<TElement extends Element>(selector: string): TElement {
  const element = document.querySelector<TElement>(selector);
  if (!element) {
    throw new Error(`Setup UI element not found: ${selector}`);
  }

  return element;
}

function delay(timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, timeoutMs);
  });
}

function closeSetupView(): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.tabs.getCurrent((tab) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      if (tab?.id == null) {
        window.close();
        resolve();
        return;
      }

      chrome.tabs.remove(tab.id, () => {
        const removeError = chrome.runtime.lastError;
        if (removeError) {
          reject(new Error(removeError.message));
          return;
        }

        resolve();
      });
    });
  });
}
