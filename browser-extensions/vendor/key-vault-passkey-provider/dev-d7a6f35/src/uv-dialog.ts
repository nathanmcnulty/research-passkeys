import type { CeremonyAuthorizationSessionView, RuntimeRequest, RuntimeResponse } from "./shared/protocol";

const sessionId = new URL(location.href).searchParams.get("sessionId");
const titleElement = requireElement<HTMLElement>("#uvTitle");
const detailElement = requireElement<HTMLElement>("#uvDetails");
const verifyButton = requireElement<HTMLButtonElement>("#verify");
const cancelButton = requireElement<HTMLButtonElement>("#cancel");
const statusElement = requireElement<HTMLElement>("#status");
const credentialSelectionElement = requireElement<HTMLFieldSetElement>("#credentialSelection");
const credentialOptionsElement = requireElement<HTMLElement>("#credentialOptions");

void initialize().catch((error) => {
  setStatus(error instanceof Error ? error.message : "Unable to initialize the passkey authorization window.", true);
  verifyButton.disabled = true;
  cancelButton.disabled = false;
});

async function initialize() {
  if (!sessionId) {
    setStatus("Missing PIN verification session.", true);
    verifyButton.disabled = true;
    return;
  }

  try {
    const response = await loadCeremonyAuthorizationSession(sessionId);
    if (!response.ok || !("ceremonyAuthorizationSession" in response)) {
      setStatus(response.ok ? "Unable to load the passkey authorization request." : response.error.message, true);
      verifyButton.disabled = true;
      return;
    }

    renderSession(response.ceremonyAuthorizationSession);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Unable to load the PIN verification request.", true);
    verifyButton.disabled = true;
    return;
  }

  verifyButton.addEventListener("click", async () => {
    await approveRequest();
  });

  cancelButton.addEventListener("click", async () => {
    await cancelSession();
  });

  verifyButton.focus();
}

async function loadCeremonyAuthorizationSession(nextSessionId: string, attempts = 20): Promise<RuntimeResponse> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await sendRuntimeMessage({ kind: "get-ceremony-authorization-session", sessionId: nextSessionId });
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      await delay(250 * (attempt + 1));
    }
  }

  throw lastError ?? new Error("Unable to initialize the passkey authorization window.");
}

function renderSession(session: CeremonyAuthorizationSessionView) {
  titleElement.textContent = session.operation === "create" ? "Confirm Passkey Registration" : "Confirm Passkey Sign-In";
  detailElement.textContent = [
    `RP ID: ${session.rpId}`,
    `Origin: ${session.origin}`,
    ...(session.topOrigin ? [`Top origin: ${session.topOrigin}`] : []),
    ...(session.accountName ? [`Account: ${session.accountName}`] : []),
    `Expires: ${session.expiresAt}`
  ].join("\n");

  renderCredentialOptions(session.credentialOptions);
  if (session.credentialOptions.length > 0) {
    verifyButton.textContent = "Use Selected Passkey";
  }
}

function renderCredentialOptions(options: CeremonyAuthorizationSessionView["credentialOptions"]) {
  credentialOptionsElement.replaceChildren();
  credentialSelectionElement.hidden = options.length === 0;

  options.forEach((option, index) => {
    const label = document.createElement("label");
    label.className = "credential-option";

    const input = document.createElement("input");
    input.type = "radio";
    input.name = "credentialId";
    input.value = option.credentialId;
    input.checked = index === 0;

    const text = document.createElement("span");
    text.className = "credential-option-text";
    const displayName = document.createElement("strong");
    displayName.textContent = option.userDisplayName || option.userName;
    const userName = document.createElement("span");
    userName.textContent = option.userName;
    const rpId = document.createElement("small");
    rpId.textContent = option.rpId;
    text.append(displayName, userName, rpId);

    label.append(input, text);
    credentialOptionsElement.appendChild(label);
  });
}

async function approveRequest() {
  if (!sessionId) {
    return;
  }

  verifyButton.disabled = true;
  cancelButton.disabled = true;
  setStatus("Approving this passkey request...");

  try {
    const credentialId = credentialSelectionElement.hidden
      ? undefined
      : credentialOptionsElement.querySelector<HTMLInputElement>('input[name="credentialId"]:checked')?.value;
    if (!credentialSelectionElement.hidden && !credentialId) {
      setStatus("Choose a passkey account before continuing.", true);
      return;
    }

    const response = await sendRuntimeMessage({ kind: "approve-ceremony-authorization-session", sessionId, credentialId });
    if (!response.ok || !("approved" in response) || !response.approved) {
      setStatus(response.ok ? "Unable to approve the passkey request." : response.error.message, true);
      return;
    }

    setStatus("Approved. Completing the passkey ceremony...");
    window.close();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Unable to verify the PIN.", true);
  } finally {
    verifyButton.disabled = false;
    cancelButton.disabled = false;
  }
}

async function cancelSession() {
  if (!sessionId) {
    window.close();
    return;
  }

  try {
    await sendRuntimeMessage({ kind: "cancel-ceremony-authorization-session", sessionId });
  } catch {
    // Best-effort cancellation only.
  }

  window.close();
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
            reject(new Error("Extension did not return an authorization dialog response."));
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

  throw lastError ?? new Error("Extension did not return an authorization dialog response.");
}

function setStatus(message: string, isError = false) {
  statusElement.textContent = message;
  statusElement.style.color = isError ? "#9a2f2f" : "#54606c";
}

function requireElement<TElement extends Element>(selector: string): TElement {
  const element = document.querySelector<TElement>(selector);
  if (!element) {
    throw new Error(`UV dialog element not found: ${selector}`);
  }

  return element;
}

function delay(timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, timeoutMs);
  });
}
