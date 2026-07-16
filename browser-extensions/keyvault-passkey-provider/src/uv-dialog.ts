import type { PinUvSessionView, RuntimeRequest, RuntimeResponse } from "./shared/protocol";

const sessionId = new URL(location.href).searchParams.get("sessionId");
const titleElement = requireElement<HTMLElement>("#uvTitle");
const detailElement = requireElement<HTMLElement>("#uvDetails");
const pinInput = requireElement<HTMLInputElement>("#pin");
const verifyButton = requireElement<HTMLButtonElement>("#verify");
const cancelButton = requireElement<HTMLButtonElement>("#cancel");
const statusElement = requireElement<HTMLElement>("#status");

void initialize().catch((error) => {
  setStatus(error instanceof Error ? error.message : "Unable to initialize the PIN verification window.", true);
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
    const response = await loadPinUvSession(sessionId);
    if (!response.ok || !("pinUvSession" in response)) {
      setStatus(response.ok ? "Unable to load the PIN verification request." : response.error.message, true);
      verifyButton.disabled = true;
      return;
    }

    renderSession(response.pinUvSession);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Unable to load the PIN verification request.", true);
    verifyButton.disabled = true;
    return;
  }

  verifyButton.addEventListener("click", async () => {
    await submitPin();
  });

  pinInput.addEventListener("keydown", async (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      await submitPin();
    }
  });

  cancelButton.addEventListener("click", async () => {
    await cancelSession();
  });

  pinInput.focus();
}

async function loadPinUvSession(nextSessionId: string, attempts = 20): Promise<RuntimeResponse> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await sendRuntimeMessage({ kind: "get-pin-uv-session", sessionId: nextSessionId });
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      await delay(250 * (attempt + 1));
    }
  }

  throw lastError ?? new Error("Unable to initialize the PIN verification window.");
}

function renderSession(session: PinUvSessionView) {
  titleElement.textContent = session.operation === "create" ? "Confirm Passkey Registration" : "Confirm Passkey Sign-In";
  detailElement.textContent = `RP ID: ${session.rpId}\nOrigin: ${session.origin}\nExpires: ${session.expiresAt}`;
}

async function submitPin() {
  if (!sessionId) {
    return;
  }

  const pin = pinInput.value;
  verifyButton.disabled = true;
  cancelButton.disabled = true;
  setStatus("Verifying PIN...");

  try {
    const response = await sendRuntimeMessage({ kind: "verify-pin-uv-session", sessionId, pin });
    if (!response.ok || !("verified" in response)) {
      setStatus(response.ok ? "Unable to verify the PIN." : response.error.message, true);
      return;
    }

    if (!response.verified) {
      setStatus("PIN verification failed. Try again.", true);
      pinInput.select();
      return;
    }

    setStatus("PIN verified. Completing the passkey ceremony...");
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
    await sendRuntimeMessage({ kind: "cancel-pin-uv-session", sessionId });
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
            reject(new Error("Extension did not return a UV dialog response."));
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

  throw lastError ?? new Error("Extension did not return a UV dialog response.");
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
