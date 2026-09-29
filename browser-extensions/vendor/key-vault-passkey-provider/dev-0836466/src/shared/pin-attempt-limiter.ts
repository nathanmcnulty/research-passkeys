import { getPinBlockExpiry, parsePinAttemptState, recordFailedPinAttempt, type PinAttemptState } from "./pin-attempt-policy";

const pinAttemptStorageKey = "kvpp.pinAttemptState";

let pinAttemptQueue: Promise<void> = Promise.resolve();

export function verifyPinWithAttemptLimit(verify: () => Promise<boolean>): Promise<boolean> {
  return enqueuePinAttemptOperation(async () => {
    const state = await getStoredPinAttemptState();
    const blockedUntil = getPinBlockExpiry(state, Date.now());
    if (blockedUntil) {
      throw new DOMException(`Too many incorrect PIN attempts. Try again after ${blockedUntil}.`, "NotAllowedError");
    }

    const verified = await verify();
    if (verified) {
      await removeStoredPinAttemptState();
      return true;
    }

    await setStoredPinAttemptState(recordFailedPinAttempt(state, Date.now()));
    return false;
  });
}

export function resetPinAttemptLimit(): Promise<void> {
  return enqueuePinAttemptOperation(removeStoredPinAttemptState);
}

function enqueuePinAttemptOperation<TResult>(operation: () => Promise<TResult>): Promise<TResult> {
  const result = pinAttemptQueue.then(operation, operation);
  pinAttemptQueue = result.then(() => undefined, () => undefined);
  return result;
}

async function getStoredPinAttemptState(): Promise<PinAttemptState | null> {
  const value = await new Promise<unknown>((resolve, reject) => {
    chrome.storage.local.get([pinAttemptStorageKey], (items: Record<string, unknown>) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(`Unable to read PIN attempt state: ${runtimeError.message}`));
        return;
      }

      resolve(items[pinAttemptStorageKey]);
    });
  });

  return parsePinAttemptState(value);
}

async function setStoredPinAttemptState(state: PinAttemptState): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.storage.local.set({ [pinAttemptStorageKey]: state }, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(`Unable to persist PIN attempt state: ${runtimeError.message}`));
        return;
      }

      resolve();
    });
  });
}

async function removeStoredPinAttemptState(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    chrome.storage.local.remove(pinAttemptStorageKey, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(`Unable to clear PIN attempt state: ${runtimeError.message}`));
        return;
      }

      resolve();
    });
  });
}
