import { defaultExtensionState, type BrowserExtensionConfig, type ExtensionState, type LockReason } from "./protocol";

const storageKey = "kvpp.extension.state";
export const minLockTimeoutMinutes = 5;
export const maxLockTimeoutMinutes = 480;
export const lockTimeoutMinuteOptions = [5, 15, 30, 60, 120, 240, 480] as const;

function getFromStorage<T>(key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([key], (items) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve(items[key] as T | undefined);
    });
  });
}

function setInStorage(value: ExtensionState): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [storageKey]: value }, () => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve();
    });
  });
}

export async function loadExtensionState(): Promise<ExtensionState> {
  const stored = await getFromStorage<ExtensionState>(storageKey);
  return stored ? normalizeExtensionState(stored) : structuredClone(defaultExtensionState);
}

export async function ensureExtensionStateInitialized(): Promise<ExtensionState> {
  const stored = await getFromStorage<ExtensionState>(storageKey);
  if (stored) {
    return normalizeExtensionState(stored);
  }

  return saveExtensionState(structuredClone(defaultExtensionState));
}

export async function saveExtensionState(state: ExtensionState): Promise<ExtensionState> {
  const normalizedState = normalizeExtensionState(state);
  await setInStorage(normalizedState);
  return normalizedState;
}

export async function updateEnabled(enabled: boolean): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.enabled = enabled;
  return saveExtensionState(state);
}

export async function updateConfig(config: BrowserExtensionConfig): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.config = config;
  return saveExtensionState(state);
}

export async function updateLockTimeoutMinutes(lockTimeoutMinutes: number): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.lockTimeoutMinutes = clampLockTimeoutMinutes(lockTimeoutMinutes);
  return saveExtensionState(state);
}

export async function setLockState(reason: LockReason, lockedAt = new Date().toISOString()): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.lockedAt = lockedAt;
  state.lockReason = reason;
  return saveExtensionState(state);
}

export async function clearLockState(unlockedAt = new Date().toISOString()): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.lockedAt = null;
  state.lockReason = null;
  state.lastUnlockedAt = unlockedAt;
  state.lastActivityAt = unlockedAt;
  return saveExtensionState(state);
}

export async function resetLockStateTracking(): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.lockedAt = null;
  state.lastUnlockedAt = null;
  state.lastActivityAt = null;
  state.lockReason = null;
  state.rememberedLoginHint = null;
  state.interactiveUnlockExpiresAt = null;
  return saveExtensionState(state);
}

export async function updateInteractiveUnlockExpiresAt(interactiveUnlockExpiresAt: string | null): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.interactiveUnlockExpiresAt = interactiveUnlockExpiresAt;
  return saveExtensionState(state);
}

export async function touchLastActivity(at = new Date().toISOString()): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.lastActivityAt = at;
  return saveExtensionState(state);
}

export async function updateInterceptTelemetry(origin: string): Promise<ExtensionState> {
  const state = await loadExtensionState();
  state.lastInterceptedAt = new Date().toISOString();
  state.lastActivityAt = state.lastInterceptedAt;
  state.lastOrigin = origin;
  return saveExtensionState(state);
}

export function clampLockTimeoutMinutes(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return defaultExtensionState.lockTimeoutMinutes;
  }

  const normalized = Math.min(maxLockTimeoutMinutes, Math.max(minLockTimeoutMinutes, Math.trunc(value)));
  return lockTimeoutMinuteOptions.reduce((closest, option) =>
    Math.abs(option - normalized) < Math.abs(closest - normalized) ? option : closest
  );
}

function normalizeExtensionState(state: ExtensionState): ExtensionState {
  return {
    ...defaultExtensionState,
    ...state,
    config: {
      ...defaultExtensionState.config,
      ...state.config
    },
    lockTimeoutMinutes: clampLockTimeoutMinutes(state.lockTimeoutMinutes),
    lockedAt: state.lockedAt ?? null,
    lastUnlockedAt: state.lastUnlockedAt ?? null,
    lastActivityAt: state.lastActivityAt ?? null,
    lockReason: isLockReason(state.lockReason) ? state.lockReason : null,
    rememberedLoginHint: typeof state.rememberedLoginHint === "string" ? state.rememberedLoginHint : null,
    interactiveUnlockExpiresAt: state.interactiveUnlockExpiresAt ?? null,
    lastInterceptedAt: state.lastInterceptedAt ?? null,
    lastOrigin: state.lastOrigin ?? null
  };
}

function isLockReason(value: string | null | undefined): value is LockReason {
  return value === "idle"
    || value === "browser-start"
    || value === "manual-lock"
    || value === "manual-sign-out"
    || value === "token-expired";
}
