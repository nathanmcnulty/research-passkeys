export const pinAttemptFailureThreshold = 5;
export const pinAttemptBaseDelayMs = 30_000;
export const pinAttemptMaxDelayMs = 15 * 60_000;

export type PinAttemptState = {
  version: 1;
  failureCount: number;
  blockedUntil: string | null;
  updatedAt: string;
};

export function parsePinAttemptState(value: unknown): PinAttemptState | null {
  if (value === undefined || value === null) {
    return null;
  }

  if (!value || typeof value !== "object") {
    throw invalidPinAttemptState();
  }

  const candidate = value as Partial<PinAttemptState>;
  if (
    candidate.version !== 1
    || !Number.isSafeInteger(candidate.failureCount)
    || candidate.failureCount! < 0
    || !isValidDate(candidate.updatedAt)
    || (candidate.blockedUntil !== null && !isValidDate(candidate.blockedUntil))
  ) {
    throw invalidPinAttemptState();
  }

  return {
    version: 1,
    failureCount: candidate.failureCount!,
    blockedUntil: candidate.blockedUntil ?? null,
    updatedAt: candidate.updatedAt!
  };
}

export function getPinBlockExpiry(state: PinAttemptState | null, nowMs: number): string | null {
  if (!state?.blockedUntil) {
    return null;
  }

  return Date.parse(state.blockedUntil) > nowMs ? state.blockedUntil : null;
}

export function recordFailedPinAttempt(state: PinAttemptState | null, nowMs: number): PinAttemptState {
  if (!Number.isFinite(nowMs)) {
    throw new TypeError("PIN attempt time must be finite.");
  }

  const failureCount = Math.min((state?.failureCount ?? 0) + 1, pinAttemptFailureThreshold + 32);
  const delayMs = failureCount < pinAttemptFailureThreshold
    ? 0
    : Math.min(
      pinAttemptMaxDelayMs,
      pinAttemptBaseDelayMs * (2 ** Math.min(failureCount - pinAttemptFailureThreshold, 16))
    );

  return {
    version: 1,
    failureCount,
    blockedUntil: delayMs > 0 ? new Date(nowMs + delayMs).toISOString() : null,
    updatedAt: new Date(nowMs).toISOString()
  };
}

function isValidDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function invalidPinAttemptState(): DOMException {
  return new DOMException("The stored PIN attempt state is invalid. Reset the extension before retrying.", "InvalidStateError");
}
