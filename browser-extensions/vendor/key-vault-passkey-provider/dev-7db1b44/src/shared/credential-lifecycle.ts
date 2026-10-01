import type { BrowserCredentialLifecycleState, BrowserStoredCredentialRecord } from "./models";

const lifecycleStates = new Set<BrowserCredentialLifecycleState>([
  "pending",
  "active",
  "disabled",
  "deleting",
  "deleted"
]);
const allowedTransitions: Record<BrowserCredentialLifecycleState, ReadonlySet<BrowserCredentialLifecycleState>> = {
  pending: new Set(["active", "deleting"]),
  active: new Set(["disabled", "deleting"]),
  disabled: new Set(["active", "deleting"]),
  deleting: new Set(["deleted"]),
  deleted: new Set()
};

export function parseStoredCredentialRecord(value: unknown): BrowserStoredCredentialRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Stored credential metadata must be an object.");
  }

  const candidate = value as Record<string, unknown>;
  const state = candidate.state === undefined ? "active" : candidate.state;
  if (typeof state !== "string" || !lifecycleStates.has(state as BrowserCredentialLifecycleState)) {
    throw new Error("Stored credential metadata has an invalid lifecycle state.");
  }

  const signCount = candidate.signCount;
  if (!Number.isSafeInteger(signCount) || (signCount as number) < 0 || (signCount as number) > 0xffff_ffff) {
    throw new Error("Stored credential metadata has an invalid sign count.");
  }

  const createdAt = requireIsoTimestamp(candidate.createdAt, "createdAt");
  const updatedAt = requireIsoTimestamp(candidate.updatedAt, "updatedAt");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new Error("Stored credential metadata was updated before it was created.");
  }

  return {
    recordId: requireString(candidate.recordId, "recordId"),
    credentialId: requireString(candidate.credentialId, "credentialId"),
    rpId: requireString(candidate.rpId, "rpId"),
    userHandle: requireString(candidate.userHandle, "userHandle"),
    userName: requireString(candidate.userName, "userName"),
    userDisplayName: requireString(candidate.userDisplayName, "userDisplayName"),
    signingKeyId: requireString(candidate.signingKeyId, "signingKeyId"),
    backendKind: requireString(candidate.backendKind, "backendKind"),
    createdAt,
    updatedAt,
    signCount: signCount as number,
    state: state as BrowserCredentialLifecycleState
  };
}

export function isActiveCredential(record: BrowserStoredCredentialRecord): boolean {
  return record.state === "active";
}

export function transitionCredential(
  record: BrowserStoredCredentialRecord,
  state: BrowserCredentialLifecycleState,
  updatedAt = new Date().toISOString()
): BrowserStoredCredentialRecord {
  if (!allowedTransitions[record.state].has(state)) {
    throw new Error(`Credential lifecycle transition ${record.state} -> ${state} is not allowed.`);
  }
  if (!Number.isFinite(Date.parse(updatedAt)) || Date.parse(updatedAt) < Date.parse(record.updatedAt)) {
    throw new Error("Credential lifecycle transition timestamp is invalid.");
  }

  return {
    ...record,
    state,
    updatedAt
  };
}

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Stored credential metadata has an invalid ${fieldName}.`);
  }

  return value;
}

function requireIsoTimestamp(value: unknown, fieldName: string): string {
  const timestamp = requireString(value, fieldName);
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new Error(`Stored credential metadata has an invalid ${fieldName}.`);
  }

  return timestamp;
}
