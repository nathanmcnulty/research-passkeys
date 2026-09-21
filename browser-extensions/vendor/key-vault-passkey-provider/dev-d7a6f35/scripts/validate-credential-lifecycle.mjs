import assert from "node:assert/strict";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function importBundled(relativePath) {
  const result = await build({
    entryPoints: [path.join(root, "src", "shared", relativePath)],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    write: false
  });
  const source = result.outputFiles[0]?.text;
  assert.ok(source, `${relativePath} bundle was not produced`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
}

const lifecycle = await importBundled("credential-lifecycle.ts");
const legacyRecord = {
  recordId: "record-1",
  credentialId: "credential-1",
  rpId: "example.test",
  userHandle: "user-handle",
  userName: "user@example.test",
  userDisplayName: "Example User",
  signingKeyId: "https://vault.vault.azure.net/keys/key/version",
  backendKind: "key-vault",
  createdAt: "2026-08-12T12:00:00.000Z",
  updatedAt: "2026-08-12T12:00:00.000Z",
  signCount: 0
};

const parsedLegacyRecord = lifecycle.parseStoredCredentialRecord(legacyRecord);
assert.equal(parsedLegacyRecord.state, "active", "legacy records must migrate to active in memory");
assert.equal(lifecycle.isActiveCredential(parsedLegacyRecord), true);

const deletingRecord = lifecycle.transitionCredential(parsedLegacyRecord, "deleting", "2026-08-12T12:01:00.000Z");
assert.equal(deletingRecord.state, "deleting");
assert.equal(lifecycle.isActiveCredential(deletingRecord), false);
assert.equal(parsedLegacyRecord.state, "active", "transitions must not mutate the prior record");
const disabledRecord = lifecycle.transitionCredential(parsedLegacyRecord, "disabled", "2026-08-12T12:01:00.000Z");
assert.equal(lifecycle.isActiveCredential(disabledRecord), false);
assert.equal(
  lifecycle.transitionCredential(disabledRecord, "active", "2026-08-12T12:02:00.000Z").state,
  "active"
);
assert.throws(() => lifecycle.transitionCredential(deletingRecord, "active"), /not allowed/);
assert.throws(
  () => lifecycle.transitionCredential(parsedLegacyRecord, "deleting", "2026-08-12T11:59:00.000Z"),
  /timestamp is invalid/
);

for (const invalidRecord of [
  { ...legacyRecord, state: "unknown" },
  { ...legacyRecord, signCount: -1 },
  { ...legacyRecord, signCount: 0x1_0000_0000 },
  { ...legacyRecord, updatedAt: "not-a-date" },
  { ...legacyRecord, createdAt: "2026-08-12T12:02:00.000Z", updatedAt: "2026-08-12T12:01:00.000Z" }
]) {
  assert.throws(() => lifecycle.parseStoredCredentialRecord(invalidRecord));
}

globalThis.chrome = {
  runtime: { lastError: null },
  storage: {
    local: {
      set(_items, callback) {
        callback();
      }
    }
  }
};
Object.defineProperty(globalThis, "indexedDB", {
  configurable: true,
  get() {
    throw new Error("local cache unavailable");
  }
});

const metadata = await importBundled("metadata-store.ts");
let capturedEnvelope = null;
let protectedKey = null;
const environment = {
  keyProtector: {
    async protectContentKey(contentKey) {
      protectedKey = contentKey;
      return { protectionMode: "test", keyId: "test-key", value: "protected" };
    },
    async unprotectContentKey() {
      assert.ok(protectedKey);
      return protectedKey;
    }
  },
  transport: {
    async saveEnvelope(envelope) {
      capturedEnvelope = structuredClone(envelope);
    },
    async loadAllEnvelopes() {
      return capturedEnvelope ? [structuredClone(capturedEnvelope)] : [];
    }
  },
  keyVaultClient: null
};
const activeRecord = { ...legacyRecord, state: "active" };
await metadata.saveCredentialRecord(activeRecord, environment);
assert.equal(capturedEnvelope.version, "2");
assert.equal(capturedEnvelope.lifecycleState, "active");
assert.deepEqual(
  await metadata.loadCredentialRecords(environment),
  [activeRecord],
  "remote metadata must remain usable when its disposable local cache is unavailable"
);

const originalEnvelope = capturedEnvelope;
capturedEnvelope = { ...capturedEnvelope, lifecycleState: "deleted" };
await assert.rejects(
  () => metadata.loadCredentialRecords(environment),
  /operation|decrypt|lifecycle/i,
  "lifecycle state must be authenticated with the encrypted payload"
);
capturedEnvelope = originalEnvelope;
delete globalThis.indexedDB;
delete globalThis.chrome;

const queue = await importBundled("serialized-operation-queue.ts");
const events = [];
let releaseFirst;
const firstGate = new Promise((resolve) => {
  releaseFirst = resolve;
});
const first = queue.runSerializedCredentialMutation(async () => {
  events.push("first:start");
  await firstGate;
  events.push("first:end");
});
const second = queue.runSerializedCredentialMutation(async () => {
  events.push("second:start");
  events.push("second:end");
});

await Promise.resolve();
assert.deepEqual(events, ["first:start"], "a second mutation must wait for the first");
releaseFirst();
await Promise.all([first, second]);
assert.deepEqual(events, ["first:start", "first:end", "second:start", "second:end"]);

await assert.rejects(() => queue.runSerializedCredentialMutation(async () => {
  throw new Error("expected failure");
}), /expected failure/);
assert.equal(
  await queue.runSerializedCredentialMutation(async () => "recovered"),
  "recovered",
  "a failed operation must not poison the queue"
);

console.log("Credential lifecycle validation passed.");
