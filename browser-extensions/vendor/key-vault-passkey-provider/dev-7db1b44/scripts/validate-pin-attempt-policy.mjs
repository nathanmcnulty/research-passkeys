import assert from "node:assert/strict";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "src", "shared", "pin-attempt-policy.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false
});
const source = result.outputFiles[0]?.text;
assert.ok(source, "PIN attempt policy bundle was not produced");
const policy = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

const startedAt = Date.parse("2026-08-12T12:00:00.000Z");
let state = null;
for (let failure = 1; failure < policy.pinAttemptFailureThreshold; failure += 1) {
  state = policy.recordFailedPinAttempt(state, startedAt + failure);
  assert.equal(state.failureCount, failure);
  assert.equal(state.blockedUntil, null);
}

state = policy.recordFailedPinAttempt(state, startedAt + policy.pinAttemptFailureThreshold);
assert.equal(state.failureCount, policy.pinAttemptFailureThreshold);
assert.equal(
  Date.parse(state.blockedUntil) - (startedAt + policy.pinAttemptFailureThreshold),
  policy.pinAttemptBaseDelayMs
);
assert.equal(policy.getPinBlockExpiry(state, startedAt + 1_000), state.blockedUntil);
assert.equal(policy.getPinBlockExpiry(state, Date.parse(state.blockedUntil)), null);

const secondBlockStart = Date.parse(state.blockedUntil);
state = policy.recordFailedPinAttempt(state, secondBlockStart);
assert.equal(Date.parse(state.blockedUntil) - secondBlockStart, policy.pinAttemptBaseDelayMs * 2);

for (let failure = 0; failure < 20; failure += 1) {
  const nextAttemptAt = state.blockedUntil ? Date.parse(state.blockedUntil) : startedAt;
  state = policy.recordFailedPinAttempt(state, nextAttemptAt);
}
assert.equal(Date.parse(state.blockedUntil) - Date.parse(state.updatedAt), policy.pinAttemptMaxDelayMs);

assert.equal(policy.parsePinAttemptState(undefined), null);
assert.deepEqual(policy.parsePinAttemptState(state), state);
assert.throws(() => policy.parsePinAttemptState({ version: 1, failureCount: -1, blockedUntil: null, updatedAt: "invalid" }));
assert.throws(() => policy.recordFailedPinAttempt(null, Number.NaN));

const limiterResult = await build({
  entryPoints: [path.join(root, "src", "shared", "pin-attempt-limiter.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false
});
const limiterSource = limiterResult.outputFiles[0]?.text;
assert.ok(limiterSource, "PIN attempt limiter bundle was not produced");

const storage = Object.create(null);
globalThis.chrome = {
  runtime: {
    lastError: null
  },
  storage: {
    local: {
      get(keys, callback) {
        callback(Object.fromEntries(keys.filter((key) => key in storage).map((key) => [key, storage[key]])));
      },
      set(items, callback) {
        Object.assign(storage, items);
        callback();
      },
      remove(key, callback) {
        delete storage[key];
        callback();
      }
    }
  }
};

const limiter = await import(`data:text/javascript;base64,${Buffer.from(limiterSource).toString("base64")}`);
let verificationCalls = 0;
const failedAttempts = Array.from({ length: policy.pinAttemptFailureThreshold }, () =>
  limiter.verifyPinWithAttemptLimit(async () => {
    verificationCalls += 1;
    await Promise.resolve();
    return false;
  }));
assert.deepEqual(await Promise.all(failedAttempts), Array(policy.pinAttemptFailureThreshold).fill(false));
assert.equal(verificationCalls, policy.pinAttemptFailureThreshold);
assert.equal(storage["kvpp.pinAttemptState"].failureCount, policy.pinAttemptFailureThreshold);

await assert.rejects(
  () => limiter.verifyPinWithAttemptLimit(async () => {
    verificationCalls += 1;
    return true;
  }),
  /Too many incorrect PIN attempts/
);
assert.equal(verificationCalls, policy.pinAttemptFailureThreshold, "blocked attempts must not invoke PIN verification");

storage["kvpp.pinAttemptState"] = {
  ...storage["kvpp.pinAttemptState"],
  blockedUntil: new Date(Date.now() - 1_000).toISOString()
};
assert.equal(await limiter.verifyPinWithAttemptLimit(async () => true), true);
assert.equal(storage["kvpp.pinAttemptState"], undefined, "successful verification must reset attempt state");

storage["kvpp.pinAttemptState"] = { version: 1, failureCount: -1 };
await assert.rejects(() => limiter.verifyPinWithAttemptLimit(async () => true), /stored PIN attempt state is invalid/);
delete globalThis.chrome;

console.log("PIN attempt policy validation passed.");
