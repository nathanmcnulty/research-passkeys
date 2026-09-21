import assert from "node:assert/strict";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "src", "shared", "ceremony-authorization-registry.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false
});
const source = result.outputFiles[0]?.text;
assert.ok(source, "ceremony authorization registry bundle was not produced");
const { CeremonyAuthorizationRegistry } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

let nowMs = Date.parse("2026-08-12T12:00:00.000Z");
let nextTimerId = 1;
const timers = new Map();
const closedWindows = [];
const createRegistry = () => new CeremonyAuthorizationRegistry({
  now: () => nowMs,
  schedule: (callback, delayMs) => {
    const id = nextTimerId++;
    timers.set(id, { callback, at: nowMs + delayMs });
    return id;
  },
  cancelSchedule: (id) => timers.delete(id),
  closeWindow: (windowId) => closedWindows.push(windowId)
});
const view = (sessionId, overrides = {}) => ({
  sessionId,
  ceremonyId: `ceremony-${sessionId}`,
  operation: "get",
  rpId: "example.test",
  origin: "https://example.test",
  topOrigin: null,
  accountName: "Test Account",
  credentialOptions: [],
  expiresAt: new Date(nowMs + 120_000).toISOString(),
  ...overrides
});

let registry = createRegistry();
const approval = registry.begin(view("approve"));
assert.deepEqual(registry.getView("approve"), view("approve"));
assert.equal(registry.attachWindow("approve", 101), true);
registry.approve("approve");
assert.deepEqual(await approval, { approved: true, credentialId: null });
assert.deepEqual(closedWindows, [101]);
assert.throws(() => registry.approve("approve"), /expired, was cancelled, or belongs to a prior worker instance/);

registry = createRegistry();
const selectionView = view("selection", {
  accountName: null,
  credentialOptions: [
    { credentialId: "allowed-one", rpId: "example.test", userName: "one@example.test", userDisplayName: "One" },
    { credentialId: "allowed-two", rpId: "example.test", userName: "two@example.test", userDisplayName: "Two" }
  ]
});
const selection = registry.begin(selectionView);
assert.throws(() => registry.approve("selection", "attacker-choice"), /Select one of the passkeys offered/);
assert.equal(registry.getView("selection").sessionId, "selection", "invalid selection must not consume the session");
registry.approve("selection", "allowed-two");
assert.deepEqual(await selection, { approved: true, credentialId: "allowed-two" });

registry = createRegistry();
const noSelection = registry.begin(view("no-selection"));
assert.throws(() => registry.approve("no-selection", "unexpected"), /does not accept an account selection/);
assert.equal(registry.cancel("no-selection"), true);
assert.deepEqual(await noSelection, { approved: false, credentialId: null });

registry = createRegistry();
const first = registry.begin(view("first"));
assert.throws(() => registry.begin(view("second")), /Another passkey request is already awaiting approval/);
assert.equal(registry.getView("first").sessionId, "first", "concurrent rejection must preserve the first session");
registry.cancel("first");
assert.deepEqual(await first, { approved: false, credentialId: null });

registry = createRegistry();
const windowCancellation = registry.begin(view("window-cancel"));
assert.equal(registry.attachWindow("window-cancel", 202), true);
assert.equal(registry.cancelByWindowId(999), false);
assert.equal(registry.cancelByWindowId(202), true);
assert.deepEqual(await windowCancellation, { approved: false, credentialId: null });
assert.equal(closedWindows.includes(202), false, "a window-removed event must not attempt to close the same window again");

registry = createRegistry();
const relayedCancellation = registry.begin(view("relay-cancel", { ceremonyId: "page-request-id" }));
assert.equal(registry.cancelByCeremonyId("unknown-request"), false);
assert.equal(registry.cancelByCeremonyId("page-request-id"), true);
assert.deepEqual(await relayedCancellation, { approved: false, credentialId: null });

registry = createRegistry();
const expiry = registry.begin(view("expiry", { expiresAt: new Date(nowMs + 1_000).toISOString() }));
nowMs += 1_000;
for (const [id, timer] of [...timers]) {
  if (timer.at <= nowMs) {
    timers.delete(id);
    timer.callback();
  }
}
assert.deepEqual(await expiry, { approved: false, credentialId: null });
assert.throws(() => registry.getView("expiry"), /expired, was cancelled, or belongs to a prior worker instance/);

registry = createRegistry();
const failed = registry.begin(view("window-failure"));
const popupError = new Error("popup creation failed");
assert.equal(registry.fail("window-failure", popupError), true);
await assert.rejects(() => failed, /popup creation failed/);

registry = createRegistry();
const teardown = registry.begin(view("worker-teardown"));
registry.cancelAll();
assert.deepEqual(await teardown, { approved: false, credentialId: null });
const restartedRegistry = createRegistry();
assert.throws(
  () => restartedRegistry.getView("worker-teardown"),
  /expired, was cancelled, or belongs to a prior worker instance/,
  "a restarted worker must not recover or approve an old in-memory ceremony"
);

assert.throws(() => registry.begin(view("already-expired", { expiresAt: new Date(nowMs).toISOString() })), /already expired/);

console.log("Ceremony authorization lifecycle validation passed.");
