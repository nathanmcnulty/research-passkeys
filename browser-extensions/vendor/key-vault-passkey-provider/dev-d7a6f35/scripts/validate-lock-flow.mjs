import { chromium } from "playwright-core";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { stageTargetScopedExtension } from "./target-scoped-extension.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const distDir = path.join(root, "dist");
const profileRoot = path.join(root, ".edge-profile");
const artifactsPath = path.resolve(root, "..", "..", "artifacts", "browser-extension-dev-environment.json");
const targetUrl = process.env.KVPP_LOCK_TARGET_URL ?? "https://ctap.dev";
const pin = process.env.KVPP_LOCK_TEST_PIN ?? "lock-test-pin-123";
const installedProfile = process.env.KVPP_LOCK_INSTALLED_PROFILE?.trim() ?? "";
const dryRun = process.argv.includes("--dry-run");
const wallClockIdle = process.argv.includes("--wall-clock-idle");
const liveSso = process.argv.includes("--live-sso");

function redactedState(state) {
  return {
    enabled: Boolean(state?.enabled),
    lockTimeoutMinutes: state?.lockTimeoutMinutes ?? null,
    locked: Boolean(state?.lockedAt),
    lockReason: state?.lockReason ?? null,
    hasLastActivityAt: Boolean(state?.lastActivityAt),
    hasLastUnlockedAt: Boolean(state?.lastUnlockedAt),
    interactiveUnlockAllowed: Boolean(state?.interactiveUnlockExpiresAt && Date.parse(state.interactiveUnlockExpiresAt) > Date.now()),
    configReady: isConfigReady(state),
    metadataTransportMode: state?.config?.metadataTransportMode ?? null
  };
}

function report(results) {
  console.log(JSON.stringify({ validator: "browser-lock", results }, null, 2));
}

async function main() {
  if (dryRun) {
    report({ dryRun: true, cases: ["setup-default-and-clamp", "browser-restart", "idle-expiry", "service-worker-reload", "silent-sso"] });
    return;
  }

  await ensureBuild();
  const edgePath = await resolveEdgePath();
  await fs.mkdir(profileRoot, { recursive: true });
  const userDataDir = installedProfile
    ? path.resolve(installedProfile)
    : await fs.mkdtemp(path.join(profileRoot, "lock-validation-"));
  const stagingRoot = installedProfile
    ? null
    : await fs.mkdtemp(path.join(os.tmpdir(), "kvpp-lock-extension-"));
  const staged = stagingRoot
    ? await stageTargetScopedExtension(distDir, targetUrl, stagingRoot)
    : null;
  const results = {};
  let context;

  try {
    context = await launch(edgePath, userDataDir, staged?.extensionDir ?? null);
    let popup = await openPopup(context);
    await delay(1500);
    await hydrateLocalTestState(popup);

    results.setup = await setupAndClamp(popup);
    results.idle = await idleExpiry(popup, wallClockIdle);
    results.workerReload = await workerReloadPersistence(context, popup);
    results.restart = await restartLock(edgePath, userDataDir, staged?.extensionDir ?? null, context);
    context = results.restart.context;
    delete results.restart.context;
    results.silentSso = liveSso
      ? await runLiveSso(context)
      : { status: "blocked", reason: "Run with --live-sso against a once-installed disposable profile to exercise normal browser authentication." };
    report(results);

    for (const [name, result] of Object.entries(results)) {
      if (result?.passed === false) {
        throw new Error(`Browser lock validation failed: ${name}.`);
      }
    }
  } finally {
    await context?.close().catch(() => {});
    if (stagingRoot) {
      await fs.rm(stagingRoot, { recursive: true, force: true }).catch(() => {});
    }
    if (!installedProfile) {
      await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

async function setupAndClamp(popup) {
  const initial = await getState(popup);
  const defaultPass = initial.lockTimeoutMinutes === 15;
  await setLocalState(popup, { lockTimeoutMinutes: 4 });
  const lower = await getState(popup);
  await setLocalState(popup, { lockTimeoutMinutes: 61 });
  const upper = await getState(popup);
  return { passed: defaultPass && lower.lockTimeoutMinutes === 5 && upper.lockTimeoutMinutes === 60, default: initial.lockTimeoutMinutes, lower: lower.lockTimeoutMinutes, upper: upper.lockTimeoutMinutes };
}

async function restartLock(edgePath, userDataDir, extensionDir, context) {
  await context.close();
  const restarted = await launch(edgePath, userDataDir, extensionDir);
  const popup = await openPopup(restarted);
  const state = await getState(popup);
  const token = await sessionKeyPresence(popup);
  const pinStatus = await send(popup, { kind: "get-pin-uv-status" });
  const stateProjection = redactedState(state);
  if (!stateProjection.configReady || !pinStatus.ok || !pinStatus.pinUvStatus?.isConfigured) {
    return {
      context: restarted,
      status: "blocked",
      reason: "The command-line unpacked extension was installed again on process launch, so its install handler reset the disposable setup before browser-start state could be observed.",
      state: stateProjection,
      cachedTokenKeyPresent: token
    };
  }

  return {
    context: restarted,
    passed: Boolean(state.lockedAt) && state.lockReason === "browser-start" && !token,
    state: stateProjection,
    cachedTokenKeyPresent: token
  };
}

async function idleExpiry(popup, useWallClock) {
  const before = await getState(popup);
  await setLocalState(popup, { lastActivityAt: new Date(useWallClock ? Date.now() : Date.now() - 6 * 60 * 1000).toISOString(), lockTimeoutMinutes: 5, lockedAt: null, lockReason: null });
  if (useWallClock) {
    await delay(5 * 60 * 1000 + 1_000);
  }
  const response = await send(popup, { kind: "get-stored-credentials" });
  const state = await getState(popup);
  const token = await sessionKeyPresence(popup);
  const rejected = !response.ok && /unlock the extension/i.test(response.error?.message ?? "");
  return { passed: rejected && state.lockReason === "idle" && !token, simulatedElapsed: !useWallClock, before: redactedState(before), after: redactedState(state), protectedActionRejected: rejected, cachedTokenKeyPresent: token };
}

async function workerReloadPersistence(context, popup) {
  const before = await getState(popup);
  const worker = context.serviceWorkers()[0];
  if (!worker) throw new Error("Extension service worker did not start.");
  await worker.evaluate(() => chrome.runtime.reload()).catch(() => {});
  await waitForNewWorker(context, worker);
  const nextPopup = await openPopup(context);
  const after = await getState(nextPopup);
  return { passed: after.locked === before.locked && after.lockReason === before.lockReason, before: redactedState(before), after: redactedState(after) };
}

async function runLiveSso(context) {
  if (!installedProfile) {
    throw new Error("--live-sso requires KVPP_LOCK_INSTALLED_PROFILE so browser identity state remains inside a disposable profile.");
  }

  const environment = await loadDevEnvironment();
  const popup = await openPopup(context);
  const saved = await send(popup, { kind: "save-config", config: environment.config, lockTimeoutMinutes: 15 });
  if (!saved.ok) throw new Error(`Unable to save live SSO configuration: ${saved.error?.message ?? "unknown error"}`);
  await setLocalState(popup, { lockedAt: null, lockReason: null, enabled: true });

  console.log("LIVE_SSO_USER_ACTION=Complete the normal Entra sign-in in the disposable Edge profile.");
  const initialSignIn = await withTimeout(send(popup, { kind: "begin-sign-in" }), 5 * 60 * 1000, "Initial interactive sign-in timed out.");
  if (!initialSignIn.ok || initialSignIn.authStatus?.mode !== "signed-in") {
    throw new Error(initialSignIn.error?.message ?? "Initial interactive sign-in did not produce a signed-in session.");
  }

  const pinResponse = await send(popup, { kind: "set-pin-uv", currentPin: pin, newPin: environment.pin });
  if (!pinResponse.ok || !pinResponse.pinUvStatus?.isConfigured) {
    throw new Error(pinResponse.error?.message ?? "Unable to configure the live SSO test PIN.");
  }

  const locked = await send(popup, { kind: "lock-extension" });
  if (!locked.ok || !locked.locked) throw new Error(locked.error?.message ?? "Unable to lock before silent SSO validation.");
  const worker = context.serviceWorkers()[0];
  if (!worker) throw new Error("Extension service worker did not start.");
  await worker.evaluate(() => chrome.runtime.reload()).catch(() => {});
  await waitForNewWorker(context, worker);
  const restartedPopup = await openPopup(context);
  const beforeSilent = await getState(restartedPopup);
  const silentUnlock = await withTimeout(send(restartedPopup, { kind: "unlock-extension", pin: environment.pin }), 90_000, "Silent SSO unlock timed out.");
  const afterSilent = await getState(restartedPopup);
  const silentPassed = silentUnlock.ok
    && silentUnlock.unlockOutcome === "unlocked"
    && silentUnlock.authStatus?.mode === "signed-in"
    && !afterSilent.lockedAt;

  await context.clearCookies();
  const relocked = await send(restartedPopup, { kind: "lock-extension" });
  if (!relocked.ok || !relocked.locked) throw new Error(relocked.error?.message ?? "Unable to lock before interactive recovery validation.");
  const recoveryUnlock = await withTimeout(send(restartedPopup, { kind: "unlock-extension", pin: environment.pin }), 90_000, "Silent-failure probe timed out.");
  const recoveryState = await getState(restartedPopup);
  const interactionRequired = recoveryUnlock.ok
    && recoveryUnlock.unlockOutcome === "interactive-sign-in-required"
    && recoveryState.lockReason === "token-expired";

  if (!interactionRequired) {
    return {
      passed: false,
      silentSsoPassed: silentPassed,
      workerRestartLockedStatePreserved: Boolean(beforeSilent.lockedAt),
      interactiveRecovery: "blocked-browser-sso-remained-active"
    };
  }

  console.log("LIVE_SSO_USER_ACTION=Complete the explicit Entra recovery sign-in in the disposable Edge profile.");
  const recovered = await withTimeout(send(restartedPopup, { kind: "begin-sign-in" }), 5 * 60 * 1000, "Interactive recovery sign-in timed out.");
  const finalState = await getState(restartedPopup);
  const recoveryPassed = recovered.ok
    && recovered.authStatus?.mode === "signed-in"
    && !finalState.lockedAt
    && !finalState.interactiveUnlockExpiresAt;

  return {
    passed: silentPassed && recoveryPassed,
    silentSsoPassed: silentPassed,
    workerRestartLockedStatePreserved: Boolean(beforeSilent.lockedAt),
    interactionRequiredObserved: interactionRequired,
    interactiveRecoveryPassed: recoveryPassed
  };
}

async function hydrateLocalTestState(popup) {
  const config = { metadataTransportMode: "LocalCacheOnly", tenantId: "00000000-0000-0000-0000-000000000001", clientId: "00000000-0000-0000-0000-000000000002", authorityHost: "https://login.microsoftonline.com", keyVaultBaseUrl: "", signingKeyName: "passkey-signing-key", signingKeyType: "EC", metadataWrappingKeyName: "passkey-metadata-wrap-key", metadataSecretPrefix: "kvpp-md" };
  await popup.evaluate(() => new Promise((resolve, reject) => chrome.storage.local.remove(["kvpp.pinUvState", "kvpp.pinAttemptState"], () => { const error = chrome.runtime.lastError; if (error) reject(new Error(error.message)); else resolve(); })));
  const saved = await send(popup, { kind: "save-config", config, lockTimeoutMinutes: 15 });
  if (!saved.ok) throw new Error(`Unable to save disposable config: ${saved.error?.message ?? "unknown error"}`);
  await setLocalState(popup, { lockedAt: null, lockReason: null, lastActivityAt: null, lastUnlockedAt: null, enabled: false });
  const response = await send(popup, { kind: "set-pin-uv", newPin: pin });
  if (!response.ok) throw new Error(`Unable to configure disposable PIN: ${response.error?.message ?? "unknown error"}`);
  const pinStatus = await send(popup, { kind: "get-pin-uv-status" });
  if (!pinStatus.ok || !pinStatus.pinUvStatus?.isConfigured) throw new Error("Disposable PIN did not become configured.");
}

async function launch(edgePath, userDataDir, extensionDir) {
  const args = extensionDir
    ? [`--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`]
    : [];
  const context = await chromium.launchPersistentContext(userDataDir, { executablePath: edgePath, headless: false, ignoreDefaultArgs: ["--disable-extensions"], args });
  await waitForExtensionId(context);
  return context;
}

async function openPopup(context) {
  const id = await waitForExtensionId(context);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`, { waitUntil: "domcontentloaded" });
  await popup.waitForFunction(() => document.body.dataset.popupReady === "true" || document.body.dataset.popupReady === "error", undefined, { timeout: 30000 });
  return popup;
}

async function getState(popup) { const response = await send(popup, { kind: "get-state" }); if (!response.ok) throw new Error(response.error?.message ?? "get-state failed"); return response.state; }
async function send(popup, message) { return popup.evaluate((value) => new Promise((resolve, reject) => chrome.runtime.sendMessage(value, (response) => { const error = chrome.runtime.lastError; if (error) reject(new Error(error.message)); else resolve(response); })), message); }
async function setLocalState(popup, patch) { await popup.evaluate((value) => new Promise((resolve, reject) => chrome.storage.local.get(["kvpp.extension.state"], (items) => { const state = { ...(items["kvpp.extension.state"] ?? {}), ...value }; chrome.storage.local.set({ "kvpp.extension.state": state }, () => { const error = chrome.runtime.lastError; if (error) reject(new Error(error.message)); else resolve(); }); })), patch); }
async function sessionKeyPresence(popup) { return popup.evaluate(() => new Promise((resolve, reject) => chrome.storage.session.get(["kvpp.auth.cachedToken"], (items) => { const error = chrome.runtime.lastError; if (error) reject(new Error(error.message)); else resolve(Object.prototype.hasOwnProperty.call(items, "kvpp.auth.cachedToken")); }))); }
async function waitForNewWorker(context, previous) { for (let i = 0; i < 80; i++) { const worker = context.serviceWorkers()[0]; if (worker && worker !== previous) return worker; await delay(250); } throw new Error("Service worker did not restart."); }
async function waitForExtensionId(context) { for (let i = 0; i < 80; i++) { const worker = context.serviceWorkers()[0]; const match = worker && /^chrome-extension:\/\/([a-z]{32})\//.exec(worker.url()); if (match) return match[1]; await delay(250); } throw new Error("Extension service worker did not start."); }
function delay(timeoutMs) { return new Promise((resolve) => setTimeout(resolve, timeoutMs)); }
async function ensureBuild() { try { await fs.access(path.join(distDir, "manifest.json")); } catch { throw new Error("Extension build output missing; run npm run build first."); } }
async function resolveEdgePath() { for (const candidate of ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"]) { try { await fs.access(candidate); return candidate; } catch {} } throw new Error("Unable to locate msedge.exe."); }
function isConfigReady(state) { return Boolean(state?.config?.tenantId?.trim() && state?.config?.clientId?.trim() && state?.config?.authorityHost?.trim() && (state?.config?.metadataTransportMode === "LocalCacheOnly" || (state?.config?.keyVaultBaseUrl?.trim() && state?.config?.metadataWrappingKeyName?.trim()))); }
function withTimeout(promise, timeoutMs, message) { return Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(message)), timeoutMs))]); }
async function loadDevEnvironment() {
  const raw = JSON.parse(await fs.readFile(artifactsPath, "utf8"));
  const testPin = typeof raw.devPinUvPin === "string" && raw.devPinUvPin.length >= 6 ? raw.devPinUvPin : pin;
  return {
    pin: testPin,
    config: {
      tenantId: raw.tenantId ?? "",
      clientId: raw.clientId ?? "",
      authorityHost: raw.authorityHost ?? "https://login.microsoftonline.com",
      keyVaultBaseUrl: raw.keyVaultBaseUrl ?? "",
      signingKeyName: raw.signingKeyName ?? "passkey-signing-key",
      signingKeyType: raw.signingKeyType === "EC-HSM" ? "EC-HSM" : "EC",
      metadataWrappingKeyName: raw.metadataWrappingKeyName ?? "passkey-metadata-wrap-key",
      metadataTransportMode: raw.metadataTransportMode === "LocalCacheOnly" ? "LocalCacheOnly" : "KeyVaultSecrets",
      metadataSecretPrefix: raw.metadataSecretPrefix ?? "kvpp-md"
    }
  };
}

main().catch((error) => { console.error(error instanceof Error ? error.stack ?? error.message : String(error)); process.exitCode = 1; });
