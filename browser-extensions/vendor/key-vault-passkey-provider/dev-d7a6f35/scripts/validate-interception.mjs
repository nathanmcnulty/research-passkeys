import assert from "node:assert/strict";
import { chromium } from "playwright-core";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { stageTargetScopedExtension } from "./target-scoped-extension.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(root, "dist");
const targetUrl = process.argv[2] ?? "https://ctap.dev/login";
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "kvpp-interception-"));
let context;

try {
  await fs.access(path.join(distDir, "manifest.json"));
  const { extensionDir, permission } = await stageTargetScopedExtension(distDir, targetUrl, temporaryRoot);
  const edgePath = await resolveEdgePath();
  context = await chromium.launchPersistentContext(path.join(temporaryRoot, "profile"), {
    executablePath: edgePath,
    headless: false,
    ignoreDefaultArgs: ["--disable-extensions"],
    args: [
      "--no-first-run",
      "--window-position=-32000,-32000",
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`
    ]
  });

  const worker = await waitForExtensionWorker(context);
  const extensionId = /^chrome-extension:\/\/([a-z]{32})\//.exec(worker.url())?.[1];
  assert.ok(extensionId, "extension service worker URL did not contain an extension ID");

  const registration = await waitForContentScriptRegistration(worker);
  assert.ok(registration, "dynamic WebAuthn content script was not registered");
  assert.ok(registration.matches.includes(permission), `content script did not include ${permission}`);
  assert.equal(registration.allFrames, true, "dynamic WebAuthn interception was not enabled for granted child frames");

  const page = context.pages()[0] ?? await context.newPage();
  let shimActive = false;
  for (let attempt = 0; attempt < 3 && !shimActive; attempt += 1) {
    await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
    try {
      await page.waitForFunction(() => document.documentElement.hasAttribute("data-kvpp-content-script"), undefined, { timeout: 10000 });
      const shimSource = await page.evaluate(() => navigator.credentials.create.toString());
      shimActive = !shimSource.includes("[native code]");
    } catch {
      // A fresh navigation retries document-start injection before failing the proof.
    }
  }
  if (!shimActive) {
    const diagnostics = await worker.evaluate(async () => ({
      permissions: await chrome.permissions.getAll(),
      registrations: await chrome.scripting.getRegisteredContentScripts()
    }));
    throw new Error(`WebAuthn shim remained native at ${page.url()}: ${JSON.stringify(diagnostics)}`);
  }

  const panelBehavior = await worker.evaluate(async () => chrome.sidePanel.getPanelBehavior());
  assert.equal(panelBehavior.openPanelOnActionClick, true, "extension action was not configured to open the side panel");

  const panel = await context.newPage();
  await panel.setViewportSize({ width: 420, height: 800 });
  await panel.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: "domcontentloaded" });
  await page.bringToFront();
  await panel.reload({ waitUntil: "domcontentloaded" });
  await panel.waitForFunction(() => document.body.dataset.popupReady === "true", undefined, { timeout: 15000 });
  await panel.waitForFunction((origin) => document.querySelector("#currentSiteOrigin")?.textContent?.trim() === origin, new URL(targetUrl).origin, { timeout: 15000 });
  const panelState = await panel.evaluate(() => ({
    origin: document.querySelector("#currentSiteOrigin")?.textContent?.trim() ?? "",
    access: document.querySelector("#currentSiteAccess")?.textContent?.trim() ?? "",
    allowHidden: document.querySelector("#allowCurrentSite")?.hasAttribute("hidden") ?? false,
    removeHidden: document.querySelector("#removeCurrentSite")?.hasAttribute("hidden") ?? true,
    documentWidth: document.documentElement.scrollWidth
  }));
  assert.match(panelState.access, /Host access is granted/);
  assert.equal(panelState.allowHidden, true, "side panel offered to grant access that was already present");
  assert.equal(panelState.removeHidden, false, "side panel did not offer to remove current-site access");
  assert.ok(panelState.documentWidth <= 420, `side panel overflowed its narrow viewport (${panelState.documentWidth}px)`);

  const pinThrottle = await panel.evaluate(async () => {
    const send = (message) => new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }
        resolve(response);
      });
    });
    const readAttemptState = () => new Promise((resolve, reject) => {
      chrome.storage.local.get(["kvpp.pinAttemptState"], (items) => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }
        resolve(items["kvpp.pinAttemptState"] ?? null);
      });
    });
    const writeAttemptState = (state) => new Promise((resolve, reject) => {
      chrome.storage.local.set({ "kvpp.pinAttemptState": state }, () => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }
        resolve();
      });
    });

    const configResponse = await send({
      kind: "save-config",
      config: {
        tenantId: "11111111-1111-4111-8111-111111111111",
        clientId: "22222222-2222-4222-8222-222222222222",
        authorityHost: "https://login.microsoftonline.com",
        keyVaultBaseUrl: "",
        signingKeyName: "passkey-signing-key",
        signingKeyType: "EC",
        metadataWrappingKeyName: "passkey-metadata-wrap-key",
        metadataTransportMode: "LocalCacheOnly",
        metadataSecretPrefix: "kvpp-md"
      }
    });
    const setPinResponse = await send({ kind: "set-pin-uv", newPin: "correct-horse" });
    const lockResponse = await send({ kind: "lock-extension" });
    const failures = [];
    for (let attempt = 0; attempt < 5; attempt += 1) {
      failures.push(await send({ kind: "unlock-extension", pin: "wrong-guess" }));
    }
    const blockedResponse = await send({ kind: "unlock-extension", pin: "correct-horse" });
    const blockedState = await readAttemptState();
    await writeAttemptState({ ...blockedState, blockedUntil: new Date(Date.now() - 1_000).toISOString() });
    const recoveryResponse = await send({ kind: "unlock-extension", pin: "correct-horse" });
    const recoveredState = await readAttemptState();

    return {
      configOk: configResponse?.ok === true,
      setPinOk: setPinResponse?.ok === true,
      locked: lockResponse?.ok === true && lockResponse?.locked === true,
      failureMessages: failures.map((response) => response?.ok === false ? response.error?.message ?? "" : "unexpected success"),
      blockedMessage: blockedResponse?.ok === false ? blockedResponse.error?.message ?? "" : "unexpected success",
      blockedFailureCount: blockedState?.failureCount ?? null,
      recovered: recoveryResponse?.ok === true && recoveryResponse?.unlockOutcome === "unlocked",
      recoveredState
    };
  });
  assert.equal(pinThrottle.configOk, true, "local-only PIN throttle test config failed");
  assert.equal(pinThrottle.setPinOk, true, "local-only PIN setup failed");
  assert.equal(pinThrottle.locked, true, "extension did not enter the locked state for PIN throttle validation");
  assert.equal(pinThrottle.failureMessages.length, 5);
  for (const message of pinThrottle.failureMessages) {
    assert.match(message, /PIN is incorrect/);
  }
  assert.match(pinThrottle.blockedMessage, /Too many incorrect PIN attempts/);
  assert.equal(pinThrottle.blockedFailureCount, 5);
  assert.equal(pinThrottle.recovered, true, "correct PIN did not unlock after the simulated backoff expired");
  assert.equal(pinThrottle.recoveredState, null, "successful PIN verification did not clear attempt state");

  const cancellationResultPromise = page.evaluate(async () => {
    const controller = new AbortController();
    globalThis.__kvppCancellationController = controller;
    try {
      await navigator.credentials.create({
        signal: controller.signal,
        publicKey: {
          rp: { id: "ctap.dev", name: "KVPP cancellation validation" },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: "cancel@example.test",
            displayName: "Cancellation Test"
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 30_000
        }
      });
      return { name: "UnexpectedSuccess", message: "create() unexpectedly completed" };
    } catch (error) {
      return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
    } finally {
      delete globalThis.__kvppCancellationController;
    }
  });
  const cancellationDialog = await waitForAuthorizationDialogOrResult(context, cancellationResultPromise, "cancellation");
  await page.evaluate(() => globalThis.__kvppCancellationController.abort());
  const cancellationResult = await cancellationResultPromise;
  assert.equal(cancellationResult.name, "AbortError", `aborted page request returned ${JSON.stringify(cancellationResult)}`);
  await waitForPageClosed(cancellationDialog, "aborted authorization dialog");

  const firstConcurrentPromise = page.evaluate(async () => {
    const controller = new AbortController();
    globalThis.__kvppConcurrentController = controller;
    try {
      await navigator.credentials.create({
        signal: controller.signal,
        publicKey: {
          rp: { id: "ctap.dev", name: "KVPP concurrency validation" },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: "first@example.test",
            displayName: "First Request"
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 30_000
        }
      });
      return { name: "UnexpectedSuccess", message: "first create() unexpectedly completed" };
    } catch (error) {
      return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
    } finally {
      delete globalThis.__kvppConcurrentController;
    }
  });
  const concurrentDialog = await waitForAuthorizationDialogOrResult(context, firstConcurrentPromise, "first concurrent");
  const secondConcurrentResult = await page.evaluate(async () => {
    try {
      await navigator.credentials.create({
        publicKey: {
          rp: { id: "ctap.dev", name: "KVPP concurrency validation" },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: "second@example.test",
            displayName: "Second Request"
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 30_000
        }
      });
      return { name: "UnexpectedSuccess", message: "second create() unexpectedly completed" };
    } catch (error) {
      return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
    }
  });
  assert.equal(secondConcurrentResult.name, "NotAllowedError");
  assert.match(secondConcurrentResult.message, /already awaiting approval/);
  await page.evaluate(() => globalThis.__kvppConcurrentController.abort());
  assert.equal((await firstConcurrentPromise).name, "AbortError");
  await waitForPageClosed(concurrentDialog, "concurrent authorization dialog");

  const timeoutResultPromise = page.evaluate(async () => {
    try {
      await navigator.credentials.create({
        publicKey: {
          rp: { id: "ctap.dev", name: "KVPP timeout validation" },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: "timeout@example.test",
            displayName: "Timeout Test"
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 3_000
        }
      });
      return { name: "UnexpectedSuccess", message: "timed create() unexpectedly completed" };
    } catch (error) {
      return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
    }
  });
  const timeoutDialog = await waitForAuthorizationDialogOrResult(context, timeoutResultPromise, "timeout");
  const timeoutResult = await timeoutResultPromise;
  assert.ok(["TimeoutError", "NotAllowedError"].includes(timeoutResult.name), `timed request returned ${JSON.stringify(timeoutResult)}`);
  await waitForPageClosed(timeoutDialog, "expired authorization dialog");

  const negativeResults = await page.evaluate(async () => {
    const attempt = async (operation, publicKey) => {
      try {
        await navigator.credentials[operation]({ publicKey });
        return { name: "UnexpectedSuccess", message: `${operation} unexpectedly completed` };
      } catch (error) {
        return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
      }
    };
    const createBase = () => ({
      rp: { id: "ctap.dev", name: "KVPP negative validation" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "negative@example.test",
        displayName: "Negative Test"
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 10_000
    });

    return {
      invalidRp: await attempt("create", { ...createBase(), rp: { id: "attacker.example", name: "Invalid RP" } }),
      requiredUv: await attempt("create", {
        ...createBase(),
        authenticatorSelection: { userVerification: "required" }
      }),
      unsupportedAlgorithm: await attempt("create", {
        ...createBase(),
        pubKeyCredParams: [{ type: "public-key", alg: -257 }]
      }),
      allowListMismatch: await attempt("get", {
        rpId: "ctap.dev",
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: crypto.getRandomValues(new Uint8Array(32)) }],
        userVerification: "preferred",
        timeout: 10_000
      })
    };
  });
  assert.equal(negativeResults.invalidRp.name, "SecurityError");
  assert.equal(negativeResults.requiredUv.name, "NotSupportedError");
  assert.equal(negativeResults.unsupportedAlgorithm.name, "NotSupportedError");
  assert.equal(negativeResults.allowListMismatch.name, "NotAllowedError");
  assert.equal(context.pages().some((candidate) => candidate.url().includes("/uv-dialog.html")), false, "negative requests opened an authorization dialog");

  await page.goto("https://example.com", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    const frame = document.createElement("iframe");
    frame.id = "kvpp-granted-frame";
    frame.allow = "publickey-credentials-create *; publickey-credentials-get *";
    frame.src = "https://ctap.dev/login?kvpp-frame-validation=1";
    document.body.appendChild(frame);
  });
  const grantedFrame = await waitForFrame(page, /https:\/\/ctap\.dev\/login\?kvpp-frame-validation=1/);
  await grantedFrame.waitForFunction(() => document.documentElement.hasAttribute("data-kvpp-content-script"), undefined, { timeout: 10_000 });
  const frameShimSource = await grantedFrame.evaluate(() => navigator.credentials.create.toString());
  assert.equal(frameShimSource.includes("[native code]"), false, "granted child frame retained native WebAuthn");

  const frameCancellationPromise = grantedFrame.evaluate(async () => {
    const controller = new AbortController();
    globalThis.__kvppFrameController = controller;
    try {
      await navigator.credentials.create({
        signal: controller.signal,
        publicKey: {
          rp: { id: "ctap.dev", name: "KVPP frame validation" },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: "frame@example.test",
            displayName: "Frame Test"
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          timeout: 30_000
        }
      });
      return { name: "UnexpectedSuccess", message: "frame create() unexpectedly completed" };
    } catch (error) {
      return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
    } finally {
      delete globalThis.__kvppFrameController;
    }
  });
  const frameDialog = await waitForAuthorizationDialogOrResult(context, frameCancellationPromise, "child-frame");
  await frameDialog.waitForFunction(() => document.querySelector("#uvDetails")?.textContent?.includes("Origin:"), undefined, { timeout: 10_000 });
  const frameDetails = (await frameDialog.locator("#uvDetails").textContent()) ?? "";
  assert.match(frameDetails, /Origin: https:\/\/ctap\.dev/);
  assert.match(frameDetails, /Top origin: https:\/\/example\.com/);
  await grantedFrame.evaluate(() => globalThis.__kvppFrameController.abort());
  assert.equal((await frameCancellationPromise).name, "AbortError");
  await waitForPageClosed(frameDialog, "child-frame authorization dialog");

  const manifest = JSON.parse((await fs.readFile(path.join(extensionDir, "manifest.json"), "utf8")).replace(/^\uFEFF/, ""));
  assert.deepEqual(manifest.host_permissions, [permission]);
  assert.equal(manifest.side_panel?.default_path, "popup.html");

  console.log(`Extension interception validation passed for ${new URL(targetUrl).origin}.`);
  console.log("Extension PIN throttling validation passed.");
  console.log("Extension ceremony cancellation, concurrency, and expiry validation passed.");
  console.log("Extension iframe and negative WebAuthn validation passed.");
  console.log(`Extension ID: ${extensionId}`);
  console.log(`Registered match: ${permission}`);
}
finally {
  await context?.close().catch(() => {});
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

async function waitForExtensionWorker(browserContext) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const worker = browserContext.serviceWorkers()[0];
    if (worker) {
      return worker;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Extension service worker did not start.");
}

async function waitForContentScriptRegistration(worker) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const registrations = await worker.evaluate(async () => chrome.scripting.getRegisteredContentScripts());
    const registration = registrations.find((item) => item.id === "kvpp-webauthn-intercept");
    if (registration) {
      return registration;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  const diagnostics = await worker.evaluate(async () => ({
    permissions: await chrome.permissions.getAll(),
    registrations: await chrome.scripting.getRegisteredContentScripts()
  }));
  throw new Error(`Dynamic WebAuthn content script was not registered: ${JSON.stringify(diagnostics)}`);
}

async function waitForAuthorizationDialog(browserContext, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const dialog = browserContext.pages().find((candidate) => candidate.url().includes("/uv-dialog.html"));
    if (dialog) {
      return dialog;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error("Timed out waiting for the extension authorization dialog.");
}

async function waitForAuthorizationDialogOrResult(browserContext, resultPromise, label) {
  return Promise.race([
    waitForAuthorizationDialog(browserContext),
    resultPromise.then((result) => {
      throw new Error(`${label} request completed before opening an authorization dialog: ${JSON.stringify(result)}`);
    })
  ]);
}

async function waitForPageClosed(page, label, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (page.isClosed()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error(`Timed out waiting for ${label} to close.`);
}

async function waitForFrame(page, urlPattern, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const frame = page.frames().find((candidate) => urlPattern.test(candidate.url()));
    if (frame) {
      return frame;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error(`Timed out waiting for child frame matching ${urlPattern}.`);
}

async function resolveEdgePath() {
  const candidates = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
  ];
  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // Continue through the known Edge installation paths.
    }
  }
  throw new Error("Unable to locate Microsoft Edge.");
}
