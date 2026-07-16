import { chromium } from "playwright-core";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const distDir = path.join(root, "dist");
const profileRoot = path.join(root, ".edge-profile");
const artifactsPath = path.resolve(root, "..", "..", "artifacts", "browser-extension-dev-environment.json");

const createScenarios = [
  {
    id: "baseline-none-attestation",
    options: {
      residentKey: "preferred",
      userVerification: "preferred",
      attestation: "none"
    }
  },
  {
    id: "direct-attestation-hmac",
    options: {
      residentKey: "preferred",
      userVerification: "preferred",
      attestation: "direct",
      extensions: {
        hmacCreateSecret: true,
        credentialProtectionPolicy: "userVerificationOptional"
      }
    }
  },
  {
    id: "required-uv-direct-attestation",
    options: {
      residentKey: "preferred",
      userVerification: "required",
      attestation: "direct",
      extensions: {
        hmacCreateSecret: true,
        credentialProtectionPolicy: "userVerificationOptional"
      }
    }
  }
];

async function main() {
  await ensureFile(path.join(distDir, "manifest.json"), "Run npm run build first.");
  logStep("loaded build output");

  const devEnvironment = JSON.parse(await fs.readFile(artifactsPath, "utf8"));
  if (typeof devEnvironment.devPinUvPin !== "string" || devEnvironment.devPinUvPin.length < 6) {
    throw new Error("Set a development PIN with devPinUvPin in artifacts/browser-extension-dev-environment.json before running PIN UV validation.");
  }
  const { sourceProfile, automationProfile } = await prepareAutomationProfile(profileRoot);
  const edgePath = await resolveEdgePath();
  logStep(`using source profile ${sourceProfile}`);
  logStep(`using automation profile ${automationProfile}`);

  const context = await chromium.launchPersistentContext(automationProfile, {
    executablePath: edgePath,
    headless: false,
    ignoreDefaultArgs: ["--disable-extensions"],
    args: [
      `--disable-extensions-except=${distDir}`,
      `--load-extension=${distDir}`
    ]
  });
  logStep("launched Edge persistent context");
  context.on("page", (page) => {
    page.on("console", (message) => {
      console.log(`[page-console:${message.type()}] ${message.text()}`);
    });

    page.on("pageerror", (error) => {
      console.log(`[page-error] ${error.message}`);
    });
  });

  try {
    const extensionId = await waitForExtensionId(context);
    logStep(`resolved extension id ${extensionId}`);
    let popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: "domcontentloaded" });
    await popup.waitForSelector("#enabled");
    logStep("opened extension popup");

    await hydratePopupConfig(popup, devEnvironment);
    logStep("hydrated popup config");
    await reloadExtension(context, popup);
    popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: "domcontentloaded" });
    await waitForPopupReady(popup);
    logStep("reopened extension popup after reload");
    await ensureSignedIn(context, popup);
    logStep("extension reports signed-in");
    await seedPinUv(popup, devEnvironment.devPinUvPin);
    logStep("seeded development PIN UV state");

    const page = await context.newPage();
    await page.goto("https://ctap.dev/login", { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    logStep("opened ctap.dev/login");
    const shimState = await page.evaluate(() => navigator.credentials.create.toString());
    logStep(shimState.includes("[native code]") ? "shim inactive on ctap.dev" : "shim active on ctap.dev");

    const createResults = [];
    for (const scenario of createScenarios) {
      const pinDialogPromise = scenario.options.userVerification === "required"
        ? completePinUvDialog(context, devEnvironment.devPinUvPin)
        : Promise.resolve();
      const createResult = await runCreate(page, popup, scenario);
      await pinDialogPromise;
      createResults.push(createResult);
      logStep(`navigator.credentials.create completed for ${scenario.id} ${JSON.stringify(createResult)}`);
    }

    await page.waitForTimeout(4000);
    await popup.reload({ waitUntil: "domcontentloaded" });
    await waitForPopupReady(popup);
    const afterCreateSummary = await readPopupSummary(popup);
    logStep(`post-create popup summary ${JSON.stringify(afterCreateSummary)}`);
    const requiredCredential = createResults.find((result) => result.scenarioId === "required-uv-direct-attestation") ?? createResults[0];
    const pinDialogPromise = completePinUvDialog(context, devEnvironment.devPinUvPin);
    const getPromise = runGet(page, requiredCredential.rawIdBase64Url, "required");
    const chooserUsed = await maybeAcceptCredentialSelection(page);
    if (chooserUsed) {
      logStep("selected first passkey option from chooser overlay");
    }

    let getResult;
    try {
      getResult = await getPromise;
      await pinDialogPromise;
    }
    catch (error) {
      const getDebugState = await popup.evaluate(() => new Promise((resolve, reject) => {
        chrome.storage.local.get(["kvpp.debug.getState"], (items) => {
          const runtimeError = chrome.runtime.lastError;
          if (runtimeError) {
            reject(new Error(runtimeError.message));
            return;
          }

          resolve(items["kvpp.debug.getState"] ?? null);
        });
      }));
      logStep(`get() failed with debug state ${JSON.stringify(getDebugState)}`);
      throw error;
    }

    logStep("navigator.credentials.get completed");

    await popup.reload({ waitUntil: "domcontentloaded" });
    await waitForPopupReady(popup);

    const popupSummary = await readPopupSummary(popup);

    console.log(JSON.stringify({
      extensionId,
      profileSource: sourceProfile,
      automationProfile,
      createResults,
      getResult,
      popupSummary,
      afterCreateSummary
    }, null, 2));
  }
  finally {
    await context.close();
  }
}

async function ensureFile(filePath, message) {
  try {
    await fs.access(filePath);
  }
  catch {
    throw new Error(message);
  }
}

async function prepareAutomationProfile(rootPath) {
  const entries = await fs.readdir(rootPath, { withFileTypes: true });
  const candidates = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }

    if (!entry.name.startsWith("session-")) {
      continue;
    }

    const fullPath = path.join(rootPath, entry.name);
    const stat = await fs.stat(fullPath);
    candidates.push({ path: fullPath, mtimeMs: stat.mtimeMs });
  }

  if (candidates.length === 0) {
    throw new Error("No prior Edge session profiles were found under .edge-profile.");
  }

  candidates.sort((left, right) => right.mtimeMs - left.mtimeMs);

  let lastError = null;
  for (const candidate of candidates) {
    try {
      if (!await isProfileCloneable(candidate.path, rootPath)) {
        continue;
      }

      const automationProfile = await cloneProfile(candidate.path, rootPath);
      return {
        sourceProfile: candidate.path,
        automationProfile
      };
    }
    catch (error) {
      lastError = error;
    }
  }

  throw lastError ?? new Error("Unable to clone any prior Edge session profile.");
}

async function cloneProfile(sourceProfile, rootPath) {
  const destination = await fs.mkdtemp(path.join(rootPath, "automation-"));
  await fs.cp(sourceProfile, destination, {
    recursive: true,
    force: true,
    filter: (source) => {
      const baseName = path.basename(source);
      return ![
        "SingletonCookie",
        "SingletonLock",
        "SingletonSocket",
        "lockfile"
      ].includes(baseName);
    }
  });

  return destination;
}

async function isProfileCloneable(sourceProfile, rootPath) {
  const cookiePath = path.join(sourceProfile, "Default", "Network", "Cookies");
  const probePath = path.join(rootPath, `copy-probe-${process.pid}-${Math.random().toString(16).slice(2)}.tmp`);

  try {
    await fs.copyFile(cookiePath, probePath);
    return true;
  }
  catch {
    return false;
  }
  finally {
    await fs.rm(probePath, { force: true });
  }
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
    }
    catch {
      // Continue.
    }
  }

  throw new Error("Unable to locate Microsoft Edge.");
}

async function waitForExtensionId(context) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const worker = context.serviceWorkers()[0];
    if (worker) {
      const match = /^chrome-extension:\/\/([a-z]{32})\//.exec(worker.url());
      if (match) {
        return match[1];
      }
    }

    await delay(250);
  }

  throw new Error("Extension service worker did not start.");
}

async function reloadExtension(context, popup) {
  const previousWorker = context.serviceWorkers()[0] ?? null;

  await popup.evaluate(() => {
    chrome.runtime.reload();
  }).catch(() => {
    // Reload usually tears down the popup page immediately.
  });

  for (let attempt = 0; attempt < 80; attempt += 1) {
    const worker = context.serviceWorkers()[0] ?? null;
    if (worker && worker !== previousWorker) {
      return;
    }

    await delay(250);
  }

  await waitForExtensionId(context);
}

async function hydratePopupConfig(popup, config) {
  await popup.waitForSelector("#enabled");

  await popup.evaluate(async (nextConfig) => {
    const nextState = {
      enabled: false,
      config: {
        tenantId: nextConfig.tenantId ?? "",
        clientId: nextConfig.clientId ?? "",
        authorityHost: nextConfig.authorityHost ?? "https://login.microsoftonline.com",
        keyVaultBaseUrl: nextConfig.keyVaultBaseUrl ?? "",
        signingKeyName: nextConfig.signingKeyName ?? "passkey-signing-key",
        signingKeyType: nextConfig.signingKeyType === "EC-HSM" ? "EC-HSM" : "EC",
        metadataWrappingKeyName: nextConfig.metadataWrappingKeyName ?? "passkey-metadata-wrap-key",
        metadataTransportMode: nextConfig.metadataTransportMode === "LocalCacheOnly" ? "LocalCacheOnly" : "KeyVaultSecrets",
        metadataSecretPrefix: nextConfig.metadataSecretPrefix ?? "kvpp-md"
      },
      lastInterceptedAt: null,
      lastOrigin: null
    };

    await new Promise((resolve, reject) => {
      chrome.storage.local.set({ "kvpp.extension.state": nextState }, () => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }

        resolve();
      });
    });
  }, config);

  await popup.reload({ waitUntil: "domcontentloaded" });
  await waitForPopupReady(popup);

  const storedSnapshot = await popup.evaluate(async () => new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ kind: "get-state" }, (result) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve(result ?? null);
    });
  }));

  if (!storedSnapshot || storedSnapshot.ok !== true || !("state" in storedSnapshot)) {
    throw new Error(`Extension state could not be read after hydration: ${JSON.stringify(storedSnapshot)}`);
  }

  const { state } = storedSnapshot;
  if (state.enabled || state.config.tenantId !== config.tenantId || state.config.clientId !== config.clientId) {
    throw new Error(`Extension state was not reloaded from storage as expected: ${JSON.stringify({ enabled: state.enabled, tenantId: state.config.tenantId, clientId: state.config.clientId })}`);
  }
}

async function seedPinUv(popup, pin) {
  await popup.evaluate(async (nextPin) => {
    await new Promise((resolve, reject) => {
      chrome.storage.local.remove("kvpp.pinUvState", () => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }

        resolve();
      });
    });
  }, pin);

  await popup.reload({ waitUntil: "domcontentloaded" });
  await waitForPopupReady(popup);
  await popup.waitForFunction(() => {
    const authStatus = document.querySelector("#authStatus")?.textContent?.trim() ?? "";
    return authStatus.includes("Signed in") || authStatus.includes("signed-in");
  }, { timeout: 15000 });

  const response = await popup.evaluate(async (nextPin) => new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ kind: "set-pin-uv", newPin: nextPin }, (result) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }

      resolve(result ?? null);
    });
  }), pin);

  if (!response || response.ok !== true || !("pinUvStatus" in response) || !response.pinUvStatus?.isConfigured) {
    throw new Error(`Unable to seed the development PIN UV state: ${JSON.stringify(response)}`);
  }

  await popup.reload({ waitUntil: "domcontentloaded" });
  await waitForPopupReady(popup);

  try {
    await popup.waitForFunction(() => {
      const status = document.querySelector("#pinUvStatus")?.textContent?.trim() ?? "";
      return status.includes("Configured");
    }, undefined, { timeout: 15000 });
  } catch {
    const diagnostics = await popup.evaluate(() => ({
      authStatus: document.querySelector("#authStatus")?.textContent?.trim() ?? "",
      pinUvStatus: document.querySelector("#pinUvStatus")?.textContent?.trim() ?? "",
      status: document.querySelector("#status")?.textContent?.trim() ?? ""
    }));
    throw new Error(`Timed out seeding the development PIN UV state: ${JSON.stringify(diagnostics)}`);
  }
}

async function ensureSignedIn(context, popup) {
  let authStatus = await popup.locator("#authStatus").textContent();
  logStep(`initial auth status: ${(authStatus ?? "").trim()}`);
  if (authStatus?.includes("signed-in") || authStatus?.includes("Signed in")) {
    return;
  }

  logStep("clicking Sign In");
  await popup.locator("#signIn").click();
  await waitForSignedIn(context, popup, 120000);
}

async function waitForSignedIn(context, popup, timeoutMs) {
  const start = Date.now();
  let lastDiagnosticAt = 0;
  while (Date.now() - start < timeoutMs) {
    await handleMicrosoftAuthPages(context);

    const authStatus = (await popup.locator("#authStatus").textContent())?.trim() ?? "";
    if (authStatus.includes("signed-in") || authStatus.includes("Signed in")) {
      return;
    }

    const statusText = (await popup.locator("#status").textContent())?.trim() ?? "";
    if (statusText.includes("Unable to complete sign-in") || authStatus.includes("Token exchange failed")) {
      throw new Error(`Extension sign-in failed: ${statusText || authStatus}`);
    }

    if (Date.now() - lastDiagnosticAt >= 5000) {
      const pageUrls = context.pages().map((page) => page.url()).filter((url) => url.length > 0);
      logStep(`waiting for sign-in; authStatus='${authStatus}', status='${statusText}', openPages=${JSON.stringify(pageUrls)}`);
      lastDiagnosticAt = Date.now();
    }

    await popup.waitForTimeout(500);
  }

  throw new Error("Timed out waiting for extension sign-in.");
}

async function handleMicrosoftAuthPages(context) {
  const testAccountEmail = process.env.ENTRA_TEST_ACCOUNT_EMAIL?.trim();
  for (const page of context.pages()) {
    const url = page.url();
    if (!url.includes("login.microsoftonline.com")) {
      continue;
    }

    try {
      if (testAccountEmail) {
        const emailButton = page.getByText(testAccountEmail, { exact: true });
        if (await emailButton.isVisible({ timeout: 250 })) {
          logStep("clicked account picker email");
          await emailButton.click();
          continue;
        }
      }
    }
    catch {
      // Ignore missing control.
    }

    try {
      const continueButton = page.getByRole("button", { name: /continue|next|accept|yes/i });
      if (await continueButton.isVisible({ timeout: 250 })) {
        logStep(`clicked auth button on ${url}`);
        await continueButton.click();
        continue;
      }
    }
    catch {
      // Ignore missing control.
    }
  }
}

async function expectStatusText(page, pattern, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const statusText = (await page.locator("#status").textContent())?.trim() ?? "";
    if (pattern.test(statusText)) {
      return statusText;
    }

    await page.waitForTimeout(250);
  }

  throw new Error(`Timed out waiting for popup status matching ${pattern}.`);
}

async function runCreate(page, popup, scenario) {
  try {
    return await page.evaluate(async (currentScenario) => {
      const encodeBase64Url = (bytes) => {
        let binary = "";
        for (const value of bytes) {
          binary += String.fromCharCode(value);
        }

        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      };

      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const userId = crypto.getRandomValues(new Uint8Array(16));

      const credential = await navigator.credentials.create({
        publicKey: {
          rp: {
            id: "ctap.dev",
            name: "ctap.dev"
          },
          user: {
            id: userId,
            name: `kvpp-${Date.now()}@ctap.dev`,
            displayName: "KVPP Automation"
          },
          challenge,
          pubKeyCredParams: [
            {
              type: "public-key",
              alg: -7
            }
          ],
          authenticatorSelection: {
            residentKey: currentScenario.options.residentKey,
            userVerification: currentScenario.options.userVerification
          },
          timeout: 120000,
          attestation: currentScenario.options.attestation,
          extensions: currentScenario.options.extensions
        }
      });

      if (!credential || typeof credential !== "object" || !("rawId" in credential) || !("response" in credential)) {
        throw new Error("create() did not return a credential-shaped object.");
      }

      const rawId = new Uint8Array((credential.rawId));
      const response = credential.response;
      const extensionResults = typeof credential.getClientExtensionResults === "function"
        ? credential.getClientExtensionResults()
        : {};
      const transports = typeof response.getTransports === "function"
        ? response.getTransports()
        : [];
      return {
        scenarioId: currentScenario.id,
        id: credential.id,
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment ?? null,
        clientExtensionResults: extensionResults,
        transports,
        rawIdBase64Url: encodeBase64Url(rawId),
        clientDataJsonLength: response.clientDataJSON.byteLength,
        attestationObjectLength: response.attestationObject.byteLength
      };
    }, scenario);
  }
  catch (error) {
    const diagnostics = await readPopupDiagnostics(popup);
    logStep(`create() failed for ${scenario.id} with diagnostics ${JSON.stringify(diagnostics)}`);
    throw error;
  }
}

async function readPopupDiagnostics(popup) {
  await popup.reload({ waitUntil: "domcontentloaded" });
  await waitForPopupReady(popup);
  return popup.evaluate(async () => {
    const storageItems = await new Promise((resolve, reject) => {
      chrome.storage.local.get(["kvpp.debug.createPhase", "kvpp.debug.createState", "kvpp.debug.getState"], (items) => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }

        resolve(items);
      });
    });

    return {
      authStatus: document.querySelector("#authStatus")?.textContent?.trim() ?? "",
      storedCredentialCount: document.querySelector("#storedCredentialCount")?.textContent?.trim() ?? "",
      relyingPartyCount: document.querySelector("#relyingPartyCount")?.textContent?.trim() ?? "",
      lastInterceptedAt: document.querySelector("#lastInterceptedAt")?.textContent?.trim() ?? "",
      lastOrigin: document.querySelector("#lastOrigin")?.textContent?.trim() ?? "",
      pinUvStatus: document.querySelector("#pinUvStatus")?.textContent?.trim() ?? "",
      createPhase: storageItems["kvpp.debug.createPhase"] ?? null,
      createState: storageItems["kvpp.debug.createState"] ?? null,
      getState: storageItems["kvpp.debug.getState"] ?? null
    };
  });
}

async function readPopupSummary(popup) {
  return popup.evaluate(() => ({
    authStatus: document.querySelector("#authStatus")?.textContent?.trim() ?? "",
    storedCredentialCount: document.querySelector("#storedCredentialCount")?.textContent?.trim() ?? "",
    relyingPartyCount: document.querySelector("#relyingPartyCount")?.textContent?.trim() ?? "",
    metadataLastUpdatedAt: document.querySelector("#metadataLastUpdatedAt")?.textContent?.trim() ?? "",
    lastInterceptedAt: document.querySelector("#lastInterceptedAt")?.textContent?.trim() ?? "",
    lastOrigin: document.querySelector("#lastOrigin")?.textContent?.trim() ?? ""
  }));
}

async function waitForPopupReady(popup) {
  await popup.waitForSelector("body");
  await popup.waitForFunction(() => {
    const state = document.body.dataset.popupReady;
    return state === "true" || state === "error";
  }, undefined, { timeout: 70000 });

  const popupReadyState = await popup.evaluate(() => document.body.dataset.popupReady ?? "");
  if (popupReadyState === "error") {
    const diagnostics = await popup.evaluate(() => ({
      status: document.querySelector("#status")?.textContent?.trim() ?? "",
      authStatus: document.querySelector("#authStatus")?.textContent?.trim() ?? ""
    }));
    throw new Error(`Popup initialization failed: ${JSON.stringify(diagnostics)}`);
  }
}

async function runGet(page, rawIdBase64Url, userVerification = "preferred") {
  try {
    return await page.evaluate(async ({ encodedRawId, nextUserVerification }) => {
      const decodeBase64Url = (value) => {
        const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
          bytes[index] = binary.charCodeAt(index);
        }

        return bytes;
      };

      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const rawId = decodeBase64Url(encodedRawId);

      const credential = await navigator.credentials.get({
        publicKey: {
          rpId: "ctap.dev",
          challenge,
          allowCredentials: [
            {
              type: "public-key",
              id: rawId
            }
          ],
          userVerification: nextUserVerification,
          timeout: 120000
        }
      });

      if (!credential || typeof credential !== "object" || !("response" in credential)) {
        throw new Error("get() did not return a credential-shaped object.");
      }

      const response = credential.response;
      const assertion = response;
      return {
        id: credential.id,
        type: credential.type,
        authenticatorDataLength: assertion.authenticatorData.byteLength,
        clientDataJsonLength: assertion.clientDataJSON.byteLength,
        signatureLength: assertion.signature.byteLength,
        userHandleLength: assertion.userHandle?.byteLength ?? 0,
        mode: "allowCredentials"
      };
    }, {
      encodedRawId: rawIdBase64Url,
      nextUserVerification: userVerification
    });
  }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes("No stored passkey matched this request.")) {
      throw error;
    }

    return page.evaluate(async () => {
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const credential = await navigator.credentials.get({
        publicKey: {
          rpId: "ctap.dev",
          challenge,
          userVerification: "preferred",
          timeout: 120000
        }
      });

      if (!credential || typeof credential !== "object" || !("response" in credential)) {
        throw new Error("get() fallback did not return a credential-shaped object.");
      }

      const response = credential.response;
      const assertion = response;
      return {
        id: credential.id,
        type: credential.type,
        authenticatorDataLength: assertion.authenticatorData.byteLength,
        clientDataJsonLength: assertion.clientDataJSON.byteLength,
        signatureLength: assertion.signature.byteLength,
        userHandleLength: assertion.userHandle?.byteLength ?? 0,
        mode: "discoverable"
      };
    });
  }
}

async function completePinUvDialog(context, pin, timeoutMs = 20000) {
  const dialog = await waitForPinUvDialog(context, timeoutMs);
  await dialog.waitForSelector("#pin");
  await dialog.locator("#pin").fill(pin);
  await dialog.locator("#verify").click();

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (dialog.isClosed()) {
      return;
    }

    const statusText = (await dialog.locator("#status").textContent().catch(() => ""))?.trim() ?? "";
    if (statusText.includes("PIN verified")) {
      return;
    }

    try {
      await dialog.waitForTimeout(250);
    } catch {
      if (dialog.isClosed()) {
        return;
      }

      throw new Error("The PIN verification dialog closed unexpectedly.");
    }
  }

  throw new Error("Timed out waiting for the PIN verification dialog to complete.");
}

async function waitForPinUvDialog(context, timeoutMs) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    for (const page of context.pages()) {
      if (page.url().includes("/uv-dialog.html")) {
        return page;
      }
    }

    await delay(250);
  }

  throw new Error("Timed out waiting for the PIN verification dialog to open.");
}

async function maybeAcceptCredentialSelection(page, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const clicked = await page.evaluate(() => {
      const headings = Array.from(document.querySelectorAll("h2"));
      const title = headings.find((element) => element.textContent?.trim() === "Choose a passkey account");
      if (!title || !title.parentElement) {
        return false;
      }

      const buttons = Array.from(title.parentElement.querySelectorAll("button"));
      const choice = buttons.find((button) => button.textContent?.trim() !== "Cancel");
      if (!choice) {
        return false;
      }

      choice.click();
      return true;
    });

    if (clicked) {
      return true;
    }

    await page.waitForTimeout(250);
  }

  return false;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const value of bytes) {
    binary += String.fromCharCode(value);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function logStep(message) {
  console.log(`[validate-ctap-flow] ${message}`);
}

function delay(timeoutMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, timeoutMs);
  });
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
