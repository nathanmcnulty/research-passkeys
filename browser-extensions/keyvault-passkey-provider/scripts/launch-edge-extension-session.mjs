import { chromium } from "playwright-core";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const distDir = path.join(root, "dist");
const userDataRoot = path.join(root, ".edge-profile");
const artifactsPath = path.resolve(root, "..", "..", "artifacts", "browser-extension-dev-environment.json");
const targetUrl = process.argv[2] ?? "https://ctap.dev";

async function main() {
  await ensureExtensionBuild(distDir);

  const edgePath = await resolveEdgePath();
  const devEnvironment = await loadDevEnvironment();
  await fs.mkdir(userDataRoot, { recursive: true });
  const { userDataDir, sourceProfile } = await prepareInteractiveProfile(userDataRoot);

  const context = await chromium.launchPersistentContext(userDataDir, {
    executablePath: edgePath,
    headless: false,
    ignoreDefaultArgs: ["--disable-extensions"],
    args: [
      `--disable-extensions-except=${distDir}`,
      `--load-extension=${distDir}`
    ]
  });

  const extensionId = await waitForExtensionId(context);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: "domcontentloaded" });
  await popup.waitForSelector("#enabled");
  await hydratePopupConfig(popup, devEnvironment.config);
  const cachedSignInReady = await isSignedIn(popup);
  if (cachedSignInReady && typeof devEnvironment.devPinUvPin === "string" && devEnvironment.devPinUvPin.length > 0) {
    await seedPinUv(popup, devEnvironment.devPinUvPin);
  }
  await reloadExtension(context, popup);
  await popup.close();

  const page = context.pages()[0] ?? await context.newPage();
  wirePageLogging(page);
  await page.goto(targetUrl, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);

  const shimActive = await detectShimState(page);

  console.log(`EDGE_PATH=${edgePath}`);
  console.log(`EXTENSION_DIR=${distDir}`);
  console.log(`USER_DATA_DIR=${userDataDir}`);
  if (sourceProfile) {
    console.log(`SOURCE_PROFILE=${sourceProfile}`);
  }
  console.log("EXTENSION_CONFIG_HYDRATED=1");
  console.log(`PIN_UV_DEV_SEEDED=${cachedSignInReady && typeof devEnvironment.devPinUvPin === "string" && devEnvironment.devPinUvPin.length > 0 ? "1" : "0"}`);
  console.log(`PAGE_URL=${page.url()}`);
  console.log(`WEBAUTHN_SHIM=${shimActive ? "override" : "native"}`);
  console.log("BROWSER_SESSION_READY=1");
  console.log("Close the Edge window to end this session.");

  context.on("page", (nextPage) => {
    wirePageLogging(nextPage);
  });

  await context.waitForEvent("close", { timeout: 0 });
}

async function prepareInteractiveProfile(rootPath) {
  const sourceProfile = await findLatestCloneableProfile(rootPath);
  if (!sourceProfile) {
    return {
      userDataDir: await fs.mkdtemp(path.join(rootPath, "session-")),
      sourceProfile: null
    };
  }

  return {
    userDataDir: await cloneProfile(sourceProfile, rootPath),
    sourceProfile
  };
}

async function findLatestCloneableProfile(rootPath) {
  const entries = await fs.readdir(rootPath, { withFileTypes: true });
  const candidates = [];

  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith("session-")) {
      continue;
    }

    const fullPath = path.join(rootPath, entry.name);
    const stat = await fs.stat(fullPath);
    candidates.push({ path: fullPath, mtimeMs: stat.mtimeMs });
  }

  candidates.sort((left, right) => right.mtimeMs - left.mtimeMs);

  for (const candidate of candidates) {
    if (await isProfileCloneable(candidate.path, rootPath)) {
      return candidate.path;
    }
  }

  return null;
}

async function cloneProfile(sourceProfile, rootPath) {
  const destination = await fs.mkdtemp(path.join(rootPath, "session-"));
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
    // Reload tears down the popup context immediately in most runs.
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

function delay(timeoutMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, timeoutMs);
  });
}

async function hydratePopupConfig(popup, config) {
  await popup.waitForSelector("#enabled");

  await popup.evaluate(async (nextConfig) => {
    const nextState = {
      enabled: false,
      config: nextConfig,
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
  await popup.waitForSelector("#enabled");
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
    const savePinButton = document.querySelector("#savePin");
    return authStatus.startsWith("signed-in:") && savePinButton instanceof HTMLButtonElement && !savePinButton.disabled;
  }, undefined, { timeout: 15000 });

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
      return status.startsWith("Configured");
    }, undefined, { timeout: 15000 });
  } catch {
    const diagnostics = await popup.evaluate(() => ({
      authStatus: document.querySelector("#authStatus")?.textContent?.trim() ?? "",
      pinUvStatus: document.querySelector("#pinUvStatus")?.textContent?.trim() ?? "",
      status: document.querySelector("#status")?.textContent?.trim() ?? "",
      pinHint: document.querySelector("#pinHint")?.textContent?.trim() ?? ""
    }));
    throw new Error(`Timed out seeding the development PIN UV state: ${JSON.stringify(diagnostics)}`);
  }
}

async function isSignedIn(popup) {
  return popup.evaluate(() => {
    const authStatus = document.querySelector("#authStatus")?.textContent?.trim() ?? "";
    return authStatus.startsWith("signed-in:");
  });
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

async function loadDevEnvironment() {
  const raw = await fs.readFile(artifactsPath, "utf8");
  const config = JSON.parse(raw);
  return {
    config: {
      tenantId: config.tenantId ?? "",
      clientId: config.clientId ?? "",
      authorityHost: config.authorityHost ?? "https://login.microsoftonline.com",
      keyVaultBaseUrl: config.keyVaultBaseUrl ?? "",
      signingKeyName: config.signingKeyName ?? "passkey-signing-key",
      signingKeyType: config.signingKeyType === "EC-HSM" ? "EC-HSM" : "EC",
      metadataWrappingKeyName: config.metadataWrappingKeyName ?? "passkey-metadata-wrap-key",
      metadataTransportMode: config.metadataTransportMode === "LocalCacheOnly" ? "LocalCacheOnly" : "KeyVaultSecrets",
      metadataSecretPrefix: config.metadataSecretPrefix ?? "kvpp-md"
    },
    devPinUvPin: typeof config.devPinUvPin === "string" ? config.devPinUvPin : ""
  };
}

async function detectShimState(page) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      const shimSource = await page.evaluate(() => navigator.credentials.create.toString());
      return !shimSource.includes("[native code]");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes("Execution context was destroyed")) {
        throw error;
      }

      await page.waitForLoadState("domcontentloaded").catch(() => {});
      await page.waitForTimeout(500);
    }
  }

  return false;
}

function wirePageLogging(page) {
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) {
      console.log(`PAGE_NAVIGATED ${frame.url()}`);
    }
  });

  page.on("console", (message) => {
    console.log(`PAGE_CONSOLE ${message.type()} ${message.text()}`);
  });

  page.on("pageerror", (error) => {
    console.log(`PAGE_ERROR ${error.message}`);
  });

  page.on("requestfailed", (request) => {
    const failureText = request.failure()?.errorText ?? "unknown";
    console.log(`REQUEST_FAILED ${request.method()} ${request.url()} ${failureText}`);
  });
}

async function ensureExtensionBuild(extensionDir) {
  const manifestPath = path.join(extensionDir, "manifest.json");
  try {
    await fs.access(manifestPath);
  } catch {
    throw new Error(`Browser extension build output was not found at ${manifestPath}. Run npm run build first.`);
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
    } catch {
      // Continue scanning known paths.
    }
  }

  throw new Error("Unable to locate msedge.exe in the standard installation paths.");
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});