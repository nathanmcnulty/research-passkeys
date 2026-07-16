import { chromium } from "playwright-core";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const distDir = path.join(root, "dist");
const sourceProfile = process.argv[2];

if (!sourceProfile) {
  throw new Error("Usage: node ./scripts/inspect-edge-session-state.mjs <profile-path>");
}

const edgePath = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

async function main() {
  const cloneProfile = await fs.mkdtemp(path.join(root, ".edge-profile", "inspect-"));
  await fs.cp(sourceProfile, cloneProfile, {
    recursive: true,
    force: true,
    filter: (entryPath) => {
      const baseName = path.basename(entryPath);
      const parentName = path.basename(path.dirname(entryPath));
      if (baseName.includes("Cookies")) {
        return false;
      }

      if (parentName === "Sessions") {
        return false;
      }

      return ![
        "SingletonCookie",
        "SingletonLock",
        "SingletonSocket",
        "lockfile"
      ].includes(baseName);
    }
  });

  const context = await chromium.launchPersistentContext(cloneProfile, {
    executablePath: edgePath,
    headless: true,
    ignoreDefaultArgs: ["--disable-extensions"],
    args: [
      `--disable-extensions-except=${distDir}`,
      `--load-extension=${distDir}`
    ]
  });

  try {
    const extensionId = await waitForExtensionId(context);
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: "domcontentloaded" });
    await popup.waitForSelector("#authStatus");

    const summary = await popup.evaluate(() => ({
      authStatus: document.querySelector("#authStatus")?.textContent?.trim() ?? "",
      storedCredentialCount: document.querySelector("#storedCredentialCount")?.textContent?.trim() ?? "",
      relyingPartyCount: document.querySelector("#relyingPartyCount")?.textContent?.trim() ?? "",
      metadataLastUpdatedAt: document.querySelector("#metadataLastUpdatedAt")?.textContent?.trim() ?? "",
      lastInterceptedAt: document.querySelector("#lastInterceptedAt")?.textContent?.trim() ?? "",
      lastOrigin: document.querySelector("#lastOrigin")?.textContent?.trim() ?? ""
    }));

    const debug = await popup.evaluate(() => new Promise((resolve, reject) => {
      chrome.storage.local.get(["kvpp.debug.createPhase", "kvpp.debug.getState", "kvpp.extension.state"], (items) => {
        const runtimeError = chrome.runtime.lastError;
        if (runtimeError) {
          reject(new Error(runtimeError.message));
          return;
        }

        resolve(items);
      });
    }));

    console.log(JSON.stringify({ extensionId, summary, debug }, null, 2));
  }
  finally {
    await context.close();
    await fs.rm(cloneProfile, { recursive: true, force: true });
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

    await context.waitForTimeout(250);
  }

  throw new Error("Extension service worker did not start.");
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});