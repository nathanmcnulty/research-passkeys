import type { BrowserAuthStatus, BrowserExtensionConfig } from "./protocol";

export type SetupProgress = {
  configReady: boolean;
  authReady: boolean;
  pinReady: boolean;
  isComplete: boolean;
};

export function isConfigReady(config: BrowserExtensionConfig): boolean {
  if (!config.tenantId.trim() || !config.clientId.trim() || !config.authorityHost.trim()) {
    return false;
  }

  if (config.metadataTransportMode === "LocalCacheOnly") {
    return true;
  }

  return Boolean(config.keyVaultBaseUrl.trim() && config.metadataWrappingKeyName.trim());
}

export function evaluateSetupProgress(
  config: BrowserExtensionConfig,
  authMode: BrowserAuthStatus["mode"],
  pinReady: boolean
): SetupProgress {
  const configReady = isConfigReady(config);
  const authReady = config.metadataTransportMode === "LocalCacheOnly"
    ? true
    : authMode === "signed-in";

  return {
    configReady,
    authReady,
    pinReady,
    isComplete: configReady && authReady && pinReady
  };
}

export function getSetupIncompleteMessage(progress: SetupProgress, config: BrowserExtensionConfig): string {
  if (!progress.configReady) {
    return config.metadataTransportMode === "LocalCacheOnly"
      ? "Finish setup by saving the extension configuration and setting the extension PIN first."
      : "Finish setup by saving the Key Vault configuration first.";
  }

  if (!progress.authReady) {
    return "Finish setup by signing in to Key Vault before using the extension.";
  }

  if (!progress.pinReady) {
    return "Finish setup by setting the extension PIN before using the extension.";
  }

  return "Setup is complete.";
}