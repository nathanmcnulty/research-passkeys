import {
  extensionResponseSource,
  pageCancelSource,
  pageRequestSource,
  type PageBridgeMessage,
  type PageResponseMessage,
  type RuntimeRequest,
  type RuntimeResponse
} from "./shared/protocol";
import { serializeRuntimeCredentialOptions } from "./shared/runtime-credential-options";

const contentScriptMarkerAttribute = "data-kvpp-content-script";
const pendingPageRequestIds = new Set<string>();

if (markContentScriptInitialized()) {
  injectPageScript();

  window.addEventListener("message", (event: MessageEvent<PageBridgeMessage>) => {
    if (event.source !== window) {
      return;
    }

    if (event.data?.source !== pageRequestSource && event.data?.source !== pageCancelSource) {
      return;
    }

    const origin = window.location.origin;
    if (event.data.source === pageCancelSource) {
      if (!pendingPageRequestIds.delete(event.data.requestId)) {
        return;
      }

      chrome.runtime.sendMessage({
        kind: "cancel-webauthn-request",
        requestId: event.data.requestId,
        origin
      } satisfies RuntimeRequest, () => {
        void chrome.runtime.lastError;
      });
      return;
    }

    const request: RuntimeRequest = {
      kind: "webauthn-request",
      requestId: event.data.requestId,
      operation: event.data.operation,
      clientData: describeFrameClientData(origin),
      options: serializeRuntimeCredentialOptions(event.data.options)
    };

    pendingPageRequestIds.add(event.data.requestId);
    chrome.runtime.sendMessage(request, (response: RuntimeResponse | undefined) => {
      const wasPending = pendingPageRequestIds.delete(event.data.requestId);
      const runtimeError = chrome.runtime.lastError;
      if (!wasPending) {
        return;
      }

      if (runtimeError) {
        postResponse({
          source: extensionResponseSource,
          requestId: event.data.requestId,
          action: "reject",
          error: {
            name: "Error",
            message: runtimeError.message || "Extension message dispatch failed."
          }
        });
        return;
      }

      if (!response) {
        postResponse({
          source: extensionResponseSource,
          requestId: event.data.requestId,
          action: "reject",
          error: {
            name: "AbortError",
            message: "Extension did not return a WebAuthn response."
          }
        });
        return;
      }

      if (!response.ok) {
        postResponse({
          source: extensionResponseSource,
          requestId: event.data.requestId,
          action: "reject",
          error: response.error
        });
        return;
      }

      if ("credential" in response) {
        postResponse({
          source: extensionResponseSource,
          requestId: event.data.requestId,
          action: "complete",
          credential: response.credential
        });
        return;
      }

      if ("action" in response && response.action === "fallback") {
        postResponse({
          source: extensionResponseSource,
          requestId: event.data.requestId,
          action: "fallback",
          reason: response.reason
        });
        return;
      }

      postResponse({
        source: extensionResponseSource,
        requestId: event.data.requestId,
        action: "reject",
        error: {
          name: "AbortError",
          message: "Extension returned an unexpected WebAuthn response shape."
        }
      });
    });
  });
}

function describeFrameClientData(origin: string): Extract<RuntimeRequest, { kind: "webauthn-request" }>["clientData"] {
  const ancestorOrigins = window.location.ancestorOrigins;
  if (ancestorOrigins.length > 0) {
    const origins: string[] = [];
    for (let index = 0; index < ancestorOrigins.length; index += 1) {
      const value = ancestorOrigins.item(index);
      if (value) {
        origins.push(value);
      }
    }

    const topOrigin = origins[origins.length - 1] ?? null;
    const crossOrigin = origins.some((value) => value !== origin);
    return {
      origin,
      crossOrigin,
      topOrigin: crossOrigin ? topOrigin : null
    };
  }

  if (window.top === window) {
    return { origin, crossOrigin: false, topOrigin: null };
  }

  try {
    const topOrigin = window.top?.location.origin ?? null;
    return {
      origin,
      crossOrigin: topOrigin !== null && topOrigin !== origin,
      topOrigin: topOrigin !== null && topOrigin !== origin ? topOrigin : null
    };
  } catch {
    return { origin, crossOrigin: true, topOrigin: null };
  }
}

function markContentScriptInitialized(): boolean {
  const root = document.documentElement;
  if (!root) {
    return true;
  }

  if (root.hasAttribute(contentScriptMarkerAttribute)) {
    return false;
  }

  root.setAttribute(contentScriptMarkerAttribute, "true");
  return true;
}

function injectPageScript() {
  const pageScript = document.createElement("script");
  pageScript.src = chrome.runtime.getURL("page.js");
  pageScript.async = false;
  pageScript.dataset.kvppInjected = "true";
  (document.head || document.documentElement).appendChild(pageScript);
  pageScript.remove();
}

function postResponse(message: PageResponseMessage) {
  window.postMessage(message, window.location.origin);
}
