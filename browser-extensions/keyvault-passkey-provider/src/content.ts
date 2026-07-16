import {
  extensionResponseSource,
  pageRequestSource,
  type PageRequestMessage,
  type PageResponseMessage,
  type RuntimeRequest,
  type RuntimeResponse
} from "./shared/protocol";
import { serializeRuntimeCredentialOptions } from "./shared/runtime-credential-options";

const contentScriptMarkerAttribute = "data-kvpp-content-script";

if (markContentScriptInitialized()) {
  injectPageScript();

  window.addEventListener("message", (event: MessageEvent<PageRequestMessage>) => {
    if (event.source !== window) {
      return;
    }

    if (event.data?.source !== pageRequestSource) {
      return;
    }

    const origin = window.location.origin;
    const request: RuntimeRequest = {
      kind: "webauthn-request",
      requestId: event.data.requestId,
      operation: event.data.operation,
      clientData: {
        ...event.data.clientData,
        origin
      },
      options: serializeRuntimeCredentialOptions(event.data.options)
    };

    chrome.runtime.sendMessage(request, (response: RuntimeResponse | undefined) => {
      const runtimeError = chrome.runtime.lastError;
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

      if ("action" in response && response.action === "select-account") {
        postResponse({
          source: extensionResponseSource,
          requestId: event.data.requestId,
          action: "select-account",
          options: response.options
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
