import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "src", "shared", "function-catalog-client.ts")],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node20",
  write: false
});
const source = result.outputFiles[0].text;
const adapter = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

const activeRecord = {
  schemaVersion: "1",
  recordId: "2de42a55-63db-53e7-bd38-56c320db6d55",
  provider: "entra",
  credentialId: "credential-id",
  rpId: "login.microsoft.com",
  userHandle: "user-handle",
  userName: "user@example.com",
  displayName: "Example User",
  keyVault: {
    vaultName: "kv-example",
    keyName: "passkey-example",
    keyId: "https://kv-example.vault.azure.net/keys/passkey-example/version"
  },
  status: "active",
  signCount: 3,
  createdAt: "2026-07-14T10:00:00Z",
  updatedAt: "2026-07-14T11:00:00Z"
};
const disabledRecord = {
  ...activeRecord,
  recordId: "cce41055-e63f-5727-8b45-5f3d35d2ccf2",
  credentialId: "disabled-credential",
  status: "disabled"
};

let requestedUrl = "";
let requestedAuthorization = "";
const client = new adapter.DevelopmentFunctionCatalogClient(
  {
    baseUrl: "https://func-example.azurewebsites.net/api/",
    apiScope: "api://client-id/access_as_user"
  },
  async (scopes) => {
    assert.deepEqual(scopes, ["api://client-id/access_as_user"]);
    return { accessToken: "api-token" };
  },
  async function (url, init) {
    assert.equal(this, globalThis, "fetch must be invoked with the worker global as its receiver");
    requestedUrl = String(url);
    requestedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
    return Response.json({ success: true, records: [activeRecord, disabledRecord] });
  }
);

const snapshot = await client.loadSnapshot();
assert.equal(requestedUrl, "https://func-example.azurewebsites.net/api/passkeys");
assert.equal(requestedAuthorization, "Bearer api-token");
assert.deepEqual(snapshot.activeRecords, [{
  recordId: activeRecord.recordId,
  credentialId: activeRecord.credentialId,
  rpId: activeRecord.rpId,
  userHandle: activeRecord.userHandle,
  userName: activeRecord.userName,
  userDisplayName: activeRecord.displayName,
  signingKeyId: activeRecord.keyVault.keyId,
  backendKind: "key-vault",
  createdAt: activeRecord.createdAt,
  updatedAt: activeRecord.updatedAt,
  signCount: activeRecord.signCount
}]);
assert.deepEqual([...snapshot.knownRecordIds].sort(), [activeRecord.recordId, disabledRecord.recordId].sort());

let assertionBody;
const assertionClient = new adapter.DevelopmentFunctionCatalogClient(
  { baseUrl: "https://func-example.azurewebsites.net", apiScope: "api://client-id/access_as_user" },
  async () => ({ accessToken: "api-token" }),
  async (url, init) => {
    assert.equal(String(url), `https://func-example.azurewebsites.net/api/passkeys/${activeRecord.recordId}/assert`);
    assertionBody = JSON.parse(String(init.body));
    return Response.json({
      success: true,
      authenticatorData: "AA",
      signature: "AA",
      signatureFormat: "ieee-p1363",
      signCount: 4
    });
  }
);
const assertion = await assertionClient.assert(activeRecord.recordId, activeRecord.rpId, new Uint8Array(32), true);
assert.equal(assertion.signCount, 4);
assert.equal(assertionBody.rpId, activeRecord.rpId);
assert.equal(assertionBody.userVerified, true);

const browserContextClient = new adapter.DevelopmentFunctionCatalogClient(
  { baseUrl: "https://func-example.azurewebsites.net/api", apiScope: "api://client-id/access_as_user" },
  async () => ({ accessToken: "api-token" }),
  async (url, init) => {
    assert.equal(String(url), `https://func-example.azurewebsites.net/api/passkeys/${activeRecord.recordId}/browser-context`);
    assert.equal(init.method, "GET");
    return Response.json({
      success: true,
      browserContext: {
        provider: "entra",
        rpId: activeRecord.rpId,
        userName: activeRecord.userName,
        userAgent: "Captured browser UA"
      }
    });
  }
);
assert.deepEqual(await browserContextClient.loadBrowserContext(activeRecord.recordId), {
  provider: "entra",
  rpId: activeRecord.rpId,
  userName: activeRecord.userName,
  userAgent: "Captured browser UA"
});

const deleteClient = new adapter.DevelopmentFunctionCatalogClient(
  { baseUrl: "https://func-example.azurewebsites.net", apiScope: "api://client-id/access_as_user" },
  async () => ({ accessToken: "api-token" }),
  async (url, init) => {
    assert.equal(String(url), `https://func-example.azurewebsites.net/api/passkeys/${activeRecord.recordId}`);
    assert.equal(init.method, "DELETE");
    return Response.json({ success: true, recordId: activeRecord.recordId, status: "deleted" });
  }
);
await deleteClient.delete(activeRecord.recordId);

await assert.rejects(
  () => new adapter.DevelopmentFunctionCatalogClient(
    {
      baseUrl: "http://func-example.test",
      apiScope: "api://client-id/access_as_user"
    },
    async () => ({ accessToken: "api-token" }),
    async () => Response.json({ success: true, records: [] })
  ).loadSnapshot(),
  /must use HTTPS/
);

console.log("Development Function catalog adapter validation passed.");
