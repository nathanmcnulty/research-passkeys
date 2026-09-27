import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ReadOnlyFunctionCatalog } from "./catalog.mjs";

const experimentRoot = path.dirname(fileURLToPath(import.meta.url));
const researchRoot = path.resolve(experimentRoot, "../../..");

const record = {
  recordId: "2de42a55-63db-53e7-bd38-56c320db6d55",
  credentialId: "credential-id",
  rpId: "login.microsoft.com",
  userHandle: "user-handle",
  userName: "user@example.com",
  displayName: "Example User",
  status: "active",
  signCount: 3,
  updatedAt: "2026-07-14T11:00:00Z"
};

function client(fetchImpl, tokenProvider = async () => ({ accessToken: "test-token" })) {
  return new ReadOnlyFunctionCatalog({
    baseUrl: "https://func-example.azurewebsites.net/api/",
    apiScope: "api://client-id/access_as_user",
    tokenProvider,
    fetchImpl
  });
}

test("reads only the catalog with a scoped token and no redirect", async () => {
  const calls = [];
  const result = await client(async function (url, init) {
    assert.equal(this, globalThis);
    calls.push({ url, init });
    return Response.json({ success: true, records: [record, { ...record,
      recordId: "cce41055-e63f-5727-8b45-5f3d35d2ccf2", credentialId: "disabled-id", status: "disabled" }] });
  }, async (scopes) => {
    assert.deepEqual(scopes, ["api://client-id/access_as_user"]);
    return { accessToken: "test-token" };
  }).list();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://func-example.azurewebsites.net/api/passkeys");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.headers.Authorization, "Bearer test-token");
  assert.deepEqual(result.map((entry) => entry.status), ["active", "disabled"]);
  assert.equal(result[0].credentialId, record.credentialId);
  assert.equal("keyVault" in result[0], false);
});

test("rejects unsafe endpoints before requesting a token", () => {
  for (const baseUrl of ["http://remote.example", "https://user:pass@example.com",
    "https://example.com/?token=x", "https://example.com/#fragment", "relative/path"]) {
    assert.throws(() => new ReadOnlyFunctionCatalog({ baseUrl, apiScope: "scope",
      tokenProvider: () => { throw new Error("should not run"); } }), /URL|HTTPS/);
  }
});

test("fails closed on missing token and invalid catalog responses", async () => {
  let called = false;
  await assert.rejects(client(async () => { called = true; }, async () => ({})).list(), /token is unavailable/);
  assert.equal(called, false);
  const invalid = [
    { success: false, records: [record] },
    { success: true, records: [record, record] },
    { success: true, records: [{ ...record, userHandle: null }] },
    { success: true, records: [{ ...record, signCount: -1 }] }
  ];
  for (const payload of invalid) {
    await assert.rejects(client(async () => Response.json(payload)).list(), /invalid|duplicate/);
  }
  await assert.rejects(client(async () => new Response("denied", { status: 403 })).list(), /HTTP 403/);
});

test("exposes no assertion, registration, context, or mutation method", () => {
  const methods = Object.getOwnPropertyNames(ReadOnlyFunctionCatalog.prototype);
  assert.deepEqual(methods, ["constructor", "list"]);
});

test("declares every overlay file and the active immutable baseline", async () => {
  const overlay = JSON.parse(await readFile(path.join(experimentRoot, "overlay.json"), "utf8"));
  const lock = JSON.parse(await readFile(path.join(researchRoot,
    "browser-extensions/upstream-provider.lock.json"), "utf8"));
  assert.equal(overlay.baselineCommit, lock.provider.commit);
  assert.equal(overlay.composition, "none");
  assert.equal(overlay.browserIdentity, null);
  assert.deepEqual(overlay.allowedOperations, ["GET /api/passkeys"]);
  const actual = (await readdir(experimentRoot)).map((name) =>
    `browser-extensions/experiments/function-catalog/${name}`).sort();
  assert.deepEqual(actual, [...overlay.changedPaths].sort());
});
