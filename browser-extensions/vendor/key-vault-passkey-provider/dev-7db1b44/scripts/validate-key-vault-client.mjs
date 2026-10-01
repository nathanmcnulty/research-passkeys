import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
async function loadModule(name) {
  const result = await build({ entryPoints: [path.join(root, "src/shared", `${name}.ts`)], bundle: true, format: "esm", platform: "browser", target: "es2022", write: false });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`);
}
const { KeyVaultClient } = await loadModule("key-vault-client");
const { buildCredentialKeyName } = await loadModule("security-boundaries");
const { encodeEs256Signature } = await loadModule("webauthn-data");
const vault = "https://example-vault.vault.azure.net";
const requests = [];
let tokenCalls = 0;
let responseStatus = 200;
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, options) => {
  requests.push({ url, ...options });
  return new Response(JSON.stringify({ id: `${vault}/secrets/example/version`, value: "fixture" }), { status: responseStatus });
};
try {
  const client = new KeyVaultClient({ baseUrl: `${vault}/`, signingKeyName: "credential", metadataWrappingKeyName: "wrap" }, async () => { tokenCalls++; return { accessToken: "test-only" }; });
  for (const identifier of [`${vault}/keys/credential/version`, "keys/credential/version", "credential"]) {
    await client.deleteKey(identifier);
    assert.equal(requests.at(-1).url, `${vault}/keys/credential?api-version=7.5`);
    assert.equal(requests.at(-1).method, "DELETE");
    assert.equal(requests.at(-1).redirect, "error");
  }
  responseStatus = 404;
  await client.deleteKey(`${vault}/keys/credential/version`);
  responseStatus = 403;
  await assert.rejects(client.deleteKey("credential"), (error) => error.name === "SecurityError");
  responseStatus = 200;
  const callsBeforeInvalid = tokenCalls;
  await assert.rejects(client.deleteKey("https://attacker.example/keys/credential/version"));
  await assert.rejects(client.signDigest("credential", new Uint8Array(31)));
  await assert.rejects(client.createEcP256Key("credential/version", "EC"));
  assert.equal(tokenCalls, callsBeforeInvalid, "invalid input acquired a token");
  await client.setSecret("example", "fixture");
  await client.getSecret("example");
  await client.deleteSecret("example");
  assert.ok(requests.slice(-3).every((request) => request.url === `${vault}/secrets/example?api-version=7.5`), "trailing-slash vault produced an invalid secret URL");
} finally {
  globalThis.fetch = originalFetch;
}

const prefix = "p".repeat(94);
const name = buildCredentialKeyName(prefix);
assert.match(name, new RegExp(`^${prefix}-[0-9a-f]{32}$`));
assert.equal(name.length, 127);
for (const invalid of ["p".repeat(95), "", "keys/name/version", "https://example.com", "prefix with spaces"]) {
  assert.throws(() => buildCredentialKeyName(invalid));
}
const small = new Uint8Array(64);
small[31] = 1;
small[63] = 2;
assert.deepEqual(Array.from(encodeEs256Signature(small)), [0x30, 6, 2, 1, 1, 2, 1, 2]);
const ambiguous = new Uint8Array(64);
ambiguous[0] = 0x30;
ambiguous[32] = 0x80;
const encoded = encodeEs256Signature(ambiguous);
assert.equal(encoded[4], 0x30, "raw 0x30 signature was misclassified as DER");
assert.deepEqual(Array.from(encoded.subarray(36, 40)), [2, 33, 0, 0x80]);
for (const length of [0, 63, 65, 72]) assert.throws(() => encodeEs256Signature(new Uint8Array(length)));
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
for (let index = 0; index < 10; index++) {
  const message = Buffer.from(`KVPP signature regression ${index}`);
  const raw = sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" });
  assert.equal(verify("sha256", message, { key: publicKey, dsaEncoding: "der" }, encodeEs256Signature(raw)), true);
}
console.log("Key Vault request, key-name, and cryptographic ES256 signature checks passed.");
