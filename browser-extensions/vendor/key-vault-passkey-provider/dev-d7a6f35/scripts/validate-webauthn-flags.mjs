import assert from "node:assert/strict";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "src", "shared", "webauthn-data.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false
});
const source = result.outputFiles[0]?.text;
assert.ok(source, "WebAuthn data bundle was not produced");
const webauthn = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

const credentialId = new Uint8Array(32);
const coordinate = new Uint8Array(32);
const defaultRegistration = await webauthn.buildMakeCredentialAuthenticatorData(
  "example.com",
  credentialId,
  coordinate,
  coordinate
);
assert.equal(defaultRegistration[32] & 0x01, 0, "UP must default to false");
assert.equal(defaultRegistration[32] & 0x04, 0, "UV must default to false");
assert.equal(defaultRegistration[32] & 0x40, 0x40, "registration must include attested credential data");

const approvedRegistration = await webauthn.buildMakeCredentialAuthenticatorData(
  "example.com",
  credentialId,
  coordinate,
  coordinate,
  0,
  true,
  false
);
assert.equal(approvedRegistration[32] & 0x01, 0x01, "approved registration must set UP");
assert.equal(approvedRegistration[32] & 0x04, 0, "browser approval must not set UV");

const defaultAssertion = await webauthn.buildAssertionAuthenticatorData("example.com", 1);
assert.equal(defaultAssertion[32] & 0x05, 0, "assertion flags must default to neither UP nor UV");

const approvedAssertion = await webauthn.buildAssertionAuthenticatorDataWithFlags("example.com", 1, true, false);
assert.equal(approvedAssertion[32] & 0x01, 0x01, "approved assertion must set UP");
assert.equal(approvedAssertion[32] & 0x04, 0, "browser approval must not set UV");

const noneAttestation = webauthn.buildNoneAttestationObject(approvedRegistration);
const encodedAttestation = Buffer.from(noneAttestation);
assert.ok(encodedAttestation.includes(Buffer.from("none")), "attestation format must be none");
assert.ok(!encodedAttestation.includes(Buffer.from("packed")), "packed attestation must not be emitted");

console.log("WebAuthn flag and attestation validation passed.");
