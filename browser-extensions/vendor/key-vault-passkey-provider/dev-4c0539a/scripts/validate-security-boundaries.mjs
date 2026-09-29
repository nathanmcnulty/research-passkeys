import assert from "node:assert/strict";
import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "src", "shared", "security-boundaries.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  write: false
});
const source = result.outputFiles[0]?.text;
assert.ok(source, "security boundary bundle was not produced");
const boundaries = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

const vault = "https://example-vault.vault.azure.net";
assert.equal(boundaries.normalizeKeyVaultBaseUrl(`${vault}/`), vault);
assert.equal(boundaries.getKeyVaultTokenScope(vault), "https://vault.azure.net/.default");
assert.equal(
  boundaries.getKeyVaultTokenScope("https://example-vault.vault.usgovcloudapi.net"),
  "https://vault.usgovcloudapi.net/.default"
);
assert.equal(boundaries.normalizeKeyVaultKeyPath(vault, "credential-key"), `${vault}/keys/credential-key`);
assert.equal(
  boundaries.normalizeKeyVaultKeyPath(vault, `${vault}/keys/credential-key/0123456789abcdef0123456789abcdef`),
  `${vault}/keys/credential-key/0123456789abcdef0123456789abcdef`
);
assert.doesNotThrow(() => boundaries.assertKeyVaultRequestUrl(`${vault}/keys/credential-key/sign?api-version=7.5`, vault));

for (const invalidBaseUrl of [
  "http://example-vault.vault.azure.net",
  "https://attacker.example",
  "https://attacker.example.vault.azure.net",
  "https://example-vault.vault.azure.net/path",
  "https://user@example-vault.vault.azure.net"
]) {
  assert.throws(() => boundaries.normalizeKeyVaultBaseUrl(invalidBaseUrl));
}

for (const invalidKeyIdentifier of [
  "https://attacker.example/keys/credential-key/version",
  `${vault}/keys/credential-key/version/sign`,
  `${vault}/keys/credential-key/version?redirect=https://attacker.example`,
  `${vault}/keys/credential-key%2Fversion`
]) {
  assert.throws(() => boundaries.normalizeKeyVaultKeyPath(vault, invalidKeyIdentifier));
}

assert.throws(() => boundaries.assertKeyVaultRequestUrl("https://attacker.example/keys/a/sign?api-version=7.5", vault));
assert.throws(() => boundaries.assertKeyVaultRequestUrl(`${vault}/keys/a/sign?api-version=7.5&next=evil`, vault));

assert.equal(
  boundaries.normalizeEntraAuthorityHost("https://login.microsoftonline.com/"),
  "https://login.microsoftonline.com"
);
assert.throws(() => boundaries.normalizeEntraAuthorityHost("https://login.microsoftonline.com.attacker.example"));
assert.throws(() => boundaries.normalizeEntraAuthorityHost("https://login.microsoftonline.com/common"));

const tenantId = "11111111-1111-4111-8111-111111111111";
assert.equal(boundaries.assertGuid(tenantId, "Tenant ID"), tenantId);
assert.throws(() => boundaries.assertGuid("organizations", "Tenant ID"));

const redirectUri = "https://abcdefghijklmnop.chromiumapp.org/aad";
assert.equal(
  boundaries.assertOAuthRedirect(`${redirectUri}?code=abc&state=expected`, redirectUri, "expected").searchParams.get("code"),
  "abc"
);
assert.throws(() => boundaries.assertOAuthRedirect(`${redirectUri}?code=abc&state=wrong`, redirectUri, "expected"));
assert.throws(() => boundaries.assertOAuthRedirect("https://attacker.example/aad?code=abc&state=expected", redirectUri, "expected"));

console.log("Security boundary validation passed.");
