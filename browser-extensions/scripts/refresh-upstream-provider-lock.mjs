import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const researchRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const sourcePath = "src/browser-extension";
const repository = "https://github.com/nathanmcnulty/keyvault-passkey-provider.git";
const lockPath = path.join(researchRoot, "browser-extensions", "upstream-provider.lock.json");
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== "--provider-repo" || args[2] !== "--commit") {
  throw new Error("Usage: node refresh-upstream-provider-lock.mjs --provider-repo <checkout> --commit <full-40-character-SHA>");
}

const providerRoot = path.resolve(args[1]);
const commit = args[3];
if (!/^[0-9a-f]{40}$/.test(commit)) {
  throw new Error("Pin a full provider commit SHA");
}
const actualRemote = git("remote", "get-url", "origin").toString("utf8").trim();
if (actualRemote !== repository) {
  throw new Error(`Unexpected provider origin: ${actualRemote}`);
}
git("merge-base", "--is-ancestor", commit, "origin/main");
const tree = git("rev-parse", `${commit}:${sourcePath}`).toString("ascii").trim();
const rootTree = git("rev-parse", `${commit}^{tree}`).toString("ascii").trim();
const sourceTree = git("rev-parse", `${commit}:src`).toString("ascii").trim();
const vendorPath = `browser-extensions/vendor/key-vault-passkey-provider/dev-${commit.slice(0, 7)}`;
const vendorRoot = path.join(researchRoot, vendorPath);

// Existing snapshots are immutable. Never reuse or replace a commit-qualified path.
await mkdir(vendorRoot, { recursive: true });
const files = {};
const rows = [];
const entries = git("ls-tree", "-rz", commit, "--", sourcePath).toString("utf8").split("\0").filter(Boolean);
for (const entry of entries) {
  const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/.exec(entry);
  if (!match || !match[3].startsWith(`${sourcePath}/`)) {
    throw new Error(`Unsupported provider tree entry: ${entry}`);
  }
  const relative = match[3].slice(sourcePath.length + 1);
  if (!relative || relative.split("/").some((part) => part === ".." || part === "." || !part)) {
    throw new Error(`Unsafe provider path: ${relative}`);
  }
  const bytes = git("cat-file", "blob", match[2]);
  const sha256 = hash(bytes);
  const target = path.join(vendorRoot, ...relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true });
  try {
    await writeFile(target, bytes, { flag: "wx" });
  } catch (error) {
    if (error?.code !== "EEXIST" || !(await readFile(target)).equals(bytes)) {
      throw error;
    }
  }
  files[relative] = { gitMode: match[1], sha256, size: bytes.length };
  rows.push(`${relative}\0${match[1]}\0${sha256}\0${bytes.length}\n`);
}
if (entries.length === 0 || !files["package.json"] || !files["public/manifest.json"]) {
  throw new Error(`Unexpected provider extension file set: ${entries.length}`);
}
const packageJson = JSON.parse((await readFile(path.join(vendorRoot, "package.json"), "utf8")).replace(/^\uFEFF/, ""));
const manifest = JSON.parse((await readFile(path.join(vendorRoot, "public", "manifest.json"), "utf8")).replace(/^\uFEFF/, ""));
const keyBytes = Buffer.from(manifest.key, "base64");
const extensionId = [...createHash("sha256").update(keyBytes).digest().subarray(0, 16)]
  .map((byte) => `${String.fromCharCode(97 + (byte >> 4))}${String.fromCharCode(97 + (byte & 15))}`)
  .join("");

const lock = {
  schemaVersion: 1,
  baselineType: "development",
  provider: {
    repository,
    commit,
    sourcePath,
    gitTree: tree,
    proof: {
      algorithm: "git-sha1",
      commitObjectBase64: git("cat-file", "commit", commit).toString("base64"),
      rootTree,
      rootTreeObjectBase64: git("cat-file", "tree", rootTree).toString("base64"),
      sourceTree,
      sourceTreeObjectBase64: git("cat-file", "tree", sourceTree).toString("base64"),
    },
  },
  vendorPath,
  version: {
    package: packageJson.version,
    manifest: manifest.version,
    versionName: manifest.version_name ?? null,
  },
  identity: { manifestKeySha256: hash(keyBytes), extensionId },
  buildArtifact: null,
  content: { algorithm: "sha256", digest: hash(Buffer.from(rows.join(""))), files },
  validation: { command: "node browser-extensions/scripts/validate-upstream-provider-lock.mjs" },
};
await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
execFileSync(process.execPath, [path.join(researchRoot, lock.validation.command.split(" ")[1])], {
  cwd: researchRoot,
  stdio: "inherit",
});
console.log(`Refreshed research baseline from provider ${commit}. Earlier snapshots remain intact.`);

function git(...argumentsList) {
  return execFileSync("git", ["-C", providerRoot, ...argumentsList], { maxBuffer: 16 * 1024 * 1024 });
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
