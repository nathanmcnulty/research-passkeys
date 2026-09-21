import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const lockPath = path.join(repositoryRoot, "browser-extensions", "upstream-provider.lock.json");
const lock = await readJson(lockPath);
const argumentsList = process.argv.slice(2);
if (argumentsList.some((argument) => argument !== "--verify-upstream")) {
  throw new Error(`Unknown argument: ${argumentsList.find((argument) => argument !== "--verify-upstream")}`);
}

if (lock.schemaVersion !== 1) {
  throw new Error(`Unsupported lock schemaVersion: ${lock.schemaVersion}`);
}
if (lock.baselineType !== "development" || lock.buildArtifact !== null) {
  throw new Error("Schema version 1 supports only development baselines without a build artifact");
}
if (
  lock.provider?.repository !== "https://github.com/nathanmcnulty/keyvault-passkey-provider.git" ||
  lock.provider?.sourcePath !== "src/browser-extension" ||
  !/^[0-9a-f]{40}$/.test(lock.provider?.commit ?? "") ||
  !/^[0-9a-f]{40}$/.test(lock.provider?.gitTree ?? "")
) {
  throw new Error("Provider provenance fields are missing or malformed");
}
if (lock.content?.algorithm !== "sha256" || !/^[0-9a-f]{64}$/.test(lock.content?.digest ?? "")) {
  throw new Error("Unsupported or malformed content digest");
}

const vendorRoot = path.resolve(repositoryRoot, lock.vendorPath);
const relativeVendor = path.relative(repositoryRoot, vendorRoot);
if (relativeVendor.startsWith("..") || path.isAbsolute(relativeVendor)) {
  throw new Error(`vendorPath escapes the repository: ${lock.vendorPath}`);
}
if (path.basename(vendorRoot) !== `dev-${lock.provider.commit.slice(0, 7)}`) {
  throw new Error("Development vendor path does not match the provider commit");
}

const files = await listFiles(vendorRoot);
const expectedPaths = Object.keys(lock.content.files).sort();
const actualPaths = files.map(({ relativePath }) => relativePath);

if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
  throw new Error(
    `Vendored file list differs from the lock.\nExpected: ${expectedPaths.join(", ")}\nActual: ${actualPaths.join(", ")}`,
  );
}

const digestRows = [];
const gitEntries = new Map();
for (const file of files) {
  const bytes = await readFile(file.absolutePath);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const expected = lock.content.files[file.relativePath];
  if (
    sha256 !== expected.sha256 ||
    bytes.length !== expected.size ||
    !["100644", "100755"].includes(expected.gitMode)
  ) {
    throw new Error(`Vendored file differs from the lock: ${file.relativePath}`);
  }
  digestRows.push(`${file.relativePath}\0${expected.gitMode}\0${sha256}\0${bytes.length}\n`);
  gitEntries.set(file.relativePath, { mode: expected.gitMode, oid: gitBlobHash(bytes) });
}

const digest = createHash("sha256").update(digestRows.join(""), "utf8").digest("hex");
if (digest !== lock.content.digest) {
  throw new Error(`Vendored content digest differs from the lock: ${digest}`);
}
const gitTree = gitTreeHash(gitEntries);
if (gitTree !== lock.provider.gitTree) {
  throw new Error(`Vendored Git tree differs from provider.gitTree: ${gitTree}`);
}
if (argumentsList.includes("--verify-upstream")) {
  await verifyUpstreamCommit(lock.provider);
}

const packageJson = await readJson(path.join(vendorRoot, "package.json"));
const manifest = await readJson(path.join(vendorRoot, "public", "manifest.json"));
if (
  packageJson.version !== lock.version.package ||
  manifest.version !== lock.version.manifest ||
  (manifest.version_name ?? null) !== lock.version.versionName
) {
  throw new Error("Vendored package or manifest version differs from the lock");
}

const keyBytes = Buffer.from(manifest.key, "base64");
const keySha256 = createHash("sha256").update(keyBytes).digest("hex");
if (keySha256 !== lock.identity.manifestKeySha256) {
  throw new Error("Vendored manifest key differs from the lock");
}

const extensionId = extensionIdFromKey(keyBytes);
if (extensionId !== lock.identity.extensionId) {
  throw new Error(`Vendored extension ID differs from the lock: ${extensionId}`);
}

console.log(
  `Validated ${files.length} immutable provider files at ${lock.provider.commit.slice(0, 12)} (${digest}).`,
);

async function listFiles(root) {
  const result = [];
  await visit(root, "");
  return result.sort((left, right) =>
    left.relativePath < right.relativePath ? -1 : left.relativePath > right.relativePath ? 1 : 0,
  );

  async function visit(directory, relativeDirectory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relativePath = path.posix.join(relativeDirectory.split(path.sep).join(path.posix.sep), entry.name);
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolutePath, relativePath);
      } else if (entry.isFile()) {
        result.push({ absolutePath, relativePath });
      } else {
        const details = await stat(absolutePath);
        throw new Error(`Unsupported vendored entry: ${relativePath} (${details.mode})`);
      }
    }
  }
}

function extensionIdFromKey(keyBytes) {
  const digest = createHash("sha256").update(keyBytes).digest().subarray(0, 16);
  return [...digest]
    .map((byte) => `${String.fromCharCode(97 + (byte >> 4))}${String.fromCharCode(97 + (byte & 0x0f))}`)
    .join("");
}

function gitBlobHash(bytes) {
  return createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
}

function gitTreeHash(files) {
  const root = { type: "tree", children: new Map() };
  for (const [filePath, file] of files) {
    const parts = filePath.split("/");
    let directory = root;
    for (const part of parts.slice(0, -1)) {
      if (!directory.children.has(part)) {
        directory.children.set(part, { type: "tree", children: new Map() });
      }
      directory = directory.children.get(part);
    }
    directory.children.set(parts.at(-1), { type: "blob", ...file });
  }

  return hashDirectory(root);

  function hashDirectory(directory) {
    const entries = [...directory.children.entries()].sort(([leftName, left], [rightName, right]) =>
      Buffer.compare(
        Buffer.from(`${leftName}${left.type === "tree" ? "/" : ""}`),
        Buffer.from(`${rightName}${right.type === "tree" ? "/" : ""}`),
      ),
    );
    const body = Buffer.concat(
      entries.map(([name, entry]) => {
        const mode = entry.type === "tree" ? "40000" : entry.mode;
        const oid = entry.type === "tree" ? hashDirectory(entry) : entry.oid;
        return Buffer.concat([Buffer.from(`${mode} ${name}\0`, "utf8"), Buffer.from(oid, "hex")]);
      }),
    );
    return createHash("sha1")
      .update(Buffer.from(`tree ${body.length}\0`, "utf8"))
      .update(body)
      .digest("hex");
  }
}

async function readJson(filePath) {
  return JSON.parse((await readFile(filePath, "utf8")).replace(/^\uFEFF/, ""));
}

async function verifyUpstreamCommit(provider) {
  const temporaryRepository = await mkdtemp(path.join(tmpdir(), "research-passkeys-provider-"));
  try {
    runGit(["-C", temporaryRepository, "init", "--quiet"]);
    runGit([
      "-C",
      temporaryRepository,
      "fetch",
      "--quiet",
      "--depth=1",
      "--filter=blob:none",
      "--no-tags",
      provider.repository,
      provider.commit,
    ]);
    const upstreamTree = runGit([
      "-C",
      temporaryRepository,
      "rev-parse",
      `FETCH_HEAD:${provider.sourcePath}`,
    ]).trim();
    if (upstreamTree !== provider.gitTree) {
      throw new Error(`Pinned provider commit resolves to a different source tree: ${upstreamTree}`);
    }
  } finally {
    await rm(temporaryRepository, { recursive: true, force: true });
  }
}

function runGit(argumentsList) {
  const result = spawnSync("git", argumentsList, { encoding: "utf8", maxBuffer: 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`Git command failed: ${result.stderr.trim() || result.stdout.trim()}`);
  }
  return result.stdout;
}
