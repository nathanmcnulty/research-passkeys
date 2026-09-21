import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const lockPath = path.join(repositoryRoot, "browser-extensions", "upstream-provider.lock.json");
const lock = await readJson(lockPath);
const argumentsList = process.argv.slice(2);
if (argumentsList.length > 0) {
  throw new Error(`Unknown argument: ${argumentsList[0]}`);
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
verifyGitProvenance(lock.provider);

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

function verifyGitProvenance(provider) {
  const proof = provider.proof;
  if (proof?.algorithm !== "git-sha1") {
    throw new Error("Provider Git object proof is missing or unsupported");
  }

  const commitObject = decodeProofObject(proof.commitObjectBase64, "commit");
  if (gitObjectHash("commit", commitObject) !== provider.commit) {
    throw new Error("Provider commit object does not match provider.commit");
  }
  const rootMatch = /^tree ([0-9a-f]{40})$/m.exec(commitObject.toString("utf8"));
  if (!rootMatch || rootMatch[1] !== proof.rootTree) {
    throw new Error("Provider commit does not reference the proof root tree");
  }

  const rootTreeObject = decodeProofObject(proof.rootTreeObjectBase64, "root tree");
  if (gitObjectHash("tree", rootTreeObject) !== proof.rootTree) {
    throw new Error("Provider root tree object does not match its object ID");
  }
  const sourceEntry = findTreeEntry(rootTreeObject, "src");
  if (sourceEntry?.mode !== "40000" || sourceEntry.oid !== proof.sourceTree) {
    throw new Error("Provider root tree does not reference the proof source tree");
  }

  const sourceTreeObject = decodeProofObject(proof.sourceTreeObjectBase64, "source tree");
  if (gitObjectHash("tree", sourceTreeObject) !== proof.sourceTree) {
    throw new Error("Provider source tree object does not match its object ID");
  }
  const extensionEntry = findTreeEntry(sourceTreeObject, "browser-extension");
  if (extensionEntry?.mode !== "40000" || extensionEntry.oid !== provider.gitTree) {
    throw new Error("Pinned provider commit does not reference provider.gitTree at src/browser-extension");
  }
}

function decodeProofObject(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Provider ${label} proof is missing`);
  }
  return Buffer.from(value, "base64");
}

function gitObjectHash(type, bytes) {
  return createHash("sha1")
    .update(Buffer.from(`${type} ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
}

function findTreeEntry(treeObject, expectedName) {
  let offset = 0;
  while (offset < treeObject.length) {
    const space = treeObject.indexOf(0x20, offset);
    const nul = treeObject.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > treeObject.length) {
      throw new Error("Malformed provider tree proof");
    }
    const mode = treeObject.subarray(offset, space).toString("ascii");
    const name = treeObject.subarray(space + 1, nul).toString("utf8");
    const oid = treeObject.subarray(nul + 1, nul + 21).toString("hex");
    if (name === expectedName) {
      return { mode, oid };
    }
    offset = nul + 21;
  }
  return null;
}
