import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const researchRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--provider-repo") {
  throw new Error("Usage: node check-current-provider-tree.mjs --provider-repo <provider-checkout>");
}
const providerRoot = path.resolve(args[1]);
const lock = JSON.parse(await readFile(path.join(researchRoot,
  "browser-extensions/upstream-provider.lock.json"), "utf8"));
const git = (...gitArgs) => execFileSync("git", ["-C", providerRoot, ...gitArgs], {
  encoding: "utf8", maxBuffer: 1024 * 1024
}).trim();
const origin = git("remote", "get-url", "origin");
if (origin !== lock.provider.repository) {
  throw new Error(`Provider checkout origin differs from the locked repository: ${origin}`);
}
const currentCommit = git("rev-parse", "HEAD");
const currentTree = git("rev-parse", `HEAD:${lock.provider.sourcePath}`);
if (currentTree !== lock.provider.gitTree) {
  throw new Error(`Provider extension drift: current ${currentCommit} tree ${currentTree} differs from locked ${lock.provider.commit} tree ${lock.provider.gitTree}. Refresh and review the research baseline.`);
}
console.log(`Provider extension tree matches the research lock (${currentTree}); provider HEAD ${currentCommit}.`);
