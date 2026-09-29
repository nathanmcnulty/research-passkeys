import fs from "node:fs/promises";
import path from "node:path";

export async function stageTargetScopedExtension(sourceDir, targetUrl, stagingRoot) {
  const permission = toTargetHostPermission(targetUrl);
  await fs.mkdir(stagingRoot, { recursive: true });
  const extensionDir = await fs.mkdtemp(path.join(stagingRoot, "extension-"));
  await fs.cp(sourceDir, extensionDir, { recursive: true, force: true });

  const manifestPath = path.join(extensionDir, "manifest.json");
  const manifest = JSON.parse((await fs.readFile(manifestPath, "utf8")).replace(/^\uFEFF/, ""));
  manifest.host_permissions = Array.from(new Set([
    ...(Array.isArray(manifest.host_permissions) ? manifest.host_permissions : []),
    permission
  ])).sort();
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  return { extensionDir, permission };
}

export function toTargetHostPermission(targetUrl) {
  const target = new URL(targetUrl);
  const isLoopback = target.hostname === "localhost"
    || target.hostname === "127.0.0.1"
    || target.hostname === "[::1]";
  if (target.protocol !== "https:" && !(target.protocol === "http:" && isLoopback)) {
    throw new Error("Extension test targets must use HTTPS except for loopback development origins.");
  }

  if (target.username || target.password) {
    throw new Error("Extension test targets must not contain user information.");
  }

  return `${target.protocol}//${target.hostname}/*`;
}
