import { build, context } from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const distDir = path.join(root, "dist");
const publicDir = path.join(root, "public");
const watchMode = process.argv.includes("--watch");

const baseOptions = {
  entryPoints: {
    background: path.join(root, "src", "background.ts"),
    content: path.join(root, "src", "content.ts"),
    page: path.join(root, "src", "page.ts"),
    popup: path.join(root, "src", "popup.ts"),
    setup: path.join(root, "src", "setup.ts"),
    "uv-dialog": path.join(root, "src", "uv-dialog.ts")
  },
  bundle: true,
  format: "iife",
  target: "chrome120",
  outdir: distDir,
  sourcemap: true,
  logLevel: "info"
};

async function copyPublic() {
  await mkdir(distDir, { recursive: true });
  await cp(publicDir, distDir, { recursive: true });
}

async function main() {
  await rm(distDir, { recursive: true, force: true });
  await copyPublic();

  if (watchMode) {
    const ctx = await context(baseOptions);
    await ctx.watch();
    console.log("Watching browser extension sources...");
    return;
  }

  await build(baseOptions);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
