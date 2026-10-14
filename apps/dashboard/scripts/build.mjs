#!/usr/bin/env node
/**
 * Dashboard build: typecheck + emit ES modules + copy static assets.
 *
 * There is no bundler on purpose (see package.json "comment"). This script finds a TypeScript
 * compiler in whatever way the environment allows — a local node_modules install, a global one, or
 * npx — and fails loudly with the retry command rather than silently shipping stale JavaScript.
 */
import { existsSync, mkdirSync, readdirSync, copyFileSync, rmSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist");

function findTsc() {
  const local = join(root, "node_modules", ".bin", "tsc");
  if (existsSync(local)) return [local, []];
  const globalProbe = spawnSync("tsc", ["--version"], { encoding: "utf8" });
  if (globalProbe.status === 0) return ["tsc", []];
  const npxProbe = spawnSync("npx", ["--no-install", "tsc", "--version"], { encoding: "utf8" });
  if (npxProbe.status === 0) return ["npx", ["--no-install", "tsc"]];
  return null;
}

function copyDir(from, to) {
  mkdirSync(to, { recursive: true });
  for (const entry of readdirSync(from)) {
    const src = join(from, entry);
    const dest = join(to, entry);
    if (statSync(src).isDirectory()) copyDir(src, dest);
    else copyFileSync(src, dest);
  }
}

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

const found = findTsc();
if (!found) {
  console.error(
    "BLOCKED: no TypeScript compiler found.\n" +
      "  retry: npm ci   (inside apps/dashboard)\n" +
      "  or install one globally: npm i -g typescript"
  );
  process.exit(1);
}
const [cmd, prefix] = found;
console.log(`==> typecheck + emit with ${cmd}`);
const build = spawnSync(cmd, [...prefix, "--project", "tsconfig.json"], {
  cwd: root,
  stdio: "inherit",
});
if (build.status !== 0) {
  console.error("TypeScript build failed.");
  process.exit(build.status ?? 1);
}

console.log("==> copy static assets");
copyDir(join(root, "public"), dist);
console.log(`built -> ${dist}`);
