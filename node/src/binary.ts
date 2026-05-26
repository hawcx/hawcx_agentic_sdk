import fs from "node:fs";
import path from "node:path";

const PLATFORM_PACKAGES: Record<string, string> = {
  "linux-x64":    "@hawcx/hawcx-haap-linux-x64",
  "linux-arm64":  "@hawcx/hawcx-haap-linux-arm64",
  "darwin-arm64": "@hawcx/hawcx-haap-darwin-arm64",
  "win32-x64":    "@hawcx/hawcx-haap-win32-x64",
  "win32-arm64":  "@hawcx/hawcx-haap-win32-arm64",
};

export function getBinaryPath(): string {
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) {
    throw new Error(
      `hawcx-manager binary not available for ${process.platform}-${process.arch}.\n` +
      `Supported platforms: ${Object.keys(PLATFORM_PACKAGES).join(", ")}`
    );
  }

  let pkgJson: string;
  try {
    pkgJson = require.resolve(`${pkg}/package.json`);
  } catch {
    throw new Error(
      `Platform package ${pkg} is not installed.\n` +
      `This should happen automatically via optionalDependencies.\n` +
      `Try: npm install`
    );
  }

  const pkgDir = path.dirname(pkgJson);
  const binaryName = process.platform === "win32" ? "hawcx-manager.exe" : "hawcx-manager";
  const binaryPath = path.join(pkgDir, binaryName);

  if (!fs.existsSync(binaryPath)) {
    throw new Error(
      `hawcx-manager binary not found at ${binaryPath}.\n` +
      `The platform package ${pkg} is installed but missing the binary file.`
    );
  }

  return binaryPath;
}
