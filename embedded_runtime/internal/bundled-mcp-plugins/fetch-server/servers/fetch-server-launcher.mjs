import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolveBundledPythonExecutable } from "../../../runtime/python/managed-python.mjs";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sitePackages = path.resolve(pluginRoot, "vendor", "site-packages");
const vendoredCertifiPath = path.resolve(sitePackages, "certifi", "cacert.pem");

function resolvePythonLauncher() {
  const bundledPython = resolveBundledPythonExecutable();
  const configured = process.env.QYPHA_PYTHON_BIN?.trim();
  const candidates = [
    ...(bundledPython && fs.existsSync(bundledPython)
      ? [{ command: bundledPython, prefixArgs: [] }]
      : []),
    ...(configured ? [{ command: configured, prefixArgs: [] }] : []),
    ...(process.platform === "win32"
      ? [
          { command: "C:\\Windows\\py.exe", prefixArgs: ["-3"] },
          { command: "py", prefixArgs: ["-3"] },
          { command: "python", prefixArgs: [] },
          { command: "python3", prefixArgs: [] },
        ]
      : [
          { command: "/opt/homebrew/bin/python3", prefixArgs: [] },
          { command: "/usr/local/bin/python3", prefixArgs: [] },
          { command: "/usr/bin/python3", prefixArgs: [] },
          { command: "python3", prefixArgs: [] },
          { command: "python", prefixArgs: [] },
        ]),
  ];
  for (const candidate of candidates) {
    const probe = spawnSync(
      candidate.command,
      [...candidate.prefixArgs, "-c", "import sys; print(sys.executable)"],
      {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    if (probe.status === 0 && probe.stdout.trim()) {
      return candidate;
    }
  }
  throw new Error(
    "Unable to locate a Python runtime. Run `npm run bootstrap:bundled-python` in embedded_runtime or set QYPHA_PYTHON_BIN.",
  );
}

function joinPythonPath(existingPath, extraPath) {
  if (!existingPath?.trim()) {
    return extraPath;
  }
  return `${extraPath}${path.delimiter}${existingPath}`;
}

function probePythonDefaultCaBundle(python) {
  const probe = spawnSync(
    python.command,
    [
      ...python.prefixArgs,
      "-c",
      [
        "import os, ssl",
        "paths = ssl.get_default_verify_paths()",
        "cafile = paths.cafile or ''",
        "print(cafile if cafile and os.path.exists(cafile) else '')",
      ].join("; "),
    ],
    {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  const resolved = probe.status === 0 ? probe.stdout.trim() : "";
  return resolved && fs.existsSync(resolved) ? resolved : undefined;
}

function resolveFetchCaBundle(python) {
  const override = process.env.QYPHA_FETCH_CA_FILE?.trim();
  if (override && fs.existsSync(override)) {
    return override;
  }
  const pythonDefault = probePythonDefaultCaBundle(python);
  if (pythonDefault) {
    return pythonDefault;
  }
  const candidates =
    process.platform === "win32"
      ? [vendoredCertifiPath]
      : [
          "/etc/ssl/certs/ca-certificates.crt",
          "/etc/pki/tls/certs/ca-bundle.crt",
          "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
          "/etc/ssl/cert.pem",
          "/private/etc/ssl/cert.pem",
          "/opt/homebrew/etc/openssl@3/cert.pem",
          "/usr/local/etc/openssl@3/cert.pem",
          vendoredCertifiPath,
        ];
  return candidates.find((candidate) => candidate && fs.existsSync(candidate));
}

const python = resolvePythonLauncher();
const caBundle = resolveFetchCaBundle(python);
const child = spawn(
  python.command,
  [...python.prefixArgs, "-m", "mcp_server_fetch", ...process.argv.slice(2)],
  {
    cwd: pluginRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      PYTHONPATH: joinPythonPath(process.env.PYTHONPATH, sitePackages),
      ...(caBundle
        ? {
            SSL_CERT_FILE: caBundle,
            REQUESTS_CA_BUNDLE: caBundle,
          }
        : {}),
    },
  },
);

child.on("error", (error) => {
  console.error(String(error));
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
