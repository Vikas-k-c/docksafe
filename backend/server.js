const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const { analyzeTrivy, calculateRisk } = require("./analyzer");
const generateSuggestions = require("./suggestions");

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);

  lines.forEach((line) => {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith("#")) {
      return;
    }

    const separatorIndex = trimmed.indexOf("=");

    if (separatorIndex === -1) {
      return;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed
      .slice(separatorIndex + 1)
      .trim()
      .replace(/^["']|["']$/g, "");

    if (key && !process.env[key]) {
      process.env[key] = value;
    }
  });
}

loadEnvFile(path.join(__dirname, ".env"));

const app = express();
const cache = new Map();
const inFlightScans = new Map();
let scanQueue = Promise.resolve();

const PORT = Number(process.env.PORT || process.env.DOCKSAFE_PORT) || 5000;
const DEFAULT_TRIVY_PATH = "C:\\trivy\\trivy.exe";
const TRIVY_PATH = process.env.TRIVY_PATH || (fs.existsSync(DEFAULT_TRIVY_PATH) ? DEFAULT_TRIVY_PATH : "trivy");
const DOCKER_PATH = process.env.DOCKER_PATH || "docker";
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS) || 180000;
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS) || 15 * 60 * 1000;
const TRIVY_IMAGE_SOURCE = process.env.TRIVY_IMAGE_SOURCE || "remote,docker";
const TRIVY_DB_REPOSITORY = process.env.TRIVY_DB_REPOSITORY || "";
const TRIVY_SEVERITY = process.env.TRIVY_SEVERITY || "CRITICAL,HIGH,MEDIUM,LOW";
const FAST_SCAN_MODE = String(process.env.FAST_SCAN_MODE || "").toLowerCase() === "true";
const IMAGE_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,254}$/;
const IMAGE_ID_PATTERN = /^[a-f0-9]{12,64}$/i;

app.use(cors());
app.use(express.json({ limit: "32kb" }));

function normalizeImageName(value) {
  const image = String(value || "").trim();

  if (!image || image.includes("@") || image.includes(":")) {
    return image;
  }

  return `${image}:latest`;
}

function getCachedScan(image) {
  const entry = cache.get(image);

  if (!entry) {
    return null;
  }

  if (Date.now() - entry.createdAt > CACHE_TTL_MS) {
    cache.delete(image);
    return null;
  }

  return {
    ...entry.result,
    cached: true,
    cacheAgeMs: Date.now() - entry.createdAt
  };
}

function runProcess(command, args, timeoutMs = SCAN_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    let didTimeout = false;

    const timeout = setTimeout(() => {
      didTimeout = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);

      if (didTimeout) {
        return reject(new Error(`${command} timed out after ${timeoutMs}ms`));
      }

      if (code !== 0) {
        const error = new Error(stderr || `${command} exited with code ${code}`);
        error.code = code;
        error.stderr = stderr;
        return reject(error);
      }

      resolve({ stdout, stderr });
    });
  });
}

function getImageSource(image) {
  return IMAGE_ID_PATTERN.test(image) ? "docker" : TRIVY_IMAGE_SOURCE;
}

function getErrorDetails(error) {
  const message = error.stderr || error.message || "Unknown error";

  if (error.code === "ENOENT") {
    return `Could not find ${TRIVY_PATH}. Install Trivy or set TRIVY_PATH to the trivy.exe location.`;
  }

  if (message.includes("--skip-db-update") || message.includes("database") || message.includes("DB")) {
    return "Trivy database is not ready. Run `trivy image --download-db-only`, or wait for the automatic retry.";
  }

  return message.split(/\r?\n/).filter(Boolean).slice(0, 4).join(" ");
}

function getTrivyMetadata(report) {
  const metadata = report.Metadata || {};
  const size = metadata.ImageSize || metadata.Size || metadata.ImageConfig?.Size || 0;
  const layers =
    metadata.ImageConfig?.RootFS?.Layers?.length ||
    metadata.ImageConfig?.rootfs?.diff_ids?.length ||
    metadata.RootFS?.Layers?.length ||
    0;

  return {
    size: Number((Number(size || 0) / (1024 * 1024)).toFixed(2)),
    layers,
    source: size || layers ? "trivy" : null
  };
}

function extractTopVulnerabilities(report, limit = 12) {
  const severityRank = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    UNKNOWN: 0
  };

  return (report.Results || [])
    .flatMap((result) =>
      (result.Vulnerabilities || []).map((vulnerability) => ({
        target: result.Target,
        packageName: vulnerability.PkgName,
        installedVersion: vulnerability.InstalledVersion,
        fixedVersion: vulnerability.FixedVersion || "Not published",
        vulnerabilityId: vulnerability.VulnerabilityID,
        severity: vulnerability.Severity || "UNKNOWN",
        title: vulnerability.Title || vulnerability.Description || ""
      }))
    )
    .sort((a, b) => {
      const severityDifference = severityRank[b.severity] - severityRank[a.severity];

      if (severityDifference !== 0) {
        return severityDifference;
      }

      return a.packageName.localeCompare(b.packageName);
    })
    .slice(0, limit);
}

function getDeterministicSeed(value) {
  return String(value).split("").reduce((total, char) => total + char.charCodeAt(0), 0);
}

function buildFastScanResult(image) {
  const startedAt = Date.now();
  const seed = getDeterministicSeed(image);
  const lowerImage = image.toLowerCase();
  const isSlimImage = lowerImage.includes("alpine") || lowerImage.includes("slim");
  const isLatestTag = lowerImage.endsWith(":latest");
  const isOldRuntime =
    lowerImage.includes("python:3.") ||
    lowerImage.includes("node:14") ||
    lowerImage.includes("node:16") ||
    lowerImage.includes("ubuntu:18") ||
    lowerImage.includes("ubuntu:20");

  const vulnerabilities = {
    critical: isOldRuntime ? 2 : seed % 2,
    high: isLatestTag ? 4 + (seed % 3) : 1 + (seed % 3),
    medium: 3 + (seed % 8),
    low: 2 + (seed % 6),
    unknown: seed % 2
  };

  vulnerabilities.total =
    vulnerabilities.critical +
    vulnerabilities.high +
    vulnerabilities.medium +
    vulnerabilities.low +
    vulnerabilities.unknown;

  const size = isSlimImage ? 52 + (seed % 90) : 180 + (seed % 420);
  const layers = isSlimImage ? 5 + (seed % 4) : 8 + (seed % 8);
  const topVulnerabilities = [
    {
      target: image,
      packageName: isOldRuntime ? "openssl" : "libcrypto3",
      installedVersion: isOldRuntime ? "1.1.1" : "3.0.12",
      fixedVersion: isOldRuntime ? "1.1.1w" : "3.0.13",
      vulnerabilityId: `CVE-2026-${1000 + (seed % 8000)}`,
      severity: vulnerabilities.critical > 0 ? "CRITICAL" : "HIGH",
      title: "Package contains a known vulnerability in the selected base image"
    },
    {
      target: image,
      packageName: "curl",
      installedVersion: "8.4.0",
      fixedVersion: "8.5.0",
      vulnerabilityId: `CVE-2025-${2000 + (seed % 7000)}`,
      severity: "HIGH",
      title: "Update package manager dependencies during image rebuild"
    },
    {
      target: image,
      packageName: "base-files",
      installedVersion: "12",
      fixedVersion: "Not published",
      vulnerabilityId: `CVE-2024-${3000 + (seed % 6000)}`,
      severity: "MEDIUM",
      title: "No fixed package version is currently published"
    }
  ];

  const scanSummary = {
    ...vulnerabilities,
    size,
    layers,
    topVulnerabilities
  };

  return {
    image,
    vulnerabilities,
    size: size.toFixed(2),
    layers,
    metadataSource: "fast-demo",
    riskScore: calculateRisk(scanSummary),
    suggestions: generateSuggestions(scanSummary),
    suggestionSource: "rules",
    topVulnerabilities,
    metadataWarning: "Fast demo mode is enabled. Results are simulated for quick classroom demos; disable FAST_SCAN_MODE for real Trivy scans.",
    cached: false,
    scanner: {
      source: "fast-demo",
      severity: TRIVY_SEVERITY
    },
    scanDurationMs: Date.now() - startedAt
  };
}

async function getLocalDockerMetadata(image) {
  const { stdout } = await runProcess(DOCKER_PATH, ["image", "inspect", image], 5000);
  const metadata = JSON.parse(stdout)[0];

  if (!metadata) {
    throw new Error("Docker inspect returned no image metadata");
  }

  return {
    size: Number((metadata.Size / (1024 * 1024)).toFixed(2)),
    layers: metadata.RootFS?.Layers?.length || 0,
    source: "docker"
  };
}

async function runTrivyScan(image, skipDbUpdate) {
  const args = [
    "image",
    "--quiet",
    "--image-src",
    getImageSource(image),
    "--scanners",
    "vuln",
    "--severity",
    TRIVY_SEVERITY,
    "--format",
    "json",
    image
  ];

  if (skipDbUpdate) {
    args.splice(args.length - 3, 0, "--skip-db-update");
  }

  if (TRIVY_DB_REPOSITORY) {
    args.splice(args.length - 1, 0, "--db-repository", TRIVY_DB_REPOSITORY);
  }

  const { stdout } = await runProcess(TRIVY_PATH, args);

  return JSON.parse(stdout);
}

async function scanImage(image) {
  try {
    return await runTrivyScan(image, true);
  } catch (error) {
    const details = getErrorDetails(error);

    if (details.includes("database")) {
      console.warn("Retrying scan after allowing Trivy DB update:", image);
      return runTrivyScan(image, false);
    }

    throw error;
  }
}

async function buildScanResult(image) {
  if (FAST_SCAN_MODE) {
    return buildFastScanResult(image);
  }

  const startedAt = Date.now();
  const report = await scanImage(image);
  const vulnerabilities = analyzeTrivy(report);
  const topVulnerabilities = extractTopVulnerabilities(report);
  let metadata = getTrivyMetadata(report);
  let metadataWarning = null;

  if (!metadata.source) {
    try {
      metadata = await getLocalDockerMetadata(image);
    } catch (error) {
      metadataWarning = "Image size and layer data are unavailable without a local Docker copy.";
      console.warn("Metadata unavailable:", error.stderr || error.message);
    }
  }

  const scanSummary = {
    ...vulnerabilities,
    size: metadata.size,
    layers: metadata.layers,
    topVulnerabilities
  };
  const suggestions = generateSuggestions(scanSummary);

  return {
    image,
    vulnerabilities,
    size: metadata.size.toFixed(2),
    layers: metadata.layers,
    metadataSource: metadata.source || "unavailable",
    riskScore: calculateRisk(scanSummary),
    suggestions,
    suggestionSource: "rules",
    topVulnerabilities,
    metadataWarning,
    cached: false,
    scanner: {
      source: getImageSource(image),
      severity: TRIVY_SEVERITY
    },
    scanDurationMs: Date.now() - startedAt
  };
}

function enqueueScan(task) {
  const queuedTask = scanQueue.then(task, task);
  scanQueue = queuedTask.catch(() => {});
  return queuedTask;
}

app.get("/", (req, res) => {
  res.json({
    name: "DockSafe Backend",
    status: "running",
    fastScanMode: FAST_SCAN_MODE,
    aiSuggestions: false,
    cacheEntries: cache.size,
    inFlightScans: inFlightScans.size
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/scan", async (req, res) => {
  const image = normalizeImageName(req.body?.image);

  if (!image) {
    return res.status(400).json({ error: "Image required" });
  }

  if (!IMAGE_NAME_PATTERN.test(image)) {
    return res.status(400).json({ error: "Invalid Docker image name" });
  }

  const cached = getCachedScan(image);

  if (cached) {
    console.log("Cache hit:", image);
    return res.json(cached);
  }

  if (inFlightScans.has(image)) {
    console.log("Joining in-flight scan:", image);
    try {
      const result = await inFlightScans.get(image);
      return res.json({ ...result, sharedScan: true });
    } catch (error) {
      return res.status(500).json({ error: "Scan failed", details: error.message });
    }
  }

  console.log("Scanning:", image);

  const scanPromise = enqueueScan(() => buildScanResult(image))
    .then((result) => {
      cache.set(image, { createdAt: Date.now(), result });
      return result;
    })
    .finally(() => {
      inFlightScans.delete(image);
    });

  inFlightScans.set(image, scanPromise);

  try {
    res.json(await scanPromise);
  } catch (error) {
    const details = getErrorDetails(error);
    console.error("Scan failed:", details);
    res.status(500).json({
      error: "Scan failed",
      details
    });
  }
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
}).on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use. Stop the old backend process or set DOCKSAFE_PORT to another value.`);
    process.exit(1);
  }

  console.error("Backend failed to start:", error.message);
  process.exit(1);
});
