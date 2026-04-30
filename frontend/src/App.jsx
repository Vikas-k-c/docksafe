import { useMemo, useState } from "react";
import axios from "axios";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";
const SCAN_TIMEOUT_MS = 180000;
const EXAMPLES = ["python:3.9", "nginx:latest", "node:20-alpine", "redis:7"];

function getRiskLabel(score) {
  if (score >= 70) return "Critical";
  if (score >= 40) return "Elevated";
  return "Managed";
}

function getRiskClass(score) {
  if (score >= 70) return "riskHigh";
  if (score >= 40) return "riskMedium";
  return "riskLow";
}

function formatSeconds(ms) {
  if (!ms) return "0.00s";
  return `${(ms / 1000).toFixed(2)}s`;
}

function App() {
  const [image, setImage] = useState("python:3.9");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState([]);

  const riskClass = useMemo(
    () => (data ? getRiskClass(data.riskScore) : "riskLow"),
    [data]
  );

  const scanImage = async (selectedImage = image) => {
    const nextImage = selectedImage.trim();

    if (!nextImage) {
      setError("Enter an image name, for example python:3.9");
      return;
    }

    try {
      setImage(nextImage);
      setLoading(true);
      setError("");

      const response = await axios.post(
        `${API_URL}/scan`,
        { image: nextImage },
        { timeout: SCAN_TIMEOUT_MS }
      );

      setData(response.data);
      setRecentScans((items) => [
        response.data,
        ...items.filter((item) => item.image !== response.data.image)
      ].slice(0, 4));
    } catch (err) {
      const message =
        err.code === "ECONNABORTED"
          ? "Scan timed out after 3 minutes. Try a smaller image first, or run the same scan again after Trivy finishes updating its database."
          : err.response?.data?.details || err.response?.data?.error || err.message;
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="shell">
      <section className="scanPanel">
        <div>
          <p className="eyebrow">Container vulnerability scanner</p>
          <h1>DockSafe</h1>
        </div>

        <div className="searchRow">
          <input
            aria-label="Docker image"
            placeholder="python:3.9"
            value={image}
            onChange={(event) => setImage(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") scanImage();
            }}
          />
          <button onClick={() => scanImage()} disabled={loading}>
            {loading ? "Scanning" : "Scan"}
          </button>
        </div>

        <div className="quickScans" aria-label="Quick scan examples">
          {EXAMPLES.map((example) => (
            <button
              type="button"
              key={example}
              onClick={() => scanImage(example)}
              disabled={loading}
            >
              {example}
            </button>
          ))}
        </div>

        {error && <div className="alert">{error}</div>}
      </section>

      <section className="dashboard">
        <div className={`scorePanel ${riskClass}`}>
          <span>Risk Score</span>
          <strong>{data?.riskScore ?? "--"}</strong>
          <p>{data ? getRiskLabel(data.riskScore) : "Awaiting scan"}</p>
        </div>

        <div className="metricGrid">
          <article>
            <span>Critical</span>
            <strong>{data?.vulnerabilities?.critical ?? 0}</strong>
          </article>
          <article>
            <span>High</span>
            <strong>{data?.vulnerabilities?.high ?? 0}</strong>
          </article>
          <article>
            <span>Medium</span>
            <strong>{data?.vulnerabilities?.medium ?? 0}</strong>
          </article>
          <article>
            <span>Total</span>
            <strong>{data?.vulnerabilities?.total ?? 0}</strong>
          </article>
        </div>
      </section>

      {data && (
        <section className="results">
          <div className="resultHeader">
            <div>
              <p className="eyebrow">Latest result</p>
              <h2>{data.image}</h2>
            </div>
            <div className="statusPills">
              <span>{formatSeconds(data.scanDurationMs)}</span>
              <span>{data.cached ? "Cached" : "Fresh"}</span>
              <span>{data.metadataSource}</span>
              <span>Guided feedback</span>
            </div>
          </div>

          <div className="detailsGrid">
            <div>
              <span>Image Size</span>
              <strong>{data.size} MB</strong>
            </div>
            <div>
              <span>Layers</span>
              <strong>{data.layers}</strong>
            </div>
            <div>
              <span>Scanner Source</span>
              <strong>{data.scanner?.source || "remote,docker"}</strong>
            </div>
          </div>

          {data.metadataWarning && <div className="notice">{data.metadataWarning}</div>}

          <div className="suggestions">
            <h3>Remediation</h3>
            <ul>
              {data.suggestions.map((suggestion) => (
                <li key={suggestion}>{suggestion}</li>
              ))}
            </ul>
          </div>

          {data.topVulnerabilities?.length > 0 && (
            <div className="vulnerabilityTable">
              <h3>Top findings</h3>
              <div>
                {data.topVulnerabilities.slice(0, 6).map((item) => (
                  <article key={`${item.target}-${item.vulnerabilityId}-${item.packageName}`}>
                    <strong>{item.vulnerabilityId}</strong>
                    <span>{item.severity}</span>
                    <p>{item.packageName}</p>
                    <small>
                      {item.installedVersion} {"->"} {item.fixedVersion}
                    </small>
                  </article>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {recentScans.length > 0 && (
        <section className="recent">
          <h2>Recent scans</h2>
          <div>
            {recentScans.map((scan) => (
              <button key={scan.image} onClick={() => scanImage(scan.image)} disabled={loading}>
                <span>{scan.image}</span>
                <strong>{scan.riskScore}</strong>
              </button>
            ))}
          </div>
        </section>
      )}
    </main>
  );
}

export default App;
