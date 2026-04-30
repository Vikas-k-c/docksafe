function analyzeTrivy(report) {
  let critical = 0, high = 0, medium = 0, low = 0, unknown = 0;

  report.Results?.forEach(r => {
    r.Vulnerabilities?.forEach(v => {
      if (v.Severity === "CRITICAL") critical++;
      else if (v.Severity === "HIGH") high++;
      else if (v.Severity === "MEDIUM") medium++;
      else if (v.Severity === "LOW") low++;
      else unknown++;
    });
  });

  return {
    critical,
    high,
    medium,
    low,
    unknown,
    total: critical + high + medium + low + unknown
  };
}

function calculateRisk({ critical, high, medium, low, size, layers }) {
  let score = 0;

  score += critical * 5;
  score += high * 3;
  score += medium;
  score += low * 0.25;

  if (size > 500) score += 10;
  if (layers > 10) score += 5;

  return Math.round(Math.min(score, 100));
}

module.exports = { analyzeTrivy, calculateRisk };
