function formatPackageFix(vulnerability) {
  if (!vulnerability || vulnerability.fixedVersion === "Not published") {
    return null;
  }

  return `Upgrade ${vulnerability.packageName} from ${vulnerability.installedVersion} to ${vulnerability.fixedVersion} to address ${vulnerability.vulnerabilityId}`;
}

function generateSuggestions(data) {
  const suggestions = [];
  const topVulnerabilities = data.topVulnerabilities || [];
  const criticalFixes = topVulnerabilities
    .filter((item) => item.severity === "CRITICAL")
    .map(formatPackageFix)
    .filter(Boolean)
    .slice(0, 2);
  const highFix = topVulnerabilities
    .filter((item) => item.severity === "HIGH")
    .map(formatPackageFix)
    .find(Boolean);

  suggestions.push(...criticalFixes);

  if (data.critical > 0) {
    suggestions.push("Prioritize rebuilding the image after applying security updates for CRITICAL packages");
  }

  if (highFix) {
    suggestions.push(highFix);
  } else if (data.high > 5) {
    suggestions.push("Run package manager security updates in the Dockerfile and rebuild the image");
  }

  if (data.size > 500) {
    suggestions.push("Use a smaller base image such as slim or alpine when compatible with your app");
  }

  if (data.layers > 10) {
    suggestions.push("Reduce Docker layers by combining related RUN commands and using multi-stage builds");
  }

  if (topVulnerabilities.some((item) => item.fixedVersion === "Not published")) {
    suggestions.push("Monitor unfixed CVEs and consider switching base image versions when no package fix is published");
  }

  if (suggestions.length === 0) {
    suggestions.push("No urgent changes found for the current scan policy");
  }

  return [...new Set(suggestions)].slice(0, 6);
}

module.exports = generateSuggestions;
