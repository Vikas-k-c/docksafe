function Result({ data }) {
  return (
    <div style={{ marginTop: "20px" }}>
      <h2>Result</h2>

      <p><b>Image:</b> {data.image}</p>

      <h3>Vulnerabilities</h3>
      <p>Critical: {data.vulnerabilities.critical}</p>
      <p>High: {data.vulnerabilities.high}</p>
      <p>Medium: {data.vulnerabilities.medium}</p>

      <h3>Suggestions</h3>
      <ul>
        {data.suggestions.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ul>
    </div>
  );
}

export default Result;