import React, { useState } from "react";

const API_BASE =
  import.meta.env.VITE_API_BASE || "http://localhost:8000";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function scan(e) {
    e.preventDefault();

    if (!url.trim()) return;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Scan failed.");
      }

      setResult(data);
    } catch (err) {
      setError(
        err.message || "Unable to connect to PhishX backend."
      );
    } finally {
      setLoading(false);
    }
  }

  const verdictClass =
    result?.verdict?.toLowerCase() || "";

  return (
    <main>

      {/* ================= NAVBAR ================= */}

      <nav className="nav">
        <div className="brand">
          Phish<span>X</span>
        </div>

        <div className="nav-pill">
          Hybrid URL Intelligence
        </div>
      </nav>


      {/* ================= RESEARCH STRIP ================= */}

      <div className="research-strip">

        <div className="research-strip-label">
          RESEARCH
        </div>

        <div className="research-strip-title">
          A Hybrid Machine Learning and Domain Reputation
          Framework for Phishing URL Detection
        </div>

        <div className="research-strip-badge">
          PUBLISHED RESEARCH
        </div>

      </div>


      {/* ================= HERO ================= */}

      <section className="hero">

        <div className="eyebrow">
          AI-POWERED WEB SECURITY
        </div>


        {/* HERO CONTENT */}

        <div className="hero-main">

          {/* LEFT SIDE */}

          <div className="hero-copy">

            <h1>
              Know before
              <br />
              <span>you click.</span>
            </h1>

            <p className="subtitle">
              PhishX combines machine learning with DNS
              and SSL trust signals to assess suspicious
              links in real time.
            </p>

          </div>


          {/* RIGHT SIDE — RESEARCH */}

          <aside className="research-card">

            <div className="research-card-header">

              <div className="eyebrow">
                RESEARCH PUBLICATION
              </div>

              <span className="published-badge">
                PUBLISHED · AJIR · 2026
              </span>

            </div>


            <h2>
              A Hybrid Machine Learning and Domain
              Reputation Framework for Phishing URL
              Detection
            </h2>

<p>
  Published in the AJIR Journal in 2026, this
  research presents the hybrid framework behind
  PhishX, combining machine learning with DNS
  and SSL trust assessment.
</p>
            


           <a
  className="publication-button"
  href="/PhishX-Research-Paper.pdf"
  target="_blank"
  rel="noopener noreferrer"
>
  <span>View Publication</span>
  <span>→</span>
</a>

          </aside>

        </div>


        {/* ================= URL SCANNER ================= */}

        <form
          className="scanner"
          onSubmit={scan}
        >

          <input
            value={url}
            onChange={(e) =>
              setUrl(e.target.value)
            }
            placeholder="Paste a URL to analyze..."
            type="text"
            required
          />

          <button
            type="submit"
            disabled={loading}
          >
            {loading
              ? "Analyzing..."
              : "Analyze URL"}
          </button>

        </form>


        {/* ================= WEIGHTS ================= */}

        <div className="weight-row">

          <span>
            <b>65%</b> ML Analysis
          </span>

          <span>
            <b>35%</b> DNS + SSL
          </span>

          <span>
            Free & privacy-focused architecture
          </span>

        </div>


        {/* ================= ERROR ================= */}

        {error && (
          <div className="error">
            {error}
          </div>
        )}


        {/* ================= SCAN RESULT ================= */}

        {result && (

          <section
            className={`result ${verdictClass}`}
          >

            {/* RESULT HEADER */}

            <div className="result-top">

              <div>

                <div className="result-label">
                  VERDICT
                </div>

                <h2>
                  {result.verdict}
                </h2>

                <p className="scanned-url">
                  {result.url}
                </p>

              </div>


              <div className="risk">

                <strong>
                  {result.risk_score}%
                </strong>

                <span>
                  risk score
                </span>

              </div>

            </div>


            {/* RESULT BARS */}

            <div className="bars">


              {/* MACHINE LEARNING */}

              <div className="component">

                <div className="bar-label">

                  <span>
                    Machine Learning
                  </span>

                  <b>
                    {result.ml?.contribution ?? 0}%
                  </b>

                </div>

                <div className="bar">

                  <i
                    style={{
                      width: `${Math.min(
                        result.ml?.contribution ?? 0,
                        100
                      )}%`,
                    }}
                  />

                </div>

              </div>


              {/* DNS / SSL */}

              <div className="component">

                <div className="bar-label">

                  <span>
                    DNS / SSL Risk
                  </span>

                  <b>
                    {result.dns_ssl?.contribution ?? 0}%
                  </b>

                </div>

                <div className="bar">

                  <i
                    style={{
                      width: `${Math.min(
                        result.dns_ssl?.contribution ?? 0,
                        100
                      )}%`,
                    }}
                  />

                </div>

              </div>

            </div>


            {/* ================= MODEL DETAILS ================= */}

            <div className="details-grid">


              {/* ML WEIGHT */}

              <div className="detail-card">

                <span>
                  ML WEIGHT
                </span>

                <strong>
                  {result.ml?.weight || "65%"}
                </strong>

              </div>


              {/* ML PROBABILITY */}

              <div className="detail-card">

                <span>
                  ML PROBABILITY
                </span>

                <strong>
                  {result.ml?.phishing_probability ?? 0}%
                </strong>

              </div>


              {/* CHARACTER MODEL */}

              <div className="detail-card">

                <span>
                  CHARACTER MODEL
                </span>

                <strong>
                  {result.ml?.character_model ?? 0}%
                </strong>

              </div>


              {/* XGBOOST */}

              <div className="detail-card">

                <span>
                  XGBOOST MODEL
                </span>

                <strong>
                  {result.ml?.xgboost_model ?? 0}%
                </strong>

              </div>


              {/* DNS / SSL TRUST */}

              <div className="detail-card">

                <span>
                  DNS / SSL TRUST
                </span>

                <strong>
                  {result.dns_ssl?.trust_score ?? 0}%
                </strong>

              </div>


              {/* DNS / SSL RISK */}

              <div className="detail-card">

                <span>
                  DNS / SSL RISK
                </span>

                <strong>
                  {result.dns_ssl?.risk ?? 0}%
                </strong>

              </div>

            </div>

          </section>

        )}

      </section>


      {/* ================= FEATURES ================= */}

      <section className="features">


        <article>

          <b>
            01
          </b>

          <h3>
            URL Intelligence
          </h3>

          <p>
            Lexical and structural URL signals
            are evaluated using machine learning
            models.
          </p>

        </article>


        <article>

          <b>
            02
          </b>

          <h3>
            DNS + SSL Trust
          </h3>

          <p>
            Domain resolution and TLS certificate
            signals provide additional trust context.
          </p>

        </article>


        <article>

          <b>
            03
          </b>

          <h3>
            Hybrid Decision
          </h3>

          <p>
            Machine learning and domain trust
            signals are combined into a final
            risk assessment.
          </p>

        </article>


      </section>


      {/* ================= COMING SOON ================= */}

      <section className="coming">

        <div>

          <div className="eyebrow">
            COMING SOON
          </div>

          <h2>
            Phishing detection from screenshots
          </h2>

          <p>
            Visual and webpage-level analysis will
            extend PhishX beyond URL-only detection.
          </p>

        </div>


        <div className="soon-badge">
          IMAGE ANALYSIS
        </div>

      </section>


      {/* ================= FOOTER ================= */}

      <footer>
        PhishX · Hybrid Phishing Detection
      </footer>

    </main>
  );
}