# PhishX

### A Hybrid Machine Learning and Domain Reputation Framework for Phishing URL Detection

PhishX is a real-time phishing URL detection system that combines machine learning with DNS and SSL trust signals to assess the risk of suspicious URLs.

The system uses a hybrid decision framework in which **65% of the final risk assessment comes from machine learning analysis and 35% from DNS/SSL trust analysis**.

## Live Demo

🌐 **[PhishX Live](https://phishx-frontend.onrender.com/)**

## Research Publication

**A Hybrid Machine Learning and Domain Reputation Framework for Phishing URL Detection**

The PhishX system is based on the methodology presented in the research publication.

## Features

- Real-time URL phishing analysis
- Character-level machine learning model
- XGBoost URL feature model
- DNS resolution analysis
- SSL/TLS certificate analysis
- Hybrid risk scoring
- SAFE / SUSPICIOUS / PHISHING classification
- No paid threat-intelligence APIs
- Privacy-focused URL analysis
- Free-tier deployment architecture

## How It Works

```text
                    URL
                     │
                     ▼
              URL Feature Extraction
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   Character Model          XGBoost Model
          │                     │
          └──────────┬──────────┘
                     ▼
              ML Risk Score
                  65%
                     │
                     │
                     ▼
              DNS + SSL Analysis
                  35%
                     │
                     ▼
             Hybrid Risk Score
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        SAFE    SUSPICIOUS   PHISHING
````

## Detection Methodology

### 1. Machine Learning Analysis

PhishX analyzes lexical and structural properties of URLs.

The URL-based feature set includes signals such as:

* URL length
* Hostname length
* Path depth
* Special characters
* Subdomains
* Suspicious keywords
* IP address usage
* HTTPS usage
* Port information
* URL structure and entropy

The ML layer combines two models:

* **Character-level TF-IDF + Logistic Regression**
* **XGBoost URL feature model**

The production ML score uses:

```text
80% Character Model
20% XGBoost Model
```

The resulting ML probability contributes **65%** to the final hybrid risk score.

### 2. DNS + SSL Trust Analysis

PhishX performs additional domain-level analysis using freely available network and certificate information.

The system evaluates:

* DNS resolution
* Resolved IP information
* HTTPS/TLS availability
* SSL certificate validity
* Certificate issuer
* Certificate expiry information

DNS/SSL analysis contributes **35%** to the final risk score.

### 3. Hybrid Decision

The final risk score is calculated using:

```text
Final Risk =
    65% × ML Risk
  + 35% × DNS/SSL Risk
```

Classification thresholds:

```text
Risk < 40%       → SAFE
40% – <70%       → SUSPICIOUS
Risk ≥ 70%       → PHISHING
```

## Model Performance

The current URL-based ML ensemble was evaluated on a held-out test set from the EdgePhish-5G URL dataset.

| Metric    | Result |
| --------- | -----: |
| Accuracy  | 97.87% |
| Precision | 97.86% |
| Recall    | 97.87% |
| F1 Score  | 97.87% |
| ROC-AUC   | 99.78% |

The ensemble used:

```text
Character Model → 80%
XGBoost Model   → 20%
```

These figures represent **offline test-set performance**, not guaranteed real-world accuracy.

## Dataset

The current URL-based model was trained using the **EdgePhish-5G** balanced URL dataset.

Dataset composition:

```text
Total URLs:       340,000
Phishing URLs:    170,000
Legitimate URLs:  170,000
```

The dataset contains URLs collected from multiple sources including phishing feeds and legitimate web sources.

## Technology Stack

### Frontend

* React
* Vite
* JavaScript
* CSS

### Backend

* Python
* FastAPI
* Uvicorn

### Machine Learning

* XGBoost
* Scikit-learn
* TF-IDF
* Logistic Regression
* Joblib

### Security / Network Analysis

* DNS resolution
* SSL/TLS certificate inspection
* Python networking libraries

### Deployment

* GitHub
* Render
* Render Static Site
* Render Web Service

## Project Structure

```text
PhishX/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   └── services/
│   │       ├── url_features.py
│   │       ├── dns_ssl.py
│   │       └── hybrid.py
│   │
│   ├── model/
│   │   ├── phishx_char_model.joblib
│   │   ├── phishx_xgboost.joblib
│   │   └── phishx_xgboost_url_v1.joblib
│   │
│   └── requirements.txt
│
├── ml/
│   ├── train.py
│   ├── train_url_model.py
│   ├── train_char_model.py
│   └── url_ml_features.py
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── package.json
│   └── index.html
│
├── README.md
└── .gitignore
```

## API

### Health Check

```http
GET /health
```

### URL Scan

```http
POST /scan
```

Request:

```json
{
  "url": "https://example.com"
}
```

The API returns the final verdict, risk score, ML probability, model contributions, DNS/SSL trust information, and extracted URL features.

## Example Results

### Legitimate URL

```text
URL: https://example.com

Verdict: SAFE
Risk Score: 2.31%
```

### Phishing-like URL

```text
URL: http://paypal-login-secure-verification.com/account/verify

Verdict: PHISHING
Risk Score: 99.93%
```

## Privacy

PhishX is designed as a URL-focused detection system.

It does not require paid or proprietary threat-intelligence services for its core detection workflow.

## Future Work

Future extensions include:

* Screenshot-based phishing detection
* Webpage content analysis
* Visual similarity detection
* Explainable AI
* Adaptive model learning
* Browser integration
* Mobile integration

### Screenshot Detection

🚧 **Coming Soon**

PhishX is planned to support phishing detection from webpage screenshots and visual content in a future version.

## Research Context

The hybrid architecture follows the research framework in which machine learning provides the primary phishing-risk signal while DNS and SSL indicators provide complementary domain-trust context.

The current implementation extends the URL-based machine learning component using character-level URL modeling alongside XGBoost.

## Disclaimer

PhishX is a research and educational cybersecurity project. Detection results should be treated as risk assessments rather than absolute guarantees of website safety.

---