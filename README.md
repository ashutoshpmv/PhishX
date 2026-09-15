# PhishX

PhishX is a hybrid phishing-URL detection platform based on the research framework:
- XGBoost URL analysis: 65%
- DNS + SSL trust analysis: 35%

> This implementation is being developed as a real deployable system. The research paper is the methodological reference; production results will be measured from the trained model and live analysis rather than copied from the paper.

## Planned architecture

User URL -> URL feature extraction -> XGBoost (65%) + DNS/SSL analysis (35%) -> Hybrid Risk Score -> Safe / Suspicious / Phishing

## Repository structure

```text
PhishX/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   └── services/
│   │       ├── url_features.py
│   │       ├── dns_ssl.py
│   │       └── hybrid.py
│   └── requirements.txt
├── ml/
│   ├── train.py
│   └── README.md
├── frontend/
│   ├── index.html
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── index.css
└── .gitignore
```

## Important

The paper does not specify a downloadable training dataset by name in its methodology. For the implementation, a public labelled URL dataset will be used and documented separately. Do not claim the paper's 99% result as the deployed model's result unless the same experimental setup is reproduced.

## Research publication

A dedicated publication section will be added to the frontend with the published paper details and link supplied by the owner.

## Future feature

Screenshot/image phishing detection will be displayed as **Coming Soon**, matching the research paper's future-work direction around webpage visual analysis.
