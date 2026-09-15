from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from app.services.url_features import extract_url_features
from app.services.dns_ssl import analyze_dns_ssl
from app.services.hybrid import predict_ml, combine_scores
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="PhishX API",
    description="Hybrid ML + DNS/SSL Phishing Detection API",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def root():
    return {
        "name": "PhishX",
        "status": "online",
        "message": "Hybrid phishing detection API is running."
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/scan")
def scan_url(request: ScanRequest):

    url = str(request.url)

    try:

        # --------------------------------
        # 1. Extract URL features
        # --------------------------------
        features = extract_url_features(url)

        # --------------------------------
        # 2. ML prediction
        # Character Model = 80%
        # XGBoost Model   = 20%
        # --------------------------------
        ml_result = predict_ml(
            features,
            url
        )

        ml_probability = ml_result["phishing_probability"]

        # --------------------------------
        # 3. DNS + SSL analysis
        # --------------------------------
        dns_ssl = analyze_dns_ssl(url)

        # DNS/SSL score represents RISK
        # Convert risk into trust
        trust_score = 1 - (
            dns_ssl["score"] / 100
        )

        # --------------------------------
        # 4. Hybrid decision
        # ML = 65%
        # DNS/SSL = 35%
        # --------------------------------
        hybrid = combine_scores(
            ml_probability,
            trust_score
        )

        # --------------------------------
        # 5. Response
        # --------------------------------
        return {

            "success": True,

            "url": url,

            "verdict": hybrid["verdict"],

            "risk_score": round(
                hybrid["final_risk"] * 100,
                2
            ),

            "ml": {
                "weight": "65%",

                "phishing_probability": round(
                    ml_probability * 100,
                    2
                ),

                "contribution": round(
                    ml_probability * 65,
                    2
                ),

                "character_model": round(
                    ml_result["character_probability"] * 100,
                    2
                ),

                "xgboost_model": round(
                    ml_result["xgboost_probability"] * 100,
                    2
                )
            },

            "dns_ssl": {
                "weight": "35%",

                "trust_score": round(
                    trust_score * 100,
                    2
                ),

                "risk": round(
                    hybrid["dns_ssl_risk"] * 100,
                    2
                ),

                "contribution": round(
                    hybrid["dns_ssl_risk"] * 35,
                    2
                ),

                "details": dns_ssl
            },

            "features": features
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )