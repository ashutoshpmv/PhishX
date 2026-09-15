import requests


API_URL = "http://127.0.0.1:8000/scan"


urls = [
    "https://google.com",
    "https://example.com",
    "https://github.com",
    "https://www.microsoft.com",
    "http://paypal-login-secure-verification.com/account/verify",
]


for url in urls:

    print("\n" + "=" * 80)
    print("URL:", url)
    print("=" * 80)

    try:

        response = requests.post(
            API_URL,
            json={
                "url": url
            },
            timeout=30
        )

        data = response.json()

        if response.status_code != 200:

            print("ERROR:")
            print(data)
            continue

        print(
            f"Verdict: {data['verdict']}"
        )

        print(
            f"Risk Score: {data['risk_score']}%"
        )

        print(
            f"ML Probability: "
            f"{data['ml']['phishing_probability']}%"
        )

        print(
            f"Character Model: "
            f"{data['ml']['character_model']}%"
        )

        print(
            f"XGBoost Model: "
            f"{data['ml']['xgboost_model']}%"
        )

        print(
            f"DNS/SSL Trust: "
            f"{data['dns_ssl']['trust_score']}%"
        )

        print(
            f"DNS/SSL Risk: "
            f"{data['dns_ssl']['risk']}%"
        )

    except Exception as error:

        print(
            "Request failed:",
            error
        )