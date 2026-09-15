import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone


def analyze_dns_ssl(url: str):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    result = {
        "dns_resolved": False,
        "ip_address": None,
        "ssl_valid": False,
        "ssl_expired": False,
        "issuer": None,
        "certificate_expiry": None,
        "dns_score": 0,
        "ssl_score": 0,
        "score": 0,
    }

    if not hostname:
        result["score"] = 100
        return result

    # ==================================================
    # DNS ANALYSIS
    # ==================================================

    try:
        ip_address = socket.gethostbyname(hostname)

        result["dns_resolved"] = True
        result["ip_address"] = ip_address

    except Exception:
        result["dns_resolved"] = False

    # DNS risk
    if not result["dns_resolved"]:
        result["dns_score"] = 100
    else:
        result["dns_score"] = 0

    # ==================================================
    # SSL / TLS ANALYSIS
    # ==================================================

    if parsed.scheme == "https":

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (hostname, 443),
                timeout=6
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname
                ) as secure_sock:

                    certificate = secure_sock.getpeercert()

                    result["ssl_valid"] = True

                    # ----------------------------------
                    # Certificate issuer
                    # ----------------------------------

                    issuer = certificate.get(
                        "issuer",
                        []
                    )

                    for issuer_part in issuer:

                        for key, value in issuer_part:

                            if key == "organizationName":

                                result["issuer"] = value

                    # ----------------------------------
                    # Certificate expiry
                    # ----------------------------------

                    expiry = certificate.get(
                        "notAfter"
                    )

                    if expiry:

                        result["certificate_expiry"] = expiry

                        try:

                            expiry_date = datetime.strptime(
                                expiry,
                                "%b %d %H:%M:%S %Y %Z"
                            ).replace(
                                tzinfo=timezone.utc
                            )

                            if expiry_date < datetime.now(
                                timezone.utc
                            ):

                                result["ssl_expired"] = True

                        except Exception:
                            pass

        except Exception:

            result["ssl_valid"] = False

    else:

        # HTTP website has no HTTPS protection
        result["ssl_valid"] = False

    # ==================================================
    # SSL RISK
    # ==================================================

    if parsed.scheme != "https":

        result["ssl_score"] = 100

    elif not result["ssl_valid"]:

        result["ssl_score"] = 100

    elif result["ssl_expired"]:

        result["ssl_score"] = 100

    else:

        result["ssl_score"] = 0

    # ==================================================
    # COMBINED DNS + SSL RISK
    # ==================================================

    result["score"] = round(
        (
            result["dns_score"] * 0.5
            + result["ssl_score"] * 0.5
        ),
        2
    )

    return result