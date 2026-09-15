import re
import math
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "authenticate",
    "bank",
    "banking",
    "paypal",
    "wallet",
    "payment",
    "invoice",
    "billing",
    "recover",
    "unlock",
    "suspend",
    "alert",
    "support",
    "webscr",
    "bonus",
    "free",
    "gift",
}


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "underscore_count",
    "at_count",
    "question_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "digit_count",
    "letter_count",
    "special_char_count",
    "subdomain_count",
    "path_depth",
    "suspicious_keyword_count",
    "has_ip",
    "has_port",
    "hostname_has_hyphen",
    "double_slash_in_path",
    "hostname_entropy",
]


def normalize_url(url: str) -> str:
    url = str(url).strip()

    if not url:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0

    frequencies = {}

    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    length = len(value)

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname: str) -> int:
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_features(url: str) -> dict:
    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    hostname_lower = hostname.lower()
    url_lower = url.lower()

    path_without_scheme = parsed.path or ""

    if path_without_scheme:
        path_depth = len(
            [part for part in path_without_scheme.split("/") if part]
        )
    else:
        path_depth = 0

    suspicious_keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            suspicious_keyword_count += 1

    special_characters = re.findall(
        r"[^a-zA-Z0-9]",
        url
    )

    feature_values = {
        "url_length": len(url),

        "hostname_length": len(hostname),

        "path_length": len(path),

        "query_length": len(query),

        "fragment_length": len(fragment),

        "dot_count": url.count("."),

        "slash_count": url.count("/"),

        "hyphen_count": url.count("-"),

        "underscore_count": url.count("_"),

        "at_count": url.count("@"),

        "question_count": url.count("?"),

        "equal_count": url.count("="),

        "ampersand_count": url.count("&"),

        "percent_count": url.count("%"),

        "digit_count": sum(char.isdigit() for char in url),

        "letter_count": sum(char.isalpha() for char in url),

        "special_char_count": len(special_characters),

        "subdomain_count": max(0, len(hostname.split(".")) - 2),

        "path_depth": path_depth,

        "suspicious_keyword_count": suspicious_keyword_count,

        "has_ip": is_ip_address(hostname),


        "has_port": 1 if parsed.port is not None else 0,

        "hostname_has_hyphen": 1 if "-" in hostname else 0,

        "double_slash_in_path": 1 if "//" in path else 0,

        "hostname_entropy": calculate_entropy(hostname),
    }

    return feature_values