import re
import math
import ipaddress
from urllib.parse import urlparse


SHORTENING_SERVICES = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}


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
    "bonus",
    "free",
    "gift",
}


def calculate_entropy(value):
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


def get_hostname(url):
    parsed = urlparse(url)

    return parsed.hostname or ""


def is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_url_features(url):

    url = str(url).strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    hostname_lower = hostname.lower()
    url_lower = url.lower()

    # ---------------------------------------
    # Basic URL properties
    # ---------------------------------------

    url_length = len(url)

    hostname_length = len(hostname)

    path_length = len(path)

    # ---------------------------------------
    # UCI-compatible features
    # ---------------------------------------

    having_IP_Address = (
        1 if is_ip(hostname) else -1
    )

    URL_Length = (
        -1 if url_length > 75
        else 1
    )

    Shortining_Service = (
        -1
        if any(
            service in hostname_lower
            for service in SHORTENING_SERVICES
        )
        else 1
    )

    having_At_Symbol = (
        1 if "@" in url else -1
    )

    double_slash_redirecting = (
        1
        if "//" in url[8:]
        else -1
    )

    Prefix_Suffix = (
        -1
        if "-" in hostname
        else 1
    )

    hostname_parts = [
        part
        for part in hostname.split(".")
        if part
    ]

    subdomain_count = max(
        0,
        len(hostname_parts) - 2
    )

    if subdomain_count == 0:
        having_Sub_Domain = -1
    elif subdomain_count == 1:
        having_Sub_Domain = 0
    else:
        having_Sub_Domain = 1

    SSLfinal_State = (
        1
        if parsed.scheme.lower() == "https"
        else -1
    )

    Domain_registeration_length = 0

    Favicon = 0

    port = (
        -1
        if parsed.port is None
        else 1
    )

    HTTPS_token = (
        -1
        if "https" in hostname_lower
        else 1
    )

    Request_URL = 0

    URL_of_Anchor = 0

    Links_in_tags = 0

    SFH = 0

    Submitting_to_email = 0

    Abnormal_URL = 0

    Redirect = 0

    on_mouseover = -1

    RightClick = -1

    popUpWidnow = -1

    Iframe = -1

    age_of_domain = 0

    DNSRecord = 0

    web_traffic = 0

    Page_Rank = 0

    Google_Index = 0

    Links_pointing_to_page = 0

    Statistical_report = 1

    # ---------------------------------------
    # Additional URL intelligence
    # ---------------------------------------

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    )

    special_char_count = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    digit_count = sum(
        char.isdigit()
        for char in url
    )

    letter_count = sum(
        char.isalpha()
        for char in url
    )

    path_depth = len(
        [
            part
            for part in path.split("/")
            if part
        ]
    )

    query_parameter_count = (
        0
        if not query
        else query.count("&") + 1
    )

    hostname_entropy = calculate_entropy(
        hostname
    )

    return {

        # -----------------------------------
        # UCI 30 features
        # -----------------------------------

        "having_IP_Address":
            having_IP_Address,

        "URL_Length":
            URL_Length,

        "Shortining_Service":
            Shortining_Service,

        "having_At_Symbol":
            having_At_Symbol,

        "double_slash_redirecting":
            double_slash_redirecting,

        "Prefix_Suffix":
            Prefix_Suffix,

        "having_Sub_Domain":
            having_Sub_Domain,

        "SSLfinal_State":
            SSLfinal_State,

        "Domain_registeration_length":
            Domain_registeration_length,

        "Favicon":
            Favicon,

        "port":
            port,

        "HTTPS_token":
            HTTPS_token,

        "Request_URL":
            Request_URL,

        "URL_of_Anchor":
            URL_of_Anchor,

        "Links_in_tags":
            Links_in_tags,

        "SFH":
            SFH,

        "Submitting_to_email":
            Submitting_to_email,

        "Abnormal_URL":
            Abnormal_URL,

        "Redirect":
            Redirect,

        "on_mouseover":
            on_mouseover,

        "RightClick":
            RightClick,

        "popUpWidnow":
            popUpWidnow,

        "Iframe":
            Iframe,

        "age_of_domain":
            age_of_domain,

        "DNSRecord":
            DNSRecord,

        "web_traffic":
            web_traffic,

        "Page_Rank":
            Page_Rank,

        "Google_Index":
            Google_Index,

        "Links_pointing_to_page":
            Links_pointing_to_page,

        "Statistical_report":
            Statistical_report,

        # -----------------------------------
        # Additional URL features
        # -----------------------------------

        "url_length":
            url_length,

        "hostname_length":
            hostname_length,

        "path_length":
            path_length,

        "query_length":
            len(query),

        "dot_count":
            url.count("."),

        "slash_count":
            url.count("/"),

        "hyphen_count":
            url.count("-"),

        "underscore_count":
            url.count("_"),

        "at_count":
            url.count("@"),

        "question_count":
            url.count("?"),

        "equal_count":
            url.count("="),

        "ampersand_count":
            url.count("&"),

        "percent_count":
            url.count("%"),

        "digit_count":
            digit_count,

        "letter_count":
            letter_count,

        "special_char_count":
            special_char_count,

        "subdomain_count":
            subdomain_count,

        "path_depth":
            path_depth,

        "suspicious_keyword_count":
            suspicious_keyword_count,

        "has_ip":
            1 if is_ip(hostname) else 0,

        "uses_https":
            1 if parsed.scheme.lower() == "https" else 0,

        "has_port":
            1 if parsed.port is not None else 0,

        "hostname_has_hyphen":
            1 if "-" in hostname else 0,

        "double_slash_in_path":
            1 if "//" in path else 0,

        "hostname_entropy":
            hostname_entropy,
    }