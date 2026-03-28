import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
    
import math
import re
import socket
import ssl
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
import tldextract
import whois
from bs4 import BeautifulSoup

import src.external_features as external_features


SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly", "tiny.cc"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "signin", "password", "wallet"
}

BRANDS = {
    "google", "facebook", "paypal", "amazon", "microsoft",
    "apple", "netflix", "instagram", "bank", "nubank"
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq"
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0"
}


def normalizar_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def parse_date(value):
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value
    return None


def main_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


def url_entropy(url: str) -> float:
    if not url:
        return 0.0
    prob = [n / len(url) for n in Counter(url).values()]
    return -sum(p * math.log2(p) for p in prob)


def count_digits(text: str) -> int:
    return sum(c.isdigit() for c in text)


def count_special_chars(text: str) -> int:
    return len(re.findall(r"[!@#$%^&*(),.?\":{}|<>%=_]", text))


def has_brand_name(text: str) -> int:
    text = text.lower()
    return int(any(brand in text for brand in BRANDS))


def count_suspicious_words(text: str) -> int:
    text = text.lower()
    return sum(1 for word in SUSPICIOUS_WORDS if word in text)


def suspicious_tld(hostname: str) -> int:
    hostname = hostname.lower()
    return int(any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS))


def count_hyphens(text: str) -> int:
    return text.count("-")


def has_encoding(text: str) -> int:
    return int("%" in text)


def count_subdomains(hostname: str) -> int:
    ext = tldextract.extract(hostname)
    sub = ext.subdomain or ""
    if not sub:
        return 0
    return sub.count(".") + 1


def safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def tokenize_text(text: str):
    return [token for token in re.split(r"[^a-z0-9]+", (text or "").lower()) if token]


def path_depth(path: str) -> int:
    path = path or ""
    return len([segment for segment in path.split("/") if segment])


def path_token_count(path: str) -> int:
    return len(tokenize_text(path))


def query_param_count(query: str) -> int:
    query = query or ""
    if not query:
        return 0
    return query.count("&") + 1


def hostname_entropy(hostname: str) -> float:
    return round(url_entropy(hostname or ""), 6)


def domain_token_count(hostname: str) -> int:
    return len(tokenize_text(hostname))


def build_fast_context(url: str):
    url = normalizar_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    return {
        "url": url,
        "parsed": parsed,
        "hostname": hostname,
    }


def build_slow_context(url: str):
    url = normalizar_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    response = None
    html = ""
    soup = None
    redirect_count = 0
    cert_ok = False
    whois_data = None
    dns_ok = False
    status_code = None

    try:
        response = requests.get(
            url,
            timeout=2,
            allow_redirects=True,
            headers=DEFAULT_HEADERS
        )
        html = response.text or ""
        soup = BeautifulSoup(html, "html.parser")
        redirect_count = len(response.history)
        status_code = response.status_code

        if response.url:
            url = response.url
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
    except Exception:
        pass

    try:
        socket.gethostbyname(hostname)
        dns_ok = True
    except Exception:
        dns_ok = False

    try:
        whois_data = whois.whois(hostname)
    except Exception:
        whois_data = None

    if parsed.scheme == "https" and hostname:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        cert_ok = True
        except Exception:
            cert_ok = False

    return {
        "url": url,
        "parsed": parsed,
        "hostname": hostname,
        "response": response,
        "html": html,
        "soup": soup,
        "redirect_count": redirect_count,
        "cert_ok": cert_ok,
        "whois": whois_data,
        "dns_ok": dns_ok,
        "status_code": status_code,
    }


# ========= FAST FEATURES =========

def extract_fast_features(url: str):
    ctx = build_fast_context(url)
    url = ctx["url"]
    parsed = ctx["parsed"]
    hostname = ctx["hostname"]
    hostname_digits = count_digits(hostname)
    url_digits = count_digits(url)
    special_chars = count_special_chars(url)
    hostname_tokens = domain_token_count(hostname)
    path_tokens = path_token_count(parsed.path or "")
    query_params = query_param_count(parsed.query or "")
    suspicious_word_total = count_suspicious_words(url)

    ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    ipv6_pattern = r"^\[[0-9a-fA-F:]+\]$"

    # Baseline atual do modelo v2: 16 features rápidas após remover a cauda fraca.
    features = {
        "URL_Length": 1 if len(url) < 54 else 0 if len(url) <= 75 else -1,
        "digit_ratio": safe_ratio(url_digits, len(url)),
        "hostname_digit_ratio": safe_ratio(hostname_digits, len(hostname)),
        "special_char_ratio": safe_ratio(special_chars, len(url)),
        "suspicious_word_count": suspicious_word_total,
        "subdomain_count": count_subdomains(hostname),
        "url_entropy": round(url_entropy(url), 6),
        "hostname_entropy": hostname_entropy(hostname),
        "hyphen_count": count_hyphens(url),
        "brand_name": has_brand_name(url),
        "hostname_length": len(hostname),
        "domain_token_count": hostname_tokens,
        "path_depth": path_depth(parsed.path or ""),
        "path_token_count": path_tokens,
        "query_length": len(parsed.query or ""),
        "query_param_count": query_params,
    }

    return features


# ========= SLOW FEATURES =========

def feature_domain_registration_length(whois_data):
    try:
        expiration = parse_date(getattr(whois_data, "expiration_date", None))
        if expiration is None:
            return 0
        meses = (expiration - datetime.now()).days / 30
        return 1 if meses >= 12 else -1
    except Exception:
        return 0


def feature_age_of_domain(whois_data):
    try:
        creation = parse_date(getattr(whois_data, "creation_date", None))
        if creation is None:
            return 0
        meses = (datetime.now() - creation).days / 30
        return 1 if meses >= 6 else -1
    except Exception:
        return 0


def feature_favicon(soup, url, hostname):
    if not soup:
        return 0
    link = soup.find("link", rel=lambda x: x and "icon" in str(x).lower())
    if not link or not link.get("href"):
        return 0
    favicon_url = urljoin(url, link["href"])
    favicon_host = urlparse(favicon_url).hostname or ""
    return 1 if favicon_host in ("", hostname) or main_domain(favicon_host) == main_domain(hostname) else -1


def feature_request_url(soup, url, hostname):
    if not soup:
        return 0

    tags = soup.find_all(["img", "audio", "embed", "iframe", "source", "video"])
    if not tags:
        return 1

    externos = 0
    total = 0
    base_main = main_domain(hostname)

    for tag in tags:
        src = tag.get("src")
        if not src:
            continue
        total += 1
        full = urljoin(url, src)
        host = urlparse(full).hostname or ""
        if host and main_domain(host) != base_main:
            externos += 1

    if total == 0:
        return 1

    ratio = externos / total
    if ratio < 0.22:
        return 1
    elif ratio <= 0.61:
        return 0
    return -1


def feature_url_of_anchor(soup, url, hostname):
    if not soup:
        return 0

    anchors = soup.find_all("a")
    if not anchors:
        return 1

    inseguros = 0
    total = 0
    base_main = main_domain(hostname)

    for a in anchors:
        href = (a.get("href") or "").strip().lower()
        total += 1

        if href in ("", "#", "#content", "javascript:void(0)", "javascript:;") or href.startswith("mailto:"):
            inseguros += 1
            continue

        full = urljoin(url, href)
        host = urlparse(full).hostname or ""
        if host and main_domain(host) != base_main:
            inseguros += 1

    if total == 0:
        return 1

    ratio = inseguros / total
    if ratio < 0.31:
        return 1
    elif ratio <= 0.67:
        return 0
    return -1


def feature_links_in_tags(soup, url, hostname):
    if not soup:
        return 0

    tags = soup.find_all(["meta", "script", "link", "style"])
    if not tags:
        return 1

    externos = 0
    total = 0
    base_main = main_domain(hostname)

    for tag in tags:
        ref = tag.get("href") or tag.get("src")
        if not ref:
            continue
        total += 1
        full = urljoin(url, ref)
        host = urlparse(full).hostname or ""
        if host and main_domain(host) != base_main:
            externos += 1

    if total == 0:
        return 1

    ratio = externos / total
    if ratio < 0.17:
        return 1
    elif ratio <= 0.81:
        return 0
    return -1


def feature_sfh(soup, url, hostname):
    if not soup:
        return 0

    forms = soup.find_all("form")
    if not forms:
        return 1

    base_main = main_domain(hostname)

    for form in forms:
        action = (form.get("action") or "").strip().lower()

        if action in ("", "about:blank") or action.startswith("javascript:"):
            return -1

        full = urljoin(url, action)
        host = urlparse(full).hostname or ""
        if host and main_domain(host) != base_main:
            return 0

    return 1


def extract_slow_features(url: str):
    ctx = build_slow_context(url)

    url = ctx["url"]
    parsed = ctx["parsed"]
    hostname = ctx["hostname"]
    soup = ctx["soup"]
    html = ctx["html"]
    whois_data = ctx["whois"]
    response = ctx["response"]

    features = {
        "SSLfinal_State": 1 if url.startswith("https://") and ctx["cert_ok"] else 0 if url.startswith("https://") else -1,
        "Domain_registration_length": feature_domain_registration_length(whois_data),
        "Favicon": feature_favicon(soup, url, hostname),
        "port": 1 if parsed.port in (None, 80, 443) else -1,
        "Request_URL": feature_request_url(soup, url, hostname),
        "URL_of_Anchor": feature_url_of_anchor(soup, url, hostname),
        "Links_in_tags": feature_links_in_tags(soup, url, hostname),
        "SFH": feature_sfh(soup, url, hostname),
        "Submitting_to_email": -1 if "mailto:" in html.lower() else 1,
        "Abnormal_URL": 0 if whois_data is None else 1,
        "Redirect": 1 if ctx["redirect_count"] == 0 else 0 if ctx["redirect_count"] <= 2 else -1,
        "on_mouseover": -1 if re.search(r'onmouseover\s*=|window\.status|status=', html, re.IGNORECASE) else 1,
        "RightClick": -1 if re.search(r"event\.button\s*==\s*2|contextmenu", html, re.IGNORECASE) else 1,
        "popUpWidnow": -1 if re.search(r"alert\s*\(|prompt\s*\(|confirm\s*\(", html, re.IGNORECASE) else 1,
        "Iframe": -1 if soup and soup.find(["iframe", "frame"]) else 1 if soup else 0,
        "age_of_domain": feature_age_of_domain(whois_data),
        "DNSRecord": 1 if ctx["dns_ok"] else -1,
        "web_traffic": external_features.feature_web_traffic(hostname),
        "Page_Rank": external_features.feature_page_rank(hostname),
        "Google_Index": external_features.feature_google_index(url, hostname),
        "Links_pointing_to_page": external_features.feature_links_pointing_to_page_external(url, hostname, html),
        "Statistical_report": external_features.feature_statistical_report(url, hostname),
        "status_code": 0 if response is None or response.status_code is None else response.status_code,
    }

    return features


def extrair_features_hybrid(url: str, include_slow: bool = True):
    features = extract_fast_features(url)
    if include_slow:
        features.update(extract_slow_features(url))
    return features
