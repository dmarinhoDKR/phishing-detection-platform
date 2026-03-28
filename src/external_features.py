import os
import re
import requests
from functools import lru_cache

TIMEOUT = 6


def get_env(name: str, default: str = "") -> str:
    value = os.getenv(name, default)
    return value.strip()


def classify_3way(score, good_threshold, bad_threshold, reverse=False):
    """
    Retorna:
    1  -> bom / legítimo
    0  -> suspeito / intermediário
    -1 -> ruim / phishing
    """
    if score is None:
        return 0

    if reverse:
        if score <= good_threshold:
            return 1
        if score >= bad_threshold:
            return -1
        return 0

    if score >= good_threshold:
        return 1
    if score <= bad_threshold:
        return -1
    return 0


@lru_cache(maxsize=2048)
def feature_web_traffic(hostname: str) -> int:
    api_url = get_env("WEB_TRAFFIC_API_URL")
    api_key = get_env("WEB_TRAFFIC_API_KEY")

    if not api_url or not hostname:
        return 0

    try:
        response = requests.get(
            api_url,
            params={"domain": hostname},
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        rank = data.get("traffic_rank")
        if rank is None:
            return 0

        return classify_3way(rank, good_threshold=100000, bad_threshold=500000, reverse=True)
    except Exception:
        return 0


@lru_cache(maxsize=2048)
def feature_page_rank(hostname: str) -> int:
    api_url = get_env("PAGE_RANK_API_URL")
    api_key = get_env("PAGE_RANK_API_KEY")

    if not api_url or not hostname:
        return 0

    try:
        response = requests.get(
            api_url,
            params={"domain": hostname},
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        rank = data.get("page_rank")
        if rank is None:
            return 0

        return classify_3way(rank, good_threshold=5.0, bad_threshold=2.0, reverse=False)
    except Exception:
        return 0


@lru_cache(maxsize=2048)
def feature_google_index(url: str, hostname: str) -> int:
    api_url = get_env("SEARCH_API_URL")
    api_key = get_env("SEARCH_API_KEY")

    if not api_url or not hostname:
        return 0

    try:
        response = requests.get(
            api_url,
            params={"domain": hostname, "url": url},
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        indexed = data.get("indexed")
        if indexed is True:
            return 1
        if indexed is False:
            return -1
        return 0
    except Exception:
        return 0


@lru_cache(maxsize=2048)
def feature_links_pointing_to_page_external(url: str, hostname: str, html: str) -> int:
    api_url = get_env("BACKLINK_API_URL")
    api_key = get_env("BACKLINK_API_KEY")

    if api_url and hostname:
        try:
            response = requests.get(
                api_url,
                params={"domain": hostname, "url": url},
                headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            backlinks = data.get("backlinks")
            if backlinks is not None:
                if backlinks == 0:
                    return -1
                if backlinks <= 2:
                    return 0
                return 1
        except Exception:
            pass

    if not html:
        return 0

    total_links = html.lower().count("href=")
    if total_links == 0:
        return -1
    if total_links <= 2:
        return 0
    return 1


@lru_cache(maxsize=2048)
def feature_statistical_report(url: str, hostname: str) -> int:
    """
    Usa Google Safe Browsing v4.
    Retorna:
    -1 -> URL considerada perigosa
     1 -> URL não encontrada nas listas
     0 -> desconhecido / erro
    """
    api_key = get_env("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key or not url:
        return 0

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {
            "clientId": "phishing-ai-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()

        if "matches" in data and data["matches"]:
            return -1

        return 1

    except Exception:
        return 0