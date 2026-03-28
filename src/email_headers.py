import re
from email.utils import parseaddr


def _extract_domain_from_email(value: str) -> str:
    _, parsed = parseaddr(value or "")
    email_value = parsed or (value or "").strip()
    if "@" not in email_value:
        return ""
    return email_value.rsplit("@", 1)[-1].lower()


def parse_raw_headers(raw_headers: str) -> dict:
    headers = {}
    current_key = None

    for raw_line in (raw_headers or "").splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        if line[:1].isspace() and current_key:
            headers[current_key] = f"{headers[current_key]} {line.strip()}"
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        current_key = key.strip().lower()
        headers[current_key] = value.strip()

    return headers


def analyze_email_headers(raw_headers: str, sender_email: str = "", button_url: str = "") -> dict:
    headers = parse_raw_headers(raw_headers)

    findings = []
    trust_signals = []
    score = 0.0

    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
    authentication_results = headers.get("authentication-results", "")
    received_spf = headers.get("received-spf", "")
    x_forefront = headers.get("x-forefront-antispam-report", "")
    x_ms_exchange = headers.get("x-ms-exchange-organization-scl", "")

    sender_domain = _extract_domain_from_email(sender_email or from_header)
    from_domain = _extract_domain_from_email(from_header)
    reply_to_domain = _extract_domain_from_email(reply_to)
    return_path_domain = _extract_domain_from_email(return_path)

    if sender_domain and from_domain and sender_domain != from_domain:
        score += 0.12
        findings.append(f"Campo From usa {from_domain}, diferente do remetente informado {sender_domain}")

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        score += 0.24
        findings.append(f"Reply-To aponta para {reply_to_domain}, diferente do domínio de envio {from_domain}")

    if return_path_domain and from_domain and return_path_domain != from_domain:
        score += 0.18
        findings.append(f"Return-Path usa {return_path_domain}, diferente do domínio do From")

    auth_blob = f"{authentication_results} {received_spf}".lower()
    if "spf=fail" in auth_blob or "spf fail" in auth_blob or "received-spf: fail" in auth_blob:
        score += 0.24
        findings.append("SPF falhou nos cabeçalhos")
    elif "spf=pass" in auth_blob or "spf pass" in auth_blob:
        trust_signals.append("SPF passou")

    if "dkim=fail" in auth_blob or "dkim fail" in auth_blob:
        score += 0.22
        findings.append("DKIM falhou nos cabeçalhos")
    elif "dkim=pass" in auth_blob or "dkim pass" in auth_blob:
        trust_signals.append("DKIM passou")

    if "dmarc=fail" in auth_blob or "dmarc fail" in auth_blob:
        score += 0.28
        findings.append("DMARC falhou nos cabeçalhos")
    elif "dmarc=pass" in auth_blob or "dmarc pass" in auth_blob:
        trust_signals.append("DMARC passou")

    if "phish" in x_forefront.lower():
        score += 0.20
        findings.append("Cabeçalho antispam do provedor menciona phishing")

    if x_ms_exchange.isdigit():
        scl_value = int(x_ms_exchange)
        if scl_value >= 5:
            score += 0.14
            findings.append(f"SCL do Exchange indica alta chance de spam ({scl_value})")
        elif scl_value <= 1:
            trust_signals.append(f"SCL do Exchange baixo ({scl_value})")

    received_count = len(re.findall(r"(?im)^received:", raw_headers or ""))
    if received_count >= 8:
        score += 0.08
        findings.append("Mensagem passou por muitos hops Received")
    elif received_count >= 1:
        trust_signals.append(f"Cadeia Received presente com {received_count} hop(s)")

    if not headers:
        findings.append("Cabeçalhos não puderam ser interpretados")
        score += 0.08

    score = max(0.0, min(score, 0.95))

    return {
        "score": score,
        "findings": findings[:6],
        "trust_signals": trust_signals[:5],
        "parsed_headers": {
            "from": from_header,
            "reply_to": reply_to,
            "return_path": return_path,
            "authentication_results": authentication_results,
            "received_spf": received_spf,
        },
        "button_url": button_url,
    }
