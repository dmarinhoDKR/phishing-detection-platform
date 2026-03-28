import re
from email.utils import parseaddr
from urllib.parse import urlparse

from src.email_headers import analyze_email_headers
from src.detector_phishing_v2 import check_url_detailed


SAFE_THRESHOLD = 0.35
HIGH_RISK_THRESHOLD = 0.65

BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "paypal": {"paypal.com"},
    "coinbase": {"coinbase.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.com.br"},
    "meta": {"meta.com", "facebook.com", "instagram.com", "whatsapp.com"},
    "netflix": {"netflix.com"},
    "nubank": {"nubank.com.br"},
    "itau": {"itau.com.br"},
    "mercado livre": {"mercadolivre.com.br", "mercadolibre.com"},
}

SUBJECT_PATTERNS = [
    r"service agreement",
    r"review account",
    r"update your account",
    r"billing",
    r"invoice",
    r"verify",
    r"confirm",
    r"login",
    r"security alert",
    r"urgent",
    r"unusual activity",
    r"suspens",
    r"reativa",
    r"atualiza",
]

BODY_PATTERNS = [
    r"review your account",
    r"confirm .*billing",
    r"confirm .*payment",
    r"verify .*account",
    r"click .*button",
    r"service agreement",
    r"keep .*active",
    r"avoid .*susp",
    r"support page",
    r"update .*details",
]


def _normalize_text(text: str) -> str:
    return " ".join((text or "").strip().split())


def _extract_domain(value: str) -> str:
    _, parsed = parseaddr(value or "")
    email_value = parsed or (value or "").strip()
    if "@" not in email_value:
        return ""
    return email_value.rsplit("@", 1)[-1].lower()


def _extract_local_part(value: str) -> str:
    _, parsed = parseaddr(value or "")
    email_value = parsed or (value or "").strip()
    if "@" not in email_value:
        return ""
    return email_value.rsplit("@", 1)[0].lower()


def _root_domain(domain: str) -> str:
    parts = [part for part in (domain or "").lower().split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _domain_matches_brand(domain: str, brand: str) -> bool:
    brand = (brand or "").lower().strip()
    if not brand or not domain:
        return False

    allowed_domains = BRAND_DOMAINS.get(brand, set())
    if not allowed_domains:
        return brand.replace(" ", "") in domain.replace("-", "")

    root = _root_domain(domain)
    return root in allowed_domains or domain in allowed_domains


def _find_claimed_brand(display_name: str, subject: str, body: str):
    haystack = f"{display_name} {subject} {body}".lower()
    for brand in BRAND_DOMAINS:
        if brand in haystack:
            return brand
    return None


def _count_pattern_hits(patterns, text: str) -> int:
    lowered = (text or "").lower()
    hits = 0
    for pattern in patterns:
        if re.search(pattern, lowered):
            hits += 1
    return hits


def _risk_band(score: float) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "phishing"
    if score >= SAFE_THRESHOLD:
        return "suspeito"
    return "legitimo"


def _risk_band_label(risk_band: str) -> str:
    labels = {
        "legitimo": "Legítimo",
        "suspeito": "Suspeito",
        "phishing": "Phishing",
    }
    return labels.get(risk_band, risk_band.title())


def _risk_level(score: float) -> str:
    if score >= 0.85:
        return "ALTO"
    if score >= HIGH_RISK_THRESHOLD:
        return "MODERADO"
    if score >= SAFE_THRESHOLD:
        return "EM REVISAO"
    return "BAIXO"


def analyze_email(
    display_name: str = "",
    sender_email: str = "",
    subject: str = "",
    body_excerpt: str = "",
    button_url: str = "",
    raw_headers: str = "",
    attachments_blocked: bool = False,
    marked_as_junk: bool = False,
):
    display_name = _normalize_text(display_name)
    sender_email = _normalize_text(sender_email)
    subject = _normalize_text(subject)
    body_excerpt = _normalize_text(body_excerpt)
    button_url = _normalize_text(button_url)
    raw_headers = raw_headers or ""
    normalized_button_url = button_url
    if normalized_button_url and not normalized_button_url.startswith(("http://", "https://")):
        normalized_button_url = f"https://{normalized_button_url}"

    sender_domain = _extract_domain(sender_email)
    sender_local_part = _extract_local_part(sender_email)
    claimed_brand = _find_claimed_brand(display_name, subject, body_excerpt)

    score = 0.0
    reasons = []
    trust_signals = []

    if not sender_domain:
        score += 0.22
        reasons.append("Remetente sem domínio de email válido")

    if claimed_brand and sender_domain and not _domain_matches_brand(sender_domain, claimed_brand):
        score += 0.38
        reasons.append(f"Marca exibida parece ser {claimed_brand.title()}, mas o domínio do remetente é {sender_domain}")

    if display_name and sender_domain:
        compact_name = display_name.lower().replace(" ", "")
        compact_domain = sender_domain.replace("-", "")
        if compact_name and compact_name not in compact_domain and claimed_brand:
            score += 0.08
            reasons.append("Nome exibido e domínio do remetente não combinam")

    if sender_local_part in {"support", "admin", "security", "billing", "mr", "service"}:
        score += 0.05
        reasons.append("Local-part do remetente é genérico")

    subject_hits = _count_pattern_hits(SUBJECT_PATTERNS, subject)
    if subject_hits:
        score += min(0.08 * subject_hits, 0.16)
        reasons.append("Assunto contém padrão comum em campanhas de phishing")

    body_hits = _count_pattern_hits(BODY_PATTERNS, body_excerpt)
    if body_hits:
        score += min(0.06 * body_hits, 0.18)
        reasons.append("Texto do email pressiona revisão ou confirmação de conta")

    if attachments_blocked:
        score += 0.18
        reasons.append("Cliente de email informou anexos bloqueados por segurança")

    if marked_as_junk:
        score += 0.18
        reasons.append("Mensagem já foi classificada como lixo eletrônico")

    header_analysis = None
    if raw_headers.strip():
        header_analysis = analyze_email_headers(
            raw_headers=raw_headers,
            sender_email=sender_email,
            button_url=normalized_button_url,
        )
        score += min(header_analysis["score"], 0.35)
        reasons.extend(header_analysis["findings"][:3])
        trust_signals.extend(header_analysis["trust_signals"][:2])

    url_result = None
    if normalized_button_url:
        parsed = urlparse(normalized_button_url)
        url_domain = parsed.netloc.lower()
        if claimed_brand and url_domain and not _domain_matches_brand(url_domain, claimed_brand):
            score += 0.18
            reasons.append(f"Link do botão aponta para {url_domain}, não para um domínio típico de {claimed_brand.title()}")

        try:
            url_result = check_url_detailed(normalized_button_url)
            score += 0.30 * url_result["prob_phishing"]
            if url_result["faixa_risco"] == "phishing":
                reasons.append("URL do botão foi classificada como phishing")
            elif url_result["faixa_risco"] == "suspeito":
                reasons.append("URL do botão caiu na faixa suspeita")
            else:
                trust_signals.append("URL do botão isoladamente parece legítima")
        except Exception as exc:
            reasons.append(f"Falha ao analisar a URL do botão: {exc}")

    if claimed_brand and sender_domain and _domain_matches_brand(sender_domain, claimed_brand):
        trust_signals.append("Domínio do remetente combina com a marca alegada")

    if not attachments_blocked and not marked_as_junk and not claimed_brand:
        trust_signals.append("Contexto do email tem poucos sinais clássicos de spoofing")

    score = max(0.0, min(score, 0.99))
    risk_band = _risk_band(score)

    if risk_band == "phishing":
        summary = "Classificado como phishing porque o contexto do email mostra spoofing, urgência ou inconsistências fortes entre marca, remetente e link."
    elif risk_band == "suspeito":
        summary = "Classificado como suspeito porque há sinais mistos: o email merece revisão manual antes de qualquer clique ou download."
    else:
        summary = "Classificado como legítimo porque o remetente, o contexto e o link não apresentaram sinais fortes de fraude."

    return {
        "score_email": score,
        "faixa_risco": risk_band,
        "faixa_risco_label": _risk_band_label(risk_band),
        "nivel_risco": _risk_level(score),
        "claimed_brand": claimed_brand.title() if claimed_brand else "",
        "sender_domain": sender_domain,
        "reasons": reasons[:6] or ["Sem sinais fortes de spoofing detectados"],
        "trust_signals": trust_signals[:4],
        "summary": summary,
        "attachments_blocked": attachments_blocked,
        "marked_as_junk": marked_as_junk,
        "header_analysis": header_analysis,
        "url_analysis": url_result,
    }
