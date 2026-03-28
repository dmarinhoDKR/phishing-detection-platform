import os
import sys
import joblib
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.feature_extraction_hybrid import extrair_features_hybrid


# =========================
# CONFIG
# =========================

MODEL_FILENAME = "model/phishing_model_v2.pkl"
FEATURES_FILENAME = "model/feature_names_v2.pkl"

# threshold principal
PHISHING_THRESHOLD = 0.50

# zona de incerteza para disparar análise lenta
FALLBACK_LOW = 0.45
FALLBACK_HIGH = 0.80

# classificação em 3 níveis calibrada para o baseline atual
# legítimo: abaixo de 0.40
# suspeito: entre 0.40 e 0.60
# phishing: acima de 0.60
SAFE_THRESHOLD = 0.40
HIGH_RISK_THRESHOLD = 0.60


# =========================
# PATHS
# =========================

def get_path(rel_path: str) -> str:
    try:
        base_path = sys._MEIPASS  # PyInstaller
    except Exception:
        base_path = BASE_DIR

    return os.path.join(base_path, rel_path)


# =========================
# LOAD MODEL
# =========================

modelo = joblib.load(get_path(MODEL_FILENAME))
feature_names = joblib.load(get_path(FEATURES_FILENAME))


# =========================
# INTERNAL PREDICTION
# =========================

def _prepare_dataframe(features_dict: dict) -> pd.DataFrame:
    df = pd.DataFrame([features_dict])

    for col in feature_names:
        if col not in df.columns:
            df[col] = 0

    df = df[feature_names]
    return df


def _predict_once(url: str, fast_mode: bool = True):
    features_dict = extrair_features_hybrid(url, include_slow=not fast_mode)
    df = _prepare_dataframe(features_dict)

    proba = modelo.predict_proba(df)[0]
    classes = list(modelo.classes_)
    prob_dict = dict(zip(classes, proba))

    prob_phishing = prob_dict.get(-1, 0.0)
    prob_legit = prob_dict.get(1, 0.0)

    if prob_phishing >= PHISHING_THRESHOLD:
        pred = -1
        confianca = prob_phishing
    else:
        pred = 1
        confianca = prob_legit

    return {
        "pred": pred,
        "confianca": float(confianca),
        "prob_phishing": float(prob_phishing),
        "prob_legit": float(prob_legit),
        "fast_mode": fast_mode,
        "features": features_dict,
    }


def _is_fallback_zone(prob_phishing: float) -> bool:
    return FALLBACK_LOW <= prob_phishing <= FALLBACK_HIGH


def _prediction_label(pred: int) -> str:
    return "phishing" if pred == -1 else "legitimo"


def _risk_band(prob_phishing: float) -> str:
    if prob_phishing >= HIGH_RISK_THRESHOLD:
        return "phishing"
    if prob_phishing >= SAFE_THRESHOLD:
        return "suspeito"
    return "legitimo"


def _risk_band_label(risk_band: str) -> str:
    labels = {
        "legitimo": "Legítimo",
        "suspeito": "Suspeito",
        "phishing": "Phishing",
    }
    return labels.get(risk_band, risk_band.title())


def _risk_level(prob_phishing: float) -> str:
    if prob_phishing >= 0.85:
        return "ALTO"
    if prob_phishing >= HIGH_RISK_THRESHOLD:
        return "MODERADO"
    if prob_phishing >= SAFE_THRESHOLD:
        return "EM REVISAO"
    return "BAIXO"


def _reason_if(condition, text):
    return text if condition else None


def _summarize_reasons(features: dict):
    alerts = [
        _reason_if(features.get("digit_ratio", 0) >= 0.20, "Alta proporção de dígitos na URL"),
        _reason_if(features.get("hostname_entropy", 0) >= 3.5, "Hostname com padrão pouco natural"),
        _reason_if(features.get("url_entropy", 0) >= 4.3, "URL com alta entropia"),
        _reason_if(features.get("path_depth", 0) >= 4, "Path muito profundo"),
        _reason_if(features.get("path_token_count", 0) >= 8, "Path com muitos tokens"),
        _reason_if(features.get("special_char_ratio", 0) >= 0.18, "Muitos caracteres especiais"),
        _reason_if(features.get("query_length", 0) > 40, "Query string longa"),
        _reason_if(features.get("query_param_count", 0) >= 4, "Muitos parâmetros de query"),
        _reason_if(features.get("subdomain_count", 0) >= 2, "Muitos subdomínios"),
        _reason_if(features.get("suspicious_word_count", 0) >= 2, "Várias palavras associadas a fraude"),
        _reason_if(features.get("suspicious_word_count", 0) == 1, "Palavra sensível presente na URL"),
        _reason_if(features.get("brand_name") == 1, "Marca conhecida aparece na URL"),
        _reason_if(features.get("SSLfinal_State") == -1, "Sem HTTPS"),
        _reason_if(features.get("SSLfinal_State") == 0, "HTTPS sem validação forte"),
        _reason_if(features.get("DNSRecord") == -1, "DNS não resolvido"),
        _reason_if(features.get("Redirect") == -1, "Muitos redirecionamentos"),
        _reason_if(features.get("Request_URL") == -1, "Recursos externos em excesso"),
        _reason_if(features.get("URL_of_Anchor") == -1, "Muitos links inseguros"),
        _reason_if(features.get("Links_in_tags") == -1, "Tags apontando para conteúdo externo"),
        _reason_if(features.get("SFH") == -1, "Formulário com action suspeita"),
        _reason_if(features.get("Submitting_to_email") == -1, "Formulário enviando para email"),
        _reason_if(features.get("Iframe") == -1, "Uso de iframe/frame"),
        _reason_if(features.get("age_of_domain") == -1, "Domínio muito novo"),
        _reason_if(features.get("Domain_registration_length") == -1, "Registro de domínio curto"),
        _reason_if(features.get("Statistical_report") == -1, "URL encontrada em base de ameaça"),
    ]

    trust_signals = [
        _reason_if(features.get("SSLfinal_State") == 1, "HTTPS válido"),
        _reason_if(features.get("DNSRecord") == 1, "DNS resolvido"),
        _reason_if(features.get("age_of_domain") == 1, "Domínio com idade maior"),
        _reason_if(features.get("Domain_registration_length") == 1, "Registro de domínio longo"),
        _reason_if(features.get("Request_URL") == 1, "Recursos majoritariamente internos"),
        _reason_if(features.get("URL_of_Anchor") == 1, "Âncoras majoritariamente seguras"),
        _reason_if(features.get("Links_in_tags") == 1, "Tags com poucos recursos externos"),
        _reason_if(features.get("Statistical_report") == 1, "URL não encontrada em base de ameaça"),
    ]

    alerts = [item for item in alerts if item][:5]
    trust_signals = [item for item in trust_signals if item][:5]
    return alerts, trust_signals


def _build_explanation(result: dict):
    alerts, trust_signals = _summarize_reasons(result["features"])
    risk_band = _risk_band(result["prob_phishing"])

    if risk_band == "phishing":
        principais = alerts or ["Padrão estatístico do modelo próximo de phishing"]
        resumo = "Classificado como phishing por combinar sinais de risco lexical, estrutural ou externo."
    elif risk_band == "suspeito":
        principais = alerts or trust_signals or ["A URL caiu em uma faixa intermediária de risco"]
        resumo = "Classificado como suspeito porque o score ficou próximo da fronteira de decisão do modelo e merece revisão adicional."
    else:
        principais = trust_signals or ["Modelo encontrou mais sinais de legitimidade do que de fraude"]
        resumo = "Classificado como legítimo porque os sinais observados ficaram mais próximos de URLs confiáveis."

    return {
        "resumo": resumo,
        "principais_razoes": principais,
        "alertas_detectados": alerts,
        "sinais_de_confianca": trust_signals,
    }


# =========================
# PUBLIC API
# =========================

def check_url(url: str):
    resultado_fast = _predict_once(url, fast_mode=True)

    prob_phishing_fast = resultado_fast["prob_phishing"]

    # fallback se caso estiver duvidoso
    if _is_fallback_zone(prob_phishing_fast):
        try:
            resultado_full = _predict_once(url, fast_mode=False)
            return resultado_full["pred"], resultado_full["confianca"]
        except Exception:
            pass

    return resultado_fast["pred"], resultado_fast["confianca"]


def check_url_detailed(url: str):
    """
    Versão detalhada para debug, logs e futura interface avançada.
    Retorna:
    - predição
    - confiança final
    - probabilidades
    - se usou fallback
    - modo usado
    """

    resultado_fast = _predict_once(url, fast_mode=True)
    usou_fallback = False
    resultado_final = resultado_fast
    erro_fallback = None

    if _is_fallback_zone(resultado_fast["prob_phishing"]):
        try:
            resultado_full = _predict_once(url, fast_mode=False)
            usou_fallback = True
            resultado_final = resultado_full
        except Exception as exc:
            erro_fallback = str(exc)

    explanation = _build_explanation(resultado_final)
    risk_band = _risk_band(resultado_final["prob_phishing"])

    return {
        "pred": resultado_final["pred"],
        "classe": _prediction_label(resultado_final["pred"]),
        "faixa_risco": risk_band,
        "faixa_risco_label": _risk_band_label(risk_band),
        "nivel_risco": _risk_level(resultado_final["prob_phishing"]),
        "confianca": resultado_final["confianca"],
        "prob_phishing": resultado_final["prob_phishing"],
        "prob_legit": resultado_final["prob_legit"],
        "usou_fallback": usou_fallback,
        "modo_final": "full" if usou_fallback else "fast",
        "fallback_disponivel": _is_fallback_zone(resultado_fast["prob_phishing"]),
        "fallback_erro": erro_fallback,
        "fallback_ativado_por": {
            "prob_phishing_fast": resultado_fast["prob_phishing"],
            "faixa": [FALLBACK_LOW, FALLBACK_HIGH],
        },
        "pred_fast": resultado_fast["pred"],
        "classe_fast": _prediction_label(resultado_fast["pred"]),
        "faixa_risco_fast": _risk_band(resultado_fast["prob_phishing"]),
        "confianca_fast": resultado_fast["confianca"],
        "prob_phishing_fast": resultado_fast["prob_phishing"],
        "mudou_com_fallback": resultado_fast["pred"] != resultado_final["pred"],
        "features": resultado_final["features"],
        "explicacao": explanation,
    }


# =========================
# TEST
# =========================

if __name__ == "__main__":
    url_teste = "https://google.com"

    resultado = check_url_detailed(url_teste)

    print("URL:", url_teste)
    print("Predição:", resultado["pred"])
    print("Confiança:", resultado["confianca"])
    print("Prob phishing:", resultado["prob_phishing"])
    print("Prob legítimo:", resultado["prob_legit"])
    print("Fallback:", resultado["usou_fallback"])
    print("Modo final:", resultado["modo_final"])
