import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import streamlit as st
from src.analysis_logging import append_analysis_log, clear_analysis_logs, read_recent_logs
from src.detector_phishing_v2 import check_url_detailed
from src.email_analysis import analyze_email

st.set_page_config(
    page_title="Detector de Phishing",
    page_icon="🔎",
    layout="centered"
)

st.markdown("""
<style>
html, body, [class*="css"] {
    font-family: Arial, sans-serif;
}

.stApp {
    background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
}

.block-container {
    max-width: 820px;
    padding-top: 2rem;
    padding-bottom: 2rem;
}

.app-card {
    background: rgba(17, 24, 39, 0.88);
    border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 18px;
    padding: 24px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.30);
}

.hero-title {
    text-align: center;
    font-size: 2.4rem;
    font-weight: 800;
    color: #f8fafc;
    margin-bottom: 0.4rem;
}

.hero-subtitle {
    text-align: center;
    color: #cbd5e1;
    font-size: 1rem;
    margin-bottom: 1.2rem;
}

.result-box {
    padding: 18px 20px;
    border-radius: 14px;
    font-weight: 700;
    margin-top: 14px;
    margin-bottom: 14px;
    border: 1px solid rgba(255,255,255,0.08);
}

.result-legit {
    background: linear-gradient(90deg, #14532d 0%, #166534 100%);
    color: white;
}

.result-phishing {
    background: linear-gradient(90deg, #7f1d1d 0%, #991b1b 100%);
    color: white;
}

.result-suspicious {
    background: linear-gradient(90deg, #92400e 0%, #b45309 100%);
    color: white;
}

.detail-card {
    background: rgba(30, 41, 59, 0.72);
    border: 1px solid rgba(148, 163, 184, 0.16);
    border-radius: 14px;
    padding: 16px 18px;
    margin-top: 12px;
}

.detail-title {
    color: #f8fafc;
    font-weight: 700;
    margin-bottom: 8px;
}

.detail-text {
    color: #cbd5e1;
    line-height: 1.7;
    font-size: 0.98rem;
}

.tip-box {
    margin-top: 18px;
    padding: 14px 16px;
    border-radius: 12px;
    background: rgba(37, 99, 235, 0.10);
    border: 1px solid rgba(37, 99, 235, 0.25);
    color: #dbeafe;
    font-size: 0.95rem;
}

footer {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='app-card'>", unsafe_allow_html=True)

st.markdown("<div class='hero-title'>🔎 Detector de Phishing</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='hero-subtitle'>Analise URLs e emails suspeitos com sinais lexicais, spoofing e contexto de risco.</div>",
    unsafe_allow_html=True
)

def render_result_box(icon: str, title: str, score: float, faixa: str):
    css_class = {
        "phishing": "result-phishing",
        "suspeito": "result-suspicious",
        "legitimo": "result-legit",
    }.get(faixa, "result-legit")

    st.markdown(
        f"""
        <div class='result-box {css_class}'>
            {icon} {title}<br>
            Score de risco: {score:.2%}
        </div>
        """,
        unsafe_allow_html=True
    )


def format_recent_url(record: dict) -> str:
    url = record.get("input", {}).get("url", "")
    score = record.get("result", {}).get("prob_phishing", 0.0)
    faixa = record.get("result", {}).get("faixa_risco_label", "")
    return f"{faixa} | {score:.2%} | {url}"


def format_recent_email(record: dict) -> str:
    sender = record.get("input", {}).get("sender_email", "") or "sem remetente"
    score = record.get("result", {}).get("score_email", 0.0)
    faixa = record.get("result", {}).get("faixa_risco_label", "")
    return f"{faixa} | {score:.2%} | {sender}"


aba_url, aba_email = st.tabs(["Analise de URL", "Analise de Email"])

with aba_url:
    with st.form("form_analise_url", clear_on_submit=False):
        url = st.text_input(
            "URL",
            placeholder="Ex.: google.com ou https://exemplo.com"
        )
        submitted_url = st.form_submit_button("Verificar URL")

    if submitted_url:
        if not url.strip():
            st.warning("Digite uma URL.")
        else:
            url = url.strip()
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            with st.spinner("Analisando URL..."):
                resultado = check_url_detailed(url)
                append_analysis_log(
                    "url",
                    {
                        "analysis_type": "url",
                        "input": {"url": url},
                        "result": {
                            "faixa_risco": resultado["faixa_risco"],
                            "faixa_risco_label": resultado["faixa_risco_label"],
                            "nivel_risco": resultado["nivel_risco"],
                            "prob_phishing": resultado["prob_phishing"],
                            "modo_final": resultado["modo_final"],
                            "usou_fallback": resultado["usou_fallback"],
                            "principais_razoes": resultado["explicacao"]["principais_razoes"][:4],
                        },
                    },
                )

            st.progress(resultado["prob_phishing"])
            render_result_box(
                "⚠️" if resultado["faixa_risco"] != "legitimo" else "✅",
                resultado["faixa_risco_label"],
                resultado["prob_phishing"],
                resultado["faixa_risco"],
            )

            st.markdown(
                f"""
                <div class='detail-card'>
                    <div class='detail-title'>Detalhes da análise</div>
                    <div class='detail-text'>
                        <b>URL analisada:</b> {url}<br>
                        <b>Classificação final:</b> {resultado["faixa_risco_label"]}<br>
                        <b>Nível de risco:</b> {resultado["nivel_risco"]}<br>
                        <b>Probabilidade de phishing:</b> {resultado["prob_phishing"]:.4f}<br>
                        <b>Modo usado:</b> {resultado["modo_final"]}<br>
                        <b>Fallback:</b> {"sim" if resultado["usou_fallback"] else "não"}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("### Razões principais")
            for razao in resultado["explicacao"]["principais_razoes"][:4]:
                st.markdown(f"- {razao}")

            st.markdown("### Resumo")
            st.write(resultado["explicacao"]["resumo"])

            st.markdown(
                """
                <div class='tip-box'>
                    Dica: se a URL vier sem <b>http://</b> ou <b>https://</b>, o sistema tenta analisar usando <b>https://</b> automaticamente.
                </div>
                """,
                unsafe_allow_html=True
            )

    recentes_url = read_recent_logs("url", limit=8)
    if recentes_url:
        col_hist_url, col_clear_url = st.columns([4, 1])
        with col_hist_url:
            st.markdown("### Histórico recente de URL")
        with col_clear_url:
            if st.button("Limpar", key="limpar_historico_url"):
                clear_analysis_logs("url")
                st.rerun()
        for item in reversed(recentes_url):
            st.markdown(f"- {format_recent_url(item)}")

with aba_email:
    st.caption("Fluxo rápido: nome exibido, remetente, assunto e link principal já cobrem boa parte dos casos de spoofing.")
    st.info("Campos essenciais: nome exibido, remetente, assunto e link principal. Campos avançados: corpo, cabeçalhos e sinais extras para reforçar a análise.")

    with st.form("form_analise_email", clear_on_submit=False):
        display_name = st.text_input("Nome exibido do remetente", placeholder="Ex.: Microsoft")
        sender_email = st.text_input("Email do remetente", placeholder="Ex.: mr@timelesstriathlon.com")
        subject = st.text_input("Assunto", placeholder="Ex.: Service Agreement Update")
        button_url = st.text_input(
            "URL do botão ou link principal",
            placeholder="Ex.: https://exemplo.com/review-account"
        )
        with st.expander("Análise avançada", expanded=False):
            st.caption("Reforço opcional: use só quando quiser acrescentar contexto ou validar cabeçalhos.")
            body_excerpt = st.text_area(
                "Trecho do corpo do email",
                placeholder="Cole aqui um trecho visível do email, especialmente a parte com pedido de ação."
            )
            raw_headers = st.text_area(
                "Cabeçalhos brutos do email",
                placeholder="Cole aqui os cabeçalhos completos quando quiser validar Reply-To, Return-Path, SPF, DKIM e DMARC."
            )
            col1, col2 = st.columns(2)
            with col1:
                attachments_blocked = st.checkbox("Anexos bloqueados pelo provedor")
            with col2:
                marked_as_junk = st.checkbox("Mensagem marcada como lixo eletrônico")

        submitted_email = st.form_submit_button("Analisar Email")

    if submitted_email:
        if not sender_email.strip() and not display_name.strip() and not subject.strip():
            st.warning("Preencha pelo menos remetente, nome exibido ou assunto para analisar o email.")
        else:
            with st.spinner("Analisando contexto do email..."):
                resultado_email = analyze_email(
                    display_name=display_name,
                    sender_email=sender_email,
                    subject=subject,
                    body_excerpt=body_excerpt,
                    button_url=button_url,
                    raw_headers=raw_headers,
                    attachments_blocked=attachments_blocked,
                    marked_as_junk=marked_as_junk,
                )
                append_analysis_log(
                    "email",
                    {
                        "analysis_type": "email",
                        "input": {
                            "display_name": display_name,
                            "sender_email": sender_email,
                            "subject": subject,
                            "button_url": button_url,
                            "attachments_blocked": attachments_blocked,
                            "marked_as_junk": marked_as_junk,
                            "has_raw_headers": bool(raw_headers.strip()),
                        },
                        "result": {
                            "faixa_risco": resultado_email["faixa_risco"],
                            "faixa_risco_label": resultado_email["faixa_risco_label"],
                            "nivel_risco": resultado_email["nivel_risco"],
                            "score_email": resultado_email["score_email"],
                            "claimed_brand": resultado_email["claimed_brand"],
                            "sender_domain": resultado_email["sender_domain"],
                            "reasons": resultado_email["reasons"],
                        },
                    },
                )

            st.progress(resultado_email["score_email"])
            render_result_box(
                "⚠️" if resultado_email["faixa_risco"] != "legitimo" else "✅",
                resultado_email["faixa_risco_label"],
                resultado_email["score_email"],
                resultado_email["faixa_risco"],
            )

            marca = resultado_email["claimed_brand"] or "não identificada"
            dominio = resultado_email["sender_domain"] or "não identificado"

            st.markdown(
                f"""
                <div class='detail-card'>
                    <div class='detail-title'>Detalhes do email</div>
                    <div class='detail-text'>
                        <b>Marca alegada:</b> {marca}<br>
                        <b>Domínio do remetente:</b> {dominio}<br>
                        <b>Classificação final:</b> {resultado_email["faixa_risco_label"]}<br>
                        <b>Nível de risco:</b> {resultado_email["nivel_risco"]}<br>
                        <b>Score do email:</b> {resultado_email["score_email"]:.4f}<br>
                        <b>Anexos bloqueados:</b> {"sim" if resultado_email["attachments_blocked"] else "não"}<br>
                        <b>Marcado como junk:</b> {"sim" if resultado_email["marked_as_junk"] else "não"}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("### Sinais encontrados no email")
            for razao in resultado_email["reasons"]:
                st.markdown(f"- {razao}")

            if resultado_email["trust_signals"]:
                st.markdown("### Sinais de confiança")
                for sinal in resultado_email["trust_signals"]:
                    st.markdown(f"- {sinal}")

            if resultado_email["header_analysis"]:
                st.markdown("### Análise de cabeçalhos")
                header_result = resultado_email["header_analysis"]
                st.markdown(f"- Score dos cabeçalhos: {header_result['score']:.2%}")
                for finding in header_result["findings"]:
                    st.markdown(f"- {finding}")
                if header_result["trust_signals"]:
                    st.markdown("#### Sinais positivos dos cabeçalhos")
                    for sinal in header_result["trust_signals"]:
                        st.markdown(f"- {sinal}")

            if resultado_email["url_analysis"]:
                url_result = resultado_email["url_analysis"]
                st.markdown("### Resultado da URL do botão")
                st.markdown(
                    f"- Classificação da URL: {url_result['faixa_risco_label']}"
                )
                st.markdown(
                    f"- Probabilidade de phishing da URL: {url_result['prob_phishing']:.2%}"
                )
                for razao in url_result["explicacao"]["principais_razoes"][:3]:
                    st.markdown(f"- {razao}")

            st.markdown("### Resumo")
            st.write(resultado_email["summary"])

            st.markdown(
                """
                <div class='tip-box'>
                    Dica: um domínio pode parecer legítimo isoladamente, mas o email ainda pode ser golpe por spoofing de marca, urgência artificial ou anexos maliciosos.
                </div>
                """,
                unsafe_allow_html=True
            )

    recentes_email = read_recent_logs("email", limit=8)
    if recentes_email:
        col_hist_email, col_clear_email = st.columns([4, 1])
        with col_hist_email:
            st.markdown("### Histórico recente de email")
        with col_clear_email:
            if st.button("Limpar", key="limpar_historico_email"):
                clear_analysis_logs("email")
                st.rerun()
        for item in reversed(recentes_email):
            st.markdown(f"- {format_recent_email(item)}")

st.markdown("</div>", unsafe_allow_html=True)
