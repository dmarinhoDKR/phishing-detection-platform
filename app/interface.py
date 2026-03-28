import json
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.detector_phishing_v2 import check_url_detailed
from src.analysis_logging import append_analysis_log, read_recent_logs
from src.email_analysis import analyze_email


CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

tema_escuro = False
historico_urls = []
historico_emails = []
analise_email_avancada = None


def salvar_config():
    config = {"tema_escuro": tema_escuro}
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def carregar_config():
    global tema_escuro
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
                tema_escuro = config.get("tema_escuro", False)
        except Exception:
            tema_escuro = False


def normalizar_url(url: str) -> str:
    url = url.strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def obter_cores_status(faixa_risco):
    if faixa_risco == "phishing":
        return {
            "texto": "#b00020",
            "fundo": "#fdecef",
            "borda": "#f2b8c0",
            "icone": "⚠"
        }
    if faixa_risco == "suspeito":
        return {
            "texto": "#b45309",
            "fundo": "#fff7ed",
            "borda": "#fdba74",
            "icone": "!"
        }
    return {
        "texto": "#0a7d32",
        "fundo": "#ecfdf3",
        "borda": "#86efac",
        "icone": "✓"
    }


def atualizar_historico():
    lista_historico.delete(0, tk.END)
    itens = historico_emails if modo_analise.get() == "email" else historico_urls
    for item in itens[-10:][::-1]:
        lista_historico.insert(tk.END, item)


def adicionar_ao_historico(url):
    if not url:
        return
    if url in historico_urls:
        historico_urls.remove(url)
    historico_urls.append(url)
    atualizar_historico()


def adicionar_email_ao_historico(email_label):
    if not email_label:
        return
    if email_label in historico_emails:
        historico_emails.remove(email_label)
    historico_emails.append(email_label)
    atualizar_historico()


def limpar_historico():
    if modo_analise.get() == "email":
        historico_emails.clear()
    else:
        historico_urls.clear()
    atualizar_historico()


def usar_item_historico(event=None):
    selecao = lista_historico.curselection()
    if not selecao:
        return

    item = lista_historico.get(selecao[0])
    if modo_analise.get() == "email":
        entrada_email_remetente.delete(0, tk.END)
        entrada_email_remetente.insert(0, item)
        entrada_email_remetente.focus()
        entrada_email_remetente.select_range(0, tk.END)
    else:
        entrada_url.delete(0, tk.END)
        entrada_url.insert(0, item)
        entrada_url.focus()
        entrada_url.select_range(0, tk.END)


def selecionar_tudo_url(event=None):
    entrada_url.after(10, lambda: entrada_url.select_range(0, tk.END))


def limpar_card():
    label_status.config(text="", fg=cor_texto, bg=cor_card)
    label_detalhes.config(text="", fg=cor_texto_secundario_card, bg=cor_card)
    card_resultado.pack_forget()


def limpar_campos(event=None):
    for widget in (
        entrada_url,
        entrada_nome_remetente,
        entrada_email_remetente,
        entrada_assunto,
        entrada_link_principal,
    ):
        widget.delete(0, tk.END)

    texto_corpo_email.delete("1.0", tk.END)
    texto_cabecalhos.delete("1.0", tk.END)
    anexos_bloqueados_var.set(False)
    lixo_eletronico_var.set(False)
    analise_email_avancada.set(False)
    atualizar_email_avancado()
    limpar_card()

    if modo_analise.get() == "url":
        entrada_url.focus()
        entrada_url.select_range(0, tk.END)
    else:
        entrada_nome_remetente.focus()
        entrada_nome_remetente.select_range(0, tk.END)
    return "break"


def alternar_tema():
    global tema_escuro
    tema_escuro = not tema_escuro
    aplicar_tema()
    salvar_config()


def atualizar_modo_analise():
    modo = modo_analise.get()
    if modo == "email":
        frame_url.pack_forget()
        frame_email.pack(fill="x", padx=40, pady=(10, 14))
        atualizar_email_avancado()
        botao_verificar.config(text="Analisar Email")
        subtitulo.config(
            text="Analise URLs ou emails suspeitos com score de risco, spoofing e sinais principais."
        )
        label_historico.config(text="Histórico recente de emails analisados")
        atualizar_historico()
    else:
        frame_email.pack_forget()
        frame_url.pack(fill="x", padx=40, pady=(20, 14))
        botao_verificar.config(text="Verificar URL")
        subtitulo.config(
            text="Analise URLs ou emails suspeitos com score de risco, spoofing e sinais principais."
        )
        label_historico.config(text="Histórico das últimas URLs analisadas")
        atualizar_historico()


def atualizar_email_avancado():
    if modo_analise.get() != "email":
        return
    if analise_email_avancada.get():
        frame_email_avancado.pack(fill="x", pady=(10, 0))
        check_avancado.config(text="Ocultar análise avançada")
    else:
        frame_email_avancado.pack_forget()
        check_avancado.config(text="Mostrar análise avançada")


def iniciar_verificacao(event=None):
    modo = modo_analise.get()

    if modo == "email":
        payload = coletar_dados_email()
        if not payload:
            mostrar_card(
                "Preencha dados do email.",
                "Informe pelo menos nome exibido, remetente ou assunto para iniciar a análise.",
                "#b00020",
                cor_card,
                cor_card_borda
            )
            return "break"

        botao_verificar.config(state="disabled", text="Analisando...")
        progress_ind.start(10)
        adicionar_email_ao_historico(payload["sender_email"] or payload["display_name"] or payload["subject"])

        mostrar_card(
            "Analisando email...",
            "Verificando spoofing, urgência, contexto suspeito e link principal.",
            cor_info,
            cor_card,
            cor_card_borda
        )

        thread = threading.Thread(target=verificar_email_em_background, args=(payload,), daemon=True)
        thread.start()
        return "break"

    url = entrada_url.get().strip()
    if not url:
        mostrar_card(
            "Digite uma URL para análise.",
            "Cole ou digite uma URL válida para iniciar a verificação.",
            "#b00020",
            cor_card,
            cor_card_borda
        )
        return "break"

    url = normalizar_url(url)
    adicionar_ao_historico(url)

    botao_verificar.config(state="disabled", text="Analisando...")
    progress_ind.start(10)

    mostrar_card(
        "Analisando URL...",
        "Consultando estrutura, padrão lexical e sinais adicionais.",
        cor_info,
        cor_card,
        cor_card_borda
    )

    thread = threading.Thread(target=verificar_url_em_background, args=(url,), daemon=True)
    thread.start()
    return "break"


def coletar_dados_email():
    payload = {
        "display_name": entrada_nome_remetente.get().strip(),
        "sender_email": entrada_email_remetente.get().strip(),
        "subject": entrada_assunto.get().strip(),
        "body_excerpt": texto_corpo_email.get("1.0", tk.END).strip() if analise_email_avancada.get() else "",
        "raw_headers": texto_cabecalhos.get("1.0", tk.END).strip() if analise_email_avancada.get() else "",
        "button_url": normalizar_url(entrada_link_principal.get().strip()),
        "attachments_blocked": anexos_bloqueados_var.get() if analise_email_avancada.get() else False,
        "marked_as_junk": lixo_eletronico_var.get() if analise_email_avancada.get() else False,
    }

    if any([payload["display_name"], payload["sender_email"], payload["subject"], payload["body_excerpt"], payload["button_url"]]):
        return payload
    return None


def verificar_url_em_background(url):
    try:
        resultado = check_url_detailed(url)
        janela.after(0, lambda: mostrar_resultado_url(resultado))
    except Exception as exc:
        janela.after(0, lambda: mostrar_erro(str(exc), "URL"))


def verificar_email_em_background(payload):
    try:
        resultado = analyze_email(**payload)
        janela.after(0, lambda: mostrar_resultado_email(resultado))
    except Exception as exc:
        janela.after(0, lambda: mostrar_erro(str(exc), "email"))


def mostrar_card(status, detalhes, cor_texto_status, fundo, borda):
    card_resultado.config(bg=fundo, highlightbackground=borda, highlightcolor=borda)
    label_status.config(text=status, fg=cor_texto_status, bg=fundo)
    label_detalhes.config(text=detalhes, fg=cor_texto_secundario_card, bg=fundo)

    if not card_resultado.winfo_ismapped():
        card_resultado.pack(fill="x", padx=40, pady=(8, 18))


def mostrar_resultado_url(resultado):
    progress_ind.stop()
    botao_verificar.config(state="normal", text="Verificar URL")
    append_analysis_log(
        "url",
        {
            "analysis_type": "url",
            "input": {"url": entrada_url.get().strip()},
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

    faixa_risco = resultado["faixa_risco"]
    cores = obter_cores_status(faixa_risco)
    status = f"{cores['icone']} {resultado['faixa_risco_label']}"

    razoes = resultado["explicacao"]["principais_razoes"][:3]
    razoes_texto = "\n".join(f"- {razao}" for razao in razoes) if razoes else "- Sem razões destacadas"

    detalhes = (
        f"Classificação final: {resultado['faixa_risco_label']}\n"
        f"Nível de risco: {resultado['nivel_risco']}\n"
        f"Probabilidade de phishing: {resultado['prob_phishing']:.2%}\n"
        f"Modo usado: {resultado['modo_final']}\n"
        f"Fallback: {'sim' if resultado['usou_fallback'] else 'não'}\n\n"
        f"Razões principais:\n{razoes_texto}"
    )

    mostrar_card(status, detalhes, cores["texto"], cores["fundo"], cores["borda"])


def mostrar_resultado_email(resultado):
    progress_ind.stop()
    botao_verificar.config(state="normal", text="Analisar Email")
    append_analysis_log(
        "email",
        {
            "analysis_type": "email",
            "input": {
                "display_name": entrada_nome_remetente.get().strip(),
                "sender_email": entrada_email_remetente.get().strip(),
                "subject": entrada_assunto.get().strip(),
                "button_url": entrada_link_principal.get().strip(),
                "attachments_blocked": anexos_bloqueados_var.get(),
                "marked_as_junk": lixo_eletronico_var.get(),
                "has_raw_headers": bool(texto_cabecalhos.get("1.0", tk.END).strip()),
            },
            "result": {
                "faixa_risco": resultado["faixa_risco"],
                "faixa_risco_label": resultado["faixa_risco_label"],
                "nivel_risco": resultado["nivel_risco"],
                "score_email": resultado["score_email"],
                "claimed_brand": resultado["claimed_brand"],
                "sender_domain": resultado["sender_domain"],
                "reasons": resultado["reasons"][:4],
            },
        },
    )

    faixa_risco = resultado["faixa_risco"]
    cores = obter_cores_status(faixa_risco)
    status = f"{cores['icone']} {resultado['faixa_risco_label']}"

    razoes = resultado["reasons"][:4]
    razoes_texto = "\n".join(f"- {razao}" for razao in razoes) if razoes else "- Sem sinais fortes de spoofing detectados"

    detalhes = (
        f"Marca alegada: {resultado['claimed_brand'] or 'não identificada'}\n"
        f"Domínio do remetente: {resultado['sender_domain'] or 'não identificado'}\n"
        f"Classificação final: {resultado['faixa_risco_label']}\n"
        f"Nível de risco: {resultado['nivel_risco']}\n"
        f"Score do email: {resultado['score_email']:.2%}\n"
        f"Anexos bloqueados: {'sim' if resultado['attachments_blocked'] else 'não'}\n"
        f"Marcado como junk: {'sim' if resultado['marked_as_junk'] else 'não'}\n\n"
        f"Sinais encontrados:\n{razoes_texto}"
    )

    if resultado["url_analysis"]:
        detalhes += (
            f"\n\nResultado da URL do botão:\n"
            f"- {resultado['url_analysis']['faixa_risco_label']} ({resultado['url_analysis']['prob_phishing']:.2%})"
        )
    if resultado["header_analysis"]:
        header_info = resultado["header_analysis"]
        achados = "\n".join(f"- {item}" for item in header_info["findings"][:3]) or "- Sem achados relevantes"
        detalhes += (
            f"\n\nAnálise de cabeçalhos:\n"
            f"Score dos cabeçalhos: {header_info['score']:.2%}\n"
            f"{achados}"
        )

    mostrar_card(status, detalhes, cores["texto"], cores["fundo"], cores["borda"])


def mostrar_erro(mensagem, tipo):
    progress_ind.stop()
    botao_verificar.config(state="normal", text="Analisar Email" if tipo == "email" else "Verificar URL")
    mostrar_card(
        f"⚠ Erro ao analisar o {tipo}",
        mensagem,
        "#b00020",
        "#fdecef",
        "#f2b8c0"
    )


def aplicar_tema():
    global cor_janela, cor_container, cor_card, cor_card_borda
    global cor_texto, cor_subtexto, cor_input_bg, cor_lista_bg
    global cor_info, cor_texto_secundario_card, cor_frame_borda

    if tema_escuro:
        cor_janela = "#071224"
        cor_container = "#0b1730"
        cor_card = "#0f1b34"
        cor_card_borda = "#1e3a5f"
        cor_texto = "#f8fafc"
        cor_subtexto = "#9fb0c9"
        cor_input_bg = "#08101f"
        cor_lista_bg = "#08101f"
        cor_info = "#60a5fa"
        cor_texto_secundario_card = "#44556f"
        cor_frame_borda = "#20304d"
    else:
        cor_janela = "#eef2f7"
        cor_container = "#ffffff"
        cor_card = "#ffffff"
        cor_card_borda = "#dbe4f0"
        cor_texto = "#0f172a"
        cor_subtexto = "#475569"
        cor_input_bg = "#ffffff"
        cor_lista_bg = "#ffffff"
        cor_info = "#2563eb"
        cor_texto_secundario_card = "#334155"
        cor_frame_borda = "#dbe4f0"

    janela.configure(bg=cor_janela)
    container.configure(bg=cor_container)
    topo.configure(bg=cor_container)
    frame_modo.configure(bg=cor_container)
    frame_url.configure(bg=cor_container, highlightbackground=cor_frame_borda, highlightcolor=cor_frame_borda)
    frame_email.configure(bg=cor_container, highlightbackground=cor_frame_borda, highlightcolor=cor_frame_borda)
    frame_email_avancado.configure(bg=cor_container)
    frame_email_checks.configure(bg=cor_container)
    frame_botoes.configure(bg=cor_container)
    frame_historico.configure(bg=cor_container)

    for widget in (
        titulo,
        subtitulo,
        label_url,
        label_nome_remetente,
        label_email_remetente,
        label_assunto,
        label_email_ajuda,
        label_corpo_email,
        label_link_principal,
        label_cabecalhos,
        label_historico,
    ):
        widget.config(bg=cor_container, fg=cor_texto if widget is not subtitulo else cor_subtexto)

    for radio in (radio_url, radio_email):
        radio.config(
            bg=cor_container,
            fg=cor_texto,
            selectcolor=cor_input_bg,
            activebackground=cor_container,
            activeforeground=cor_texto,
        )

    for checkbox in (check_avancado, check_anexos, check_junk):
        checkbox.config(
            bg=cor_container,
            fg=cor_texto,
            selectcolor=cor_input_bg,
            activebackground=cor_container,
            activeforeground=cor_texto,
        )

    for entry in (
        entrada_url,
        entrada_nome_remetente,
        entrada_email_remetente,
        entrada_assunto,
        entrada_link_principal,
    ):
        entry.config(
            bg=cor_input_bg,
            fg=cor_texto,
            insertbackground=cor_texto,
            relief="flat",
            highlightthickness=1,
            highlightbackground="#3b82f6",
            highlightcolor="#3b82f6"
        )

    texto_corpo_email.config(
        bg=cor_input_bg,
        fg=cor_texto,
        insertbackground=cor_texto,
        relief="flat",
        highlightthickness=1,
        highlightbackground="#3b82f6",
        highlightcolor="#3b82f6"
    )
    texto_cabecalhos.config(
        bg=cor_input_bg,
        fg=cor_texto,
        insertbackground=cor_texto,
        relief="flat",
        highlightthickness=1,
        highlightbackground="#3b82f6",
        highlightcolor="#3b82f6"
    )

    lista_historico.config(
        bg=cor_lista_bg,
        fg=cor_texto,
        selectbackground="#2563eb",
        selectforeground="white",
        highlightbackground="#64748b"
    )

    estilo_botao(botao_verificar, "#2563eb")
    estilo_botao(botao_limpar, "#64748b")
    estilo_botao(botao_limpar_historico, "#c1121f")
    estilo_botao(botao_tema, "#334155")

    if card_resultado.winfo_ismapped():
        card_resultado.config(bg=cor_card, highlightbackground=cor_card_borda, highlightcolor=cor_card_borda)
        label_status.config(bg=cor_card)
        label_detalhes.config(bg=cor_card)


def estilo_botao(botao, cor):
    botao.config(
        bg=cor,
        fg="white",
        activebackground=cor,
        activeforeground="white",
        relief="flat",
        bd=0
    )


carregar_config()
historico_urls = [
    item.get("input", {}).get("url", "")
    for item in read_recent_logs("url", limit=20)
    if item.get("input", {}).get("url", "")
]
historico_emails = [
    item.get("input", {}).get("sender_email", "") or item.get("input", {}).get("display_name", "")
    for item in read_recent_logs("email", limit=20)
    if item.get("input", {}).get("sender_email", "") or item.get("input", {}).get("display_name", "")
]

janela = tk.Tk()
janela.title("Detector de Phishing")
janela.geometry("1040x980")
janela.minsize(1040, 980)
janela.resizable(True, True)

container = tk.Frame(janela, bd=0, relief="flat")
container.place(relx=0.5, rely=0.5, anchor="center", width=980, height=930)

topo = tk.Frame(container, bd=0, relief="flat")
topo.pack(fill="x", pady=(26, 10))

titulo = tk.Label(topo, text="Detector de Phishing", font=("Segoe UI", 24, "bold"))
titulo.pack()

subtitulo = tk.Label(
    topo,
    text="Analise URLs ou emails suspeitos com foco em sinais essenciais e reforços opcionais.",
    font=("Segoe UI", 11)
)
subtitulo.pack(pady=(8, 0))

modo_analise = tk.StringVar(value="url")

frame_modo = tk.Frame(container)
frame_modo.pack(pady=(18, 8))

radio_url = tk.Radiobutton(
    frame_modo,
    text="Análise de URL",
    variable=modo_analise,
    value="url",
    command=atualizar_modo_analise,
    font=("Segoe UI", 10, "bold")
)
radio_url.grid(row=0, column=0, padx=12)

radio_email = tk.Radiobutton(
    frame_modo,
    text="Análise de Email",
    variable=modo_analise,
    value="email",
    command=atualizar_modo_analise,
    font=("Segoe UI", 10, "bold")
)
radio_email.grid(row=0, column=1, padx=12)

frame_url = tk.Frame(container, bd=0, relief="flat", highlightthickness=1)
label_url = tk.Label(frame_url, text="URL")
label_url.pack(anchor="w", pady=(0, 6))
entrada_url = tk.Entry(frame_url, width=72, font=("Segoe UI", 13))
entrada_url.pack(ipady=12, fill="x")

frame_email = tk.Frame(container, bd=0, relief="flat", highlightthickness=1)

label_nome_remetente = tk.Label(frame_email, text="Nome exibido do remetente")
label_nome_remetente.pack(anchor="w", pady=(10, 6))
entrada_nome_remetente = tk.Entry(frame_email, font=("Segoe UI", 11))
entrada_nome_remetente.pack(ipady=8, fill="x")

label_email_remetente = tk.Label(frame_email, text="Email do remetente")
label_email_remetente.pack(anchor="w", pady=(10, 6))
entrada_email_remetente = tk.Entry(frame_email, font=("Segoe UI", 11))
entrada_email_remetente.pack(ipady=8, fill="x")

label_assunto = tk.Label(frame_email, text="Assunto")
label_assunto.pack(anchor="w", pady=(10, 6))
entrada_assunto = tk.Entry(frame_email, font=("Segoe UI", 11))
entrada_assunto.pack(ipady=8, fill="x")

label_link_principal = tk.Label(frame_email, text="URL do botão ou link principal")
label_link_principal.pack(anchor="w", pady=(10, 6))
entrada_link_principal = tk.Entry(frame_email, font=("Segoe UI", 11))
entrada_link_principal.pack(ipady=8, fill="x")

label_email_ajuda = tk.Label(
    frame_email,
    text="Essencial: nome exibido, remetente, assunto e link principal.",
    font=("Segoe UI", 9, "italic")
)
label_email_ajuda.pack(anchor="w", pady=(10, 0))

analise_email_avancada = tk.BooleanVar(value=False)
check_avancado = tk.Checkbutton(
    frame_email,
    text="Mostrar análise avançada (reforço opcional)",
    variable=analise_email_avancada,
    command=atualizar_email_avancado,
    font=("Segoe UI", 10, "bold")
)
check_avancado.pack(anchor="w", pady=(12, 0))

frame_email_avancado = tk.Frame(frame_email)

label_corpo_email = tk.Label(frame_email_avancado, text="Trecho do corpo do email")
label_corpo_email.pack(anchor="w", pady=(0, 6))
texto_corpo_email = tk.Text(frame_email_avancado, height=5, font=("Segoe UI", 10), wrap="word")
texto_corpo_email.pack(fill="x")

label_cabecalhos = tk.Label(frame_email_avancado, text="Cabeçalhos brutos do email")
label_cabecalhos.pack(anchor="w", pady=(10, 6))
texto_cabecalhos = tk.Text(frame_email_avancado, height=5, font=("Segoe UI", 10), wrap="word")
texto_cabecalhos.pack(fill="x")

frame_email_checks = tk.Frame(frame_email_avancado)
frame_email_checks.pack(fill="x", pady=(12, 0))

anexos_bloqueados_var = tk.BooleanVar(value=False)
lixo_eletronico_var = tk.BooleanVar(value=False)

check_anexos = tk.Checkbutton(
    frame_email_checks,
    text="Anexos bloqueados pelo provedor",
    variable=anexos_bloqueados_var,
    font=("Segoe UI", 10)
)
check_anexos.grid(row=0, column=0, sticky="w", padx=(0, 18))

check_junk = tk.Checkbutton(
    frame_email_checks,
    text="Mensagem marcada como lixo eletrônico",
    variable=lixo_eletronico_var,
    font=("Segoe UI", 10)
)
check_junk.grid(row=0, column=1, sticky="w")

frame_botoes = tk.Frame(container)
frame_botoes.pack(pady=(0, 12))

botao_verificar = tk.Button(
    frame_botoes,
    text="Verificar URL",
    command=iniciar_verificacao,
    font=("Segoe UI", 11, "bold"),
    padx=22,
    pady=10,
    cursor="hand2"
)
botao_verificar.grid(row=0, column=0, padx=6)

botao_limpar = tk.Button(
    frame_botoes,
    text="Limpar",
    command=limpar_campos,
    font=("Segoe UI", 10, "bold"),
    padx=18,
    pady=10,
    cursor="hand2"
)
botao_limpar.grid(row=0, column=1, padx=6)

botao_limpar_historico = tk.Button(
    frame_botoes,
    text="Limpar histórico",
    command=limpar_historico,
    font=("Segoe UI", 10, "bold"),
    padx=18,
    pady=10,
    cursor="hand2"
)
botao_limpar_historico.grid(row=0, column=2, padx=6)

botao_tema = tk.Button(
    frame_botoes,
    text="Tema",
    command=alternar_tema,
    font=("Segoe UI", 10, "bold"),
    padx=18,
    pady=10,
    cursor="hand2"
)
botao_tema.grid(row=0, column=3, padx=6)

progress_ind = ttk.Progressbar(container, mode="indeterminate", length=420)
progress_ind.pack(pady=(0, 10))

card_resultado = tk.Frame(
    container,
    bd=0,
    relief="flat",
    highlightthickness=1,
    height=360
)
card_resultado.pack_propagate(False)

label_status = tk.Label(
    card_resultado,
    text="",
    font=("Segoe UI", 16, "bold"),
    justify="center"
)
label_status.pack(pady=(22, 14), padx=24)

label_detalhes = tk.Message(
    card_resultado,
    text="",
    font=("Segoe UI", 11),
    justify="center",
    width=780
)
label_detalhes.pack(fill="x", padx=36, pady=(0, 20))

frame_historico = tk.Frame(container)
frame_historico.pack(side="bottom", fill="x", pady=(10, 20))

label_historico = tk.Label(
    frame_historico,
    text="Histórico das últimas URLs analisadas",
    font=("Segoe UI", 11, "bold")
)
label_historico.pack(anchor="w", padx=6, pady=(0, 8))

lista_historico = tk.Listbox(
    frame_historico,
    width=90,
    height=8,
    font=("Segoe UI", 10),
    relief="solid",
    bd=1
)
lista_historico.pack(fill="x", padx=6)
lista_historico.bind("<Double-Button-1>", usar_item_historico)

entrada_url.bind("<Return>", iniciar_verificacao)
entrada_url.bind("<FocusIn>", selecionar_tudo_url)
janela.bind("<Control-l>", limpar_campos)
janela.bind("<Control-L>", limpar_campos)

aplicar_tema()
atualizar_modo_analise()
entrada_url.focus()
janela.mainloop()
