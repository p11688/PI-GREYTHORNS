"""
Projeto Integrador — Cibersegurança em Programação Segura (PUC-Campinas)
Entrega 2 — Protótipo Inicial e Plano de Testes (Atividade de Extensão)
Parceira: GreyThorns (https://greythorns.myshopify.com/)

Módulo: src/auditor_extensao.py
Descrição:
    Implementa o protótipo inicial da Atividade de Extensão, composto por dois
    componentes principais:
    1) AuditorVitrineShopify: realiza inspeção estritamente passiva (somente GET)
       sobre a vitrine pública da loja na plataforma Shopify, verificando HTTPS,
       validade e emissor do certificado TLS, cabeçalhos HTTP de segurança (E5) e
       inventariando scripts externos e formulários no HTML do tema (E4).
    2) ConsolidadorDiagnosticoExtensao: valida o checklist administrativo e de
       conformidade LGPD (E1, E2, E3 e E6) preenchido em JSON e consolida os
       achados por grau de severidade para apoiar o relatório técnico (E7).
"""

import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

# URL oficial da loja parceira autorizada formalmente na Entrega 1
ALVO_GREYTHORNS = "https://greythorns.myshopify.com/"


class _ExtratorHTMLVitrine(HTMLParser):
    """
    Parser HTML baseado na biblioteca padrão do Python (html.parser).
    Percorre o documento público da vitrine sem executar JavaScript,
    coletando apenas metadados estáticos de tags <script> e <form>.
    """

    def __init__(self):
        super().__init__()
        self.scripts: list[dict] = []
        self.formularios: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        # Converte a lista de tuplas (atributo, valor) em dicionário para consulta rápida
        mapa = dict(attrs)
        tag_lower = tag.lower()

        # Captura apenas scripts carregados via URL externa (atributo src presente)
        if tag_lower == "script" and mapa.get("src"):
            self.scripts.append({
                "src": mapa["src"].strip(),
                "integrity": mapa.get("integrity"),  # Hash SRI (Subresource Integrity)
                "async": "async" in mapa,
                "defer": "defer" in mapa,
            })

        # Captura formulários HTML para verificar se o destino (action) usa HTTPS
        elif tag_lower == "form":
            self.formularios.append({
                "action": (mapa.get("action") or "").strip(),
                "method": (mapa.get("method") or "GET").upper(),
            })


class AuditorVitrineShopify:
    """
    Executa verificações passivas externas sobre a loja da GreyThorns,
    cobrindo os requisitos E4 (revisão de scripts de terceiros no tema)
    e E5 (HTTPS, certificado TLS e cabeçalhos de segurança HTTP).
    """

    # Domínios nativos da infraestrutura Shopify (considerados confiáveis da plataforma)
    DOMINIOS_NATIVOS_SHOPIFY = (
        "cdn.shopify.com",
        "shopifycloud.com",
        "greythorns.myshopify.com",
    )

    # Cabeçalhos HTTP recomendados para proteção contra clickjacking, MIME sniffing e XSS
    CABECALHOS_SEGURANCA = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    @staticmethod
    def validar_url(url: str) -> str:
        """
        Valida a URL informada antes de qualquer operação de rede.
        Garante que apenas os protocolos HTTP ou HTTPS sejam aceitos,
        prevenindo uso indevido de esquemas como file:// ou ftp://.
        """
        url_limpa = url.strip()
        parsed = urlparse(url_limpa)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or "." not in parsed.hostname:
            raise ValueError(f"URL inválida para auditoria passiva: {url}")
        return url_limpa

    @classmethod
    def avaliar_cabecalhos(cls, headers: dict[str, str]) -> dict:
        """
        Compara os cabeçalhos HTTP retornados pelo servidor com a lista de
        cabeçalhos de segurança esperados (case-insensitive).
        """
        normalizados = {k.lower(): v for k, v in headers.items()}
        presentes = [h for h in cls.CABECALHOS_SEGURANCA if h.lower() in normalizados]
        ausentes = [h for h in cls.CABECALHOS_SEGURANCA if h.lower() not in normalizados]
        return {
            "status": "CONFORME" if not ausentes else "ALERTA",
            "presentes": presentes,
            "ausentes": ausentes,
        }

    @staticmethod
    def verificar_certificado_tls(hostname: str, porta: int = 443) -> dict:
        """
        Estabelece handshake TLS padrão para inspecionar o certificado digital
        do domínio: versão do protocolo, entidade emissora e dias até a expiração.
        """
        contexto = ssl.create_default_context()
        with socket.create_connection((hostname, porta), timeout=10) as sock:
            with contexto.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                versao_tls = ssock.version()

        # Converte a data de validade do certificado (formato ASN.1/GMT) para UTC
        expira_em = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        dias_restantes = (expira_em - datetime.now(timezone.utc)).days
        emissor = dict(item[0] for item in cert.get("issuer", []))

        return {
            "valido": dias_restantes > 0,
            "versao_tls": versao_tls,
            "emissor": emissor.get("organizationName", "Desconhecido"),
            "expira_em": expira_em.strftime("%Y-%m-%d"),
            "dias_restantes": dias_restantes,
        }

    @classmethod
    def analisar_html_tema(cls, html: str) -> dict:
        """
        Analisa o código HTML da vitrine para separar scripts nativos da Shopify
        de scripts carregados a partir de domínios de terceiros (aplicativos/pixels),
        sinalizando ausência de HTTPS ou de Subresource Integrity (SRI).
        """
        parser = _ExtratorHTMLVitrine()
        parser.feed(html)

        nativos = []
        terceiros = []
        achados = []

        for script in parser.scripts:
            src = script["src"]
            # Normaliza URLs protocol-relative (ex.: //cdn.shopify.com/...)
            url_norm = f"https:{src}" if src.startswith("//") else src
            parsed = urlparse(url_norm)
            host = (parsed.hostname or "").lower()

            # Regra 1: Carregamento de script via HTTP puro expõe o cliente a MITM
            if parsed.scheme == "http":
                achados.append({
                    "codigo": "E4",
                    "severidade": "ALTA",
                    "titulo": f"Script carregado sem criptografia (HTTP): {src}",
                    "recomendacao": "Alterar a referência no tema Liquid para HTTPS.",
                })

            # Regra 2: Classifica entre CDN nativa Shopify e domínio externo de terceiro
            if any(host == dom or host.endswith(f".{dom}") for dom in cls.DOMINIOS_NATIVOS_SHOPIFY):
                nativos.append(url_norm)
            else:
                terceiros.append(url_norm)
                # Scripts externos sem atributo integrity não validam alteração no arquivo remoto
                if not script["integrity"]:
                    achados.append({
                        "codigo": "E4",
                        "severidade": "MEDIA",
                        "titulo": f"Script de terceiro sem Subresource Integrity (SRI): {url_norm}",
                        "recomendacao": "Revisar se o app/rastreador é necessário e aplicar atributo integrity quando suportado.",
                    })

        # Regra 3: Verifica se algum formulário envia dados via HTTP não cifrado
        for form in parser.formularios:
            if form["action"].startswith("http://"):
                achados.append({
                    "codigo": "E4",
                    "severidade": "ALTA",
                    "titulo": f"Formulário enviando dados via HTTP inseguro: {form['action']}",
                    "recomendacao": "Garantir envio exclusivo via HTTPS.",
                })

        return {
            "total_scripts_externos": len(parser.scripts),
            "scripts_nativos_shopify": nativos,
            "scripts_terceiros": terceiros,
            "total_formularios": len(parser.formularios),
            "achados_tema": achados,
        }

    def executar_auditoria_passiva(self, url: str = ALVO_GREYTHORNS) -> dict:
        """
        Orquestra a coleta passiva via requisição HTTP GET única sobre a loja,
        sem realizar varreduras intrusivas, testes de carga ou alterações de estado.
        """
        url_valida = self.validar_url(url)
        parsed = urlparse(url_valida)

        req = urllib.request.Request(
            url_valida,
            method="GET",
            headers={"User-Agent": "PUC-Campinas-GreyThorns-Extensao/0.1 (Passive-Audit)"},
        )

        try:
            # Esquema validado previamente em validar_url() como http/https
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
                status_http = resp.status
                url_final = resp.geturl()
                headers = dict(resp.headers.items())
                html = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as err:
            # Caso a loja esteja protegida por senha de vitrine (HTTP 401/403),
            # ainda é possível auditar os cabeçalhos HTTP e o certificado TLS.
            status_http = err.code
            url_final = err.geturl()
            headers = dict(err.headers.items()) if err.headers else {}
            html = err.read().decode("utf-8", errors="replace")

        analise_tema = self.analisar_html_tema(html)
        return {
            "alvo": url_valida,
            "url_final": url_final,
            "status_http": status_http,
            "https_ativo": url_final.startswith("https://"),
            "certificado_tls": self.verificar_certificado_tls(parsed.hostname),
            "cabecalhos_http": self.avaliar_cabecalhos(headers),
            "analise_tema": analise_tema,
        }


class ConsolidadorDiagnosticoExtensao:
    """
    Consolida os itens do checklist administrativo/LGPD (E1, E2, E3 e E6)
    com os resultados da auditoria passiva da vitrine (E4 e E5), gerando
    o pré-relatório estruturado do requisito E7.
    """

    CAMPOS_OBRIGATORIOS = {"empresa", "dominio", "itens"}

    @classmethod
    def consolidar(cls, checklist: dict, resultado_vitrine: dict | None = None) -> dict:
        """
        Valida a estrutura do dicionário de checklist e filtra os itens marcados
        como NAO_CONFORME para compor a lista priorizada de recomendações.
        """
        if not isinstance(checklist, dict) or not cls.CAMPOS_OBRIGATORIOS.issubset(checklist.keys()):
            faltantes = cls.CAMPOS_OBRIGATORIOS - set(
                checklist.keys() if isinstance(checklist, dict) else []
            )
            raise ValueError(f"Checklist inválido. Campos obrigatórios ausentes: {sorted(faltantes)}")

        achados = []
        pendentes = []

        # Processa cada item do checklist administrativo e de privacidade (LGPD)
        for item in checklist["itens"]:
            status = item.get("status", "PENDENTE").upper()
            if status == "NAO_CONFORME":
                achados.append({
                    "codigo": item.get("codigo", "GERAL"),
                    "severidade": item.get("severidade", "MEDIA"),
                    "titulo": item.get("descricao", "Não conformidade no painel"),
                    "recomendacao": item.get("recomendacao", "Corrigir configuração no painel Shopify."),
                })
            elif status == "PENDENTE":
                pendentes.append(item.get("codigo", "GERAL"))

        # Incorpora achados técnicos coletados automaticamente na vitrine pública
        if resultado_vitrine:
            achados.extend(resultado_vitrine.get("analise_tema", {}).get("achados_tema", []))
            for cab_ausente in resultado_vitrine.get("cabecalhos_http", {}).get("ausentes", []):
                achados.append({
                    "codigo": "E5",
                    "severidade": "BAIXA",
                    "titulo": f"Cabeçalho de segurança ausente na resposta HTTP: {cab_ausente}",
                    "recomendacao": "Avaliar configuração via proxy/CDN ou políticas disponíveis na plataforma.",
                })

        return {
            "empresa": checklist["empresa"],
            "dominio": checklist["dominio"],
            "gerado_em": datetime.now(timezone.utc).isoformat(),
            "itens_painel_pendentes": pendentes,
            "total_achados": len(achados),
            "achados": achados,
        }


if __name__ == "__main__":
    # Localiza o arquivo data/checklist_greythorns.json relativamente à raiz do projeto
    base_dir = Path(__file__).resolve().parent.parent
    caminho_checklist = base_dir / "data" / "checklist_greythorns.json"

    with caminho_checklist.open("r", encoding="utf-8") as arq:
        checklist_loja = json.load(arq)

    # Executa a auditoria passiva sobre https://greythorns.myshopify.com/ e consolida o diagnóstico
    auditor = AuditorVitrineShopify()
    resultado_web = auditor.executar_auditoria_passiva(ALVO_GREYTHORNS)
    diagnostico = ConsolidadorDiagnosticoExtensao.consolidar(checklist_loja, resultado_web)

    print("=== AUDITORIA PASSIVA DA VITRINE (E4 / E5) ===")
    print(json.dumps(resultado_web, indent=2, ensure_ascii=False))
    print("\n=== DIAGNÓSTICO CONSOLIDADO (E7) ===")
    print(json.dumps(diagnostico, indent=2, ensure_ascii=False))