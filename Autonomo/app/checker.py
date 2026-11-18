"""Verificações passivas sobre o domínio autorizado (A2).

Só faz requisições GET simples e uma conexão TLS: nada intrusivo.
Cada verificação devolve um dicionário: verificacao, status, gravidade, detalhe.
status: ok | atencao | falha | erro      gravidade: info | baixa | media | alta
"""
import os
import re
import socket
import ssl
from datetime import datetime, timezone

import requests

TIMEOUT = 10
USER_AGENT = "GreyThorns-Verificador/1.0 (projeto academico PUC Campinas)"
DOMINIO_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class ErroDominio(ValueError):
    pass


def _res(verificacao, status, gravidade, detalhe):
    return {"verificacao": verificacao, "status": status,
            "gravidade": gravidade, "detalhe": detalhe[:500]}


def validar_dominio(dominio):
    """Aceita só nome de domínio (sem esquema, caminho, porta ou IP).
    Se GT_DOMINIOS_AUTORIZADOS estiver definida, só permite os domínios listados."""
    d = (dominio or "").strip().lower()
    if not DOMINIO_RE.match(d):
        raise ErroDominio("Domínio inválido. Informe só o nome, ex.: loja.exemplo.com.br")
    autorizados = [x.strip().lower()
                   for x in os.environ.get("GT_DOMINIOS_AUTORIZADOS", "").split(",") if x.strip()]
    if autorizados and d not in autorizados:
        raise ErroDominio("Domínio fora da lista de domínios autorizados.")
    return d


# ---------- cabeçalhos HTTP ----------

def analisar_cabecalhos(cabecalhos):
    """Função pura: recebe os cabeçalhos da resposta e avalia os de segurança."""
    h = {str(k).lower(): str(v) for k, v in cabecalhos.items()}
    out = []

    hsts = h.get("strict-transport-security")
    if not hsts:
        out.append(_res("cabecalho:strict-transport-security", "falha", "media",
                        "HSTS ausente: o navegador não é forçado a usar HTTPS."))
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) >= 15552000:
            out.append(_res("cabecalho:strict-transport-security", "ok", "info", "HSTS presente."))
        else:
            out.append(_res("cabecalho:strict-transport-security", "atencao", "baixa",
                            "HSTS com max-age menor que 180 dias."))

    csp = h.get("content-security-policy")
    out.append(_res("cabecalho:content-security-policy", "ok" if csp else "falha",
                    "info" if csp else "media",
                    "CSP presente." if csp else "CSP ausente: sem política contra scripts injetados."))

    nosniff = h.get("x-content-type-options", "").lower() == "nosniff"
    out.append(_res("cabecalho:x-content-type-options", "ok" if nosniff else "falha",
                    "info" if nosniff else "baixa",
                    "nosniff presente." if nosniff else "X-Content-Type-Options: nosniff ausente."))

    frame = "x-frame-options" in h or "frame-ancestors" in (csp or "").lower()
    out.append(_res("cabecalho:x-frame-options", "ok" if frame else "falha",
                    "info" if frame else "baixa",
                    "Proteção contra clickjacking presente." if frame
                    else "Sem X-Frame-Options nem frame-ancestors."))

    ref = "referrer-policy" in h
    out.append(_res("cabecalho:referrer-policy", "ok" if ref else "falha",
                    "info" if ref else "baixa",
                    "Referrer-Policy presente." if ref else "Referrer-Policy ausente."))

    perm = "permissions-policy" in h
    out.append(_res("cabecalho:permissions-policy", "ok" if perm else "falha",
                    "info" if perm else "baixa",
                    "Permissions-Policy presente." if perm else "Permissions-Policy ausente."))
    return out


def _buscar_cabecalhos(url):
    r = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                     headers={"User-Agent": USER_AGENT})
    return dict(r.headers)


def verificar_cabecalhos(dominio, buscar=None):
    buscar = buscar or _buscar_cabecalhos
    try:
        return analisar_cabecalhos(buscar(f"https://{dominio}"))
    except requests.RequestException as exc:
        return [_res("cabecalhos_http", "erro", "media",
                     f"Não foi possível obter os cabeçalhos: {type(exc).__name__}")]


# ---------- redirecionamento HTTP -> HTTPS ----------

def _buscar_redirecionamento(url):
    r = requests.get(url, timeout=TIMEOUT, allow_redirects=False,
                     headers={"User-Agent": USER_AGENT})
    return r.status_code, r.headers.get("Location")


def verificar_redirecionamento_https(dominio, buscar=None):
    buscar = buscar or _buscar_redirecionamento
    try:
        codigo, destino = buscar(f"http://{dominio}")
    except requests.RequestException as exc:
        return [_res("redirecionamento_https", "erro", "media",
                     f"Não foi possível testar o redirecionamento: {type(exc).__name__}")]
    if codigo in (301, 302, 303, 307, 308) and (destino or "").lower().startswith("https://"):
        return [_res("redirecionamento_https", "ok", "info", "HTTP redireciona para HTTPS.")]
    return [_res("redirecionamento_https", "falha", "alta",
                 f"HTTP não redireciona para HTTPS (código {codigo}).")]


# ---------- certificado ----------

def _obter_certificado(dominio):
    contexto = ssl.create_default_context()  # valida cadeia e nome do host
    with socket.create_connection((dominio, 443), timeout=TIMEOUT) as sock:
        with contexto.wrap_socket(sock, server_hostname=dominio) as tls:
            return tls.getpeercert()


def verificar_certificado(dominio, obter=None, agora=None):
    obter = obter or _obter_certificado
    agora = agora or datetime.now(timezone.utc)
    try:
        cert = obter(dominio)
    except ssl.SSLCertVerificationError as exc:
        return [_res("certificado", "falha", "alta", f"Certificado inválido: {exc.verify_message}")]
    except OSError as exc:
        return [_res("certificado", "erro", "media",
                     f"Não foi possível conectar na porta 443: {type(exc).__name__}")]
    expira = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    dias = (expira - agora).days
    emissor = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "desconhecido")
    texto = f"Emissor: {emissor}. Expira em {expira:%d/%m/%Y} ({dias} dias)."
    if dias < 0:
        return [_res("certificado", "falha", "alta", "Certificado expirado. " + texto)]
    if dias < 30:
        return [_res("certificado", "atencao", "media", "Expira em menos de 30 dias. " + texto)]
    return [_res("certificado", "ok", "info", texto)]


# ---------- execução conjunta ----------

def executar_todas(dominio, obter_cert=None, buscar_cab=None, buscar_redir=None):
    dominio = validar_dominio(dominio)
    return (verificar_certificado(dominio, obter_cert)
            + verificar_redirecionamento_https(dominio, buscar_redir)
            + verificar_cabecalhos(dominio, buscar_cab))
