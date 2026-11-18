import ssl
from datetime import datetime, timezone

import pytest

from app import checker

CABECALHOS_OK = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}
AGORA = datetime(2026, 11, 18, tzinfo=timezone.utc)


def _por_nome(resultados):
    return {r["verificacao"]: r for r in resultados}


# ---- cabeçalhos ----

def test_cabecalhos_completos_sao_aprovados():
    assert all(r["status"] == "ok" for r in checker.analisar_cabecalhos(CABECALHOS_OK))


def test_leitura_de_cabecalhos_ignora_maiusculas_e_minusculas():
    minusculos = {k.lower(): v for k, v in CABECALHOS_OK.items()}
    assert all(r["status"] == "ok" for r in checker.analisar_cabecalhos(minusculos))


def test_cabecalhos_ausentes_geram_falha():
    res = checker.analisar_cabecalhos({})
    assert len(res) == 6
    assert all(r["status"] == "falha" for r in res)


def test_nosniff_com_valor_errado_falha():
    h = dict(CABECALHOS_OK, **{"X-Content-Type-Options": "outro"})
    assert _por_nome(checker.analisar_cabecalhos(h))["cabecalho:x-content-type-options"][
        "status"] == "falha"


def test_hsts_com_max_age_curto_gera_atencao():
    h = dict(CABECALHOS_OK, **{"Strict-Transport-Security": "max-age=100"})
    assert _por_nome(checker.analisar_cabecalhos(h))["cabecalho:strict-transport-security"][
        "status"] == "atencao"


def test_frame_ancestors_no_csp_substitui_x_frame_options():
    h = {k: v for k, v in CABECALHOS_OK.items() if k != "X-Frame-Options"}
    h["Content-Security-Policy"] = "frame-ancestors 'none'"
    assert _por_nome(checker.analisar_cabecalhos(h))["cabecalho:x-frame-options"]["status"] == "ok"


def test_verificar_cabecalhos_le_a_resposta_do_servidor():
    res = checker.verificar_cabecalhos("loja.exemplo.com", buscar=lambda url: CABECALHOS_OK)
    assert all(r["status"] == "ok" for r in res)


def test_erro_de_rede_vira_resultado_de_erro():
    import requests

    def falha(url):
        raise requests.ConnectionError("sem rede")

    res = checker.verificar_cabecalhos("loja.exemplo.com", buscar=falha)
    assert res[0]["status"] == "erro"


# ---- redirecionamento ----

@pytest.mark.parametrize("resposta,esperado", [
    ((301, "https://loja.exemplo.com/"), "ok"),
    ((302, "HTTPS://loja.exemplo.com/"), "ok"),
    ((200, None), "falha"),
    ((301, "http://loja.exemplo.com/"), "falha"),
])
def test_redirecionamento_para_https(resposta, esperado):
    res = checker.verificar_redirecionamento_https("loja.exemplo.com", buscar=lambda u: resposta)
    assert res[0]["status"] == esperado


# ---- certificado ----

def _cert(data):
    return {"notAfter": data, "issuer": ((("organizationName", "Let's Encrypt"),),)}


def test_certificado_valido():
    res = checker.verificar_certificado(
        "loja.exemplo.com", obter=lambda d: _cert("Jan  1 00:00:00 2030 GMT"), agora=AGORA)
    assert res[0]["status"] == "ok"
    assert "Let's Encrypt" in res[0]["detalhe"]


def test_certificado_perto_de_expirar():
    res = checker.verificar_certificado(
        "loja.exemplo.com", obter=lambda d: _cert("Dec  1 00:00:00 2026 GMT"), agora=AGORA)
    assert res[0]["status"] == "atencao"


def test_certificado_expirado():
    res = checker.verificar_certificado(
        "loja.exemplo.com", obter=lambda d: _cert("Jan  1 00:00:00 2026 GMT"), agora=AGORA)
    assert res[0]["status"] == "falha"


def test_certificado_invalido_na_cadeia():
    def invalido(d):
        erro = ssl.SSLCertVerificationError("falhou")
        erro.verify_message = "self-signed certificate"
        raise erro

    res = checker.verificar_certificado("loja.exemplo.com", obter=invalido)
    assert res[0]["status"] == "falha"
    assert res[0]["gravidade"] == "alta"


def test_servidor_inacessivel_vira_erro():
    def sem_conexao(d):
        raise TimeoutError()

    assert checker.verificar_certificado("loja.exemplo.com", obter=sem_conexao)[0][
        "status"] == "erro"


# ---- domínio ----

@pytest.mark.parametrize("dominio", [
    "https://loja.exemplo.com", "loja.exemplo.com/caminho", "localhost", "127.0.0.1",
    "10.0.0.5", "loja.exemplo.com:8080", "a b.com", "", "x'; DROP TABLE usuarios;--.com",
])
def test_dominios_invalidos_sao_rejeitados(dominio):
    with pytest.raises(checker.ErroDominio):
        checker.validar_dominio(dominio)


def test_dominio_valido_e_normalizado():
    assert checker.validar_dominio("  GreyThorns.MyShopify.com ") == "greythorns.myshopify.com"


def test_lista_de_dominios_autorizados(monkeypatch):
    monkeypatch.setenv("GT_DOMINIOS_AUTORIZADOS", "greythorns.myshopify.com")
    assert checker.validar_dominio("greythorns.myshopify.com")
    with pytest.raises(checker.ErroDominio):
        checker.validar_dominio("outro.exemplo.com")


def test_executar_todas_junta_as_tres_verificacoes():
    res = checker.executar_todas(
        "loja.exemplo.com",
        obter_cert=lambda d: _cert("Jan  1 00:00:00 2030 GMT"),
        buscar_cab=lambda u: CABECALHOS_OK,
        buscar_redir=lambda u: (301, "https://loja.exemplo.com/"),
    )
    assert len(res) == 8
    assert all(r["status"] == "ok" for r in res)
