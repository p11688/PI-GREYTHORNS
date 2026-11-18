import csv

from app import auth, checker, history, report
from app.crypto import ErroCripto

import pytest

CAB_OK = {
    "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()",
}
CERT = {"notAfter": "Jan  1 00:00:00 2030 GMT",
        "issuer": ((("organizationName", "CA Teste"),),)}


def _rodar(cabecalhos):
    return checker.executar_todas(
        "loja.exemplo.com", obter_cert=lambda d: CERT, buscar_cab=lambda u: cabecalhos,
        buscar_redir=lambda u: (301, "https://loja.exemplo.com/"))


def test_salvar_e_consultar_execucao(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    exec_id = history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar(CAB_OK), "nota")
    ex = history.obter_execucao(conn, uid, exec_id)
    assert ex["dominio"] == "loja.exemplo.com"
    assert ex["observacoes"] == "nota"
    assert len(ex["resultados"]) == 8


def test_observacoes_ficam_cifradas_no_banco(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar(CAB_OK), "dado confidencial")
    bruto = conn.consultar("SELECT observacoes_cifradas FROM execucoes")[0]["observacoes_cifradas"]
    assert "confidencial" not in bruto


def test_observacoes_nao_abrem_com_outra_chave(conn, monkeypatch):
    from cryptography.fernet import Fernet

    uid = auth.registrar(conn, "alice", "Senha1234")
    exec_id = history.salvar_execucao(conn, uid, "loja.exemplo.com", [], "dado")
    monkeypatch.setenv("GT_ENC_KEY", Fernet.generate_key().decode())
    with pytest.raises(ErroCripto):
        history.obter_execucao(conn, uid, exec_id)


def test_usuario_nao_ve_execucao_de_outro(conn):
    a = auth.registrar(conn, "alice", "Senha1234")
    b = auth.registrar(conn, "bruno", "Senha1234")
    exec_id = history.salvar_execucao(conn, a, "loja.exemplo.com", [], None)
    assert history.obter_execucao(conn, b, exec_id) is None
    assert history.listar_execucoes(conn, b) == []


def test_listagem_do_historico(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar(CAB_OK))
    history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar({}))
    lista = history.listar_execucoes(conn, uid)
    assert [e["id"] for e in lista] == [2, 1]
    assert (lista[1]["aprovadas"], lista[1]["total"]) == (8, 8)
    assert lista[0]["aprovadas"] == 2  # só certificado e redirecionamento


def test_comparacao_entre_execucoes(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    antes = history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar({}))
    depois = history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar(CAB_OK))
    difs = history.comparar(conn, uid, antes, depois)
    assert len(difs) == 6
    assert all(d["antes"] == "falha" and d["depois"] == "ok" for d in difs)


def test_comparar_execucao_inexistente(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    with pytest.raises(LookupError):
        history.comparar(conn, uid, 1, 2)


def test_relatorio_texto(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    exec_id = history.salvar_execucao(conn, uid, "loja.exemplo.com", _rodar({}), "obs")
    texto = report.gerar_relatorio_texto(history.obter_execucao(conn, uid, exec_id))
    assert "loja.exemplo.com" in texto
    assert "[FALHA] cabecalho:content-security-policy" in texto
    assert "2 de 8 verificações aprovadas" in texto


def test_exportar_csv_e_protecao_contra_formula(tmp_path):
    execucao = {"id": 1, "dominio": "x.com", "executado_em": "agora", "observacoes": None,
                "resultados": [{"verificacao": "v", "status": "ok", "gravidade": "info",
                                "detalhe": "=HYPERLINK(\"http://mal\")"}]}
    caminho = tmp_path / "r.csv"
    report.exportar_csv(execucao, caminho)
    linhas = list(csv.reader(open(caminho, encoding="utf-8")))
    assert linhas[0] == ["verificacao", "status", "gravidade", "detalhe"]
    assert linhas[1][3].startswith("'=")
