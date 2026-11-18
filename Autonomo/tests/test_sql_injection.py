"""Testes de bloqueio de SQL Injection: entradas maliciosas viram dado, nunca comando."""
import pytest

from app import auth, history
from tests.conftest import tabela_existe

PAYLOADS = [
    "' OR '1'='1' --",
    "admin' --",
    "'; DROP TABLE usuarios; --",
    '" OR ""="',
    "x' UNION SELECT 1,2,3 --",
    "alice' OR 1=1 --",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_login_nao_e_burlado_por_sql_injection(conn, payload):
    auth.registrar(conn, "alice", "Senha1234")
    with pytest.raises(auth.ErroAutenticacao):
        auth.login(conn, payload, payload)       # injeção no usuário e na senha
    with pytest.raises(auth.ErroAutenticacao):
        auth.login(conn, "alice", payload)       # injeção só na senha
    assert tabela_existe(conn, "usuarios")
    assert conn.consultar("SELECT COUNT(*) AS n FROM usuarios")[0]["n"] == 1


@pytest.mark.parametrize("payload", PAYLOADS)
def test_cadastro_rejeita_usuario_malicioso(conn, payload):
    with pytest.raises(auth.ErroValidacao):
        auth.registrar(conn, payload, "Senha1234")
    assert tabela_existe(conn, "usuarios")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_observacoes_maliciosas_sao_gravadas_como_texto(conn, payload):
    uid = auth.registrar(conn, "alice", "Senha1234")
    resultados = [{"verificacao": "teste", "status": "ok", "gravidade": "info",
                   "detalhe": payload}]
    exec_id = history.salvar_execucao(conn, uid, "loja.exemplo.com", resultados, payload)
    ex = history.obter_execucao(conn, uid, exec_id)
    assert ex["observacoes"] == payload                  # voltou idêntico, sem executar nada
    assert ex["resultados"][0]["detalhe"] == payload
    for tabela in ("usuarios", "execucoes", "resultados", "logs_acesso"):
        assert tabela_existe(conn, tabela)


def test_injecao_no_id_da_execucao_nao_vaza_dados(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    history.salvar_execucao(conn, uid, "loja.exemplo.com", [], "privado")
    assert history.obter_execucao(conn, uid, "1 OR 1=1") is None


def test_nenhum_sql_e_montado_com_f_string_ou_concatenacao():
    """Verificação estática simples: SQL só com parâmetros %s."""
    import pathlib
    import re

    for arq in pathlib.Path("app").glob("*.py"):
        codigo = arq.read_text(encoding="utf-8")
        assert not re.search(r"""f["'](SELECT|INSERT|UPDATE|DELETE)""", codigo, re.I), arq
        assert not re.search(r"""["'](SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+""", codigo,
                             re.I), arq
