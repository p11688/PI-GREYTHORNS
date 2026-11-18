import pytest
from cryptography.fernet import Fernet

from app import db


@pytest.fixture(autouse=True)
def ambiente_de_teste(monkeypatch):
    monkeypatch.setenv("GT_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("GT_DOMINIOS_AUTORIZADOS", raising=False)


@pytest.fixture
def conn():
    c = db.abrir_conexao(backend="sqlite", sqlite_path=":memory:")
    db.criar_esquema(c)
    yield c
    c.close()


def tabela_existe(conn, nome):
    return bool(conn.consultar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = %s", (nome,)))
