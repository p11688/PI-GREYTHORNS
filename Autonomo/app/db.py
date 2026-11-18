"""Acesso ao banco de dados.

Produção: MySQL (via pymysql). Testes locais: SQLite.
Todas as consultas usam parâmetros (%s); nunca concatenamos entrada do usuário no SQL.
"""
import os
import re
import sqlite3
from pathlib import Path

ARQUIVO_SCHEMA = Path(__file__).resolve().parent.parent / "schema.sql"


class Conexao:
    """Envolve a conexão DB-API e adapta o marcador %s para o SQLite."""

    def __init__(self, raw, backend):
        self.raw = raw
        self.backend = backend

    def _executar(self, sql, params=()):
        if self.backend == "sqlite":
            sql = sql.replace("%s", "?")
        cur = self.raw.cursor()
        cur.execute(sql, tuple(params))
        return cur

    def consultar(self, sql, params=()):
        """Executa um SELECT e devolve uma lista de dicionários."""
        cur = self._executar(sql, params)
        colunas = [c[0] for c in cur.description]
        linhas = [dict(zip(colunas, linha)) for linha in cur.fetchall()]
        cur.close()
        return linhas

    def inserir(self, sql, params=()):
        """Executa um INSERT e devolve o id gerado."""
        cur = self._executar(sql, params)
        novo_id = cur.lastrowid
        cur.close()
        return novo_id

    def executar(self, sql, params=()):
        self._executar(sql, params).close()

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


def _exigir_env(nome):
    valor = os.environ.get(nome)
    if not valor:
        raise RuntimeError(f"Variável de ambiente {nome} não definida (veja .env.example).")
    return valor


def abrir_conexao(backend=None, sqlite_path=None):
    """Abre a conexão. Credenciais vêm de variáveis de ambiente, nunca do código."""
    backend = backend or os.environ.get("GT_DB_BACKEND", "mysql")
    if backend == "sqlite":
        caminho = sqlite_path or os.environ.get("GT_SQLITE_PATH", "greythorns.db")
        raw = sqlite3.connect(caminho)
        raw.execute("PRAGMA foreign_keys = ON")
        return Conexao(raw, "sqlite")
    if backend == "mysql":
        import pymysql  # importado aqui para os testes não exigirem o driver

        raw = pymysql.connect(
            host=os.environ.get("GT_DB_HOST", "localhost"),
            port=int(os.environ.get("GT_DB_PORT", "3306")),
            user=_exigir_env("GT_DB_USER"),
            password=_exigir_env("GT_DB_PASSWORD"),
            database=os.environ.get("GT_DB_NAME", "greythorns"),
            charset="utf8mb4",
            autocommit=False,
        )
        return Conexao(raw, "mysql")
    raise RuntimeError("GT_DB_BACKEND deve ser 'mysql' ou 'sqlite'.")


def _para_sqlite(ddl):
    ddl = ddl.replace("INT AUTO_INCREMENT PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
    ddl = ddl.replace("TINYINT(1)", "INTEGER")
    return re.sub(r"\)\s*ENGINE=[^;]*", ")", ddl)


def criar_esquema(conn):
    """Cria as tabelas a partir do schema.sql (MySQL ou SQLite)."""
    linhas = [
        l for l in ARQUIVO_SCHEMA.read_text(encoding="utf-8").splitlines()
        if not l.strip().startswith("--")
    ]
    for comando in "\n".join(linhas).split(";"):
        comando = comando.strip()
        if not comando:
            continue
        if conn.backend == "sqlite":
            comando = _para_sqlite(comando)
        conn.executar(comando)
    conn.commit()
