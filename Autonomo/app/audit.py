"""Registro de logs de acesso à ferramenta (A7)."""
from datetime import datetime, timezone


def agora_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def registrar_log(conn, acao, sucesso, usuario_id=None, username=None):
    conn.inserir(
        "INSERT INTO logs_acesso (usuario_id, username_tentado, acao, sucesso, criado_em) "
        "VALUES (%s, %s, %s, %s, %s)",
        (usuario_id, (username or "")[:50] or None, acao, 1 if sucesso else 0, agora_utc()),
    )
    conn.commit()
