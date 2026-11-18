"""Cadastro e login de usuários (A1).

- Senha guardada apenas como hash com salt (bcrypt; se não instalado, scrypt da biblioteca padrão).
- Consultas parametrizadas (sem concatenar entrada do usuário no SQL).
- Mensagem de erro genérica no login e bloqueio temporário após várias falhas.
"""
import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta, timezone

from app.audit import registrar_log
from app.crypto import cifrar, decifrar

try:
    import bcrypt
except ImportError:  # fallback para ambientes sem bcrypt
    bcrypt = None

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
MAX_TENTATIVAS = 5
JANELA_MINUTOS = 15
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}
_hash_falso = None


class ErroValidacao(ValueError):
    pass


class ErroAutenticacao(Exception):
    pass


def validar_senha(senha):
    if len(senha) < 8:
        raise ErroValidacao("A senha deve ter pelo menos 8 caracteres.")
    if len(senha.encode("utf-8")) > 72:
        raise ErroValidacao("A senha deve ter no máximo 72 bytes.")
    if not re.search(r"[A-Za-z]", senha) or not re.search(r"\d", senha):
        raise ErroValidacao("A senha deve conter letras e números.")


def gerar_hash(senha):
    dados = senha.encode("utf-8")
    if bcrypt is not None:
        return bcrypt.hashpw(dados, bcrypt.gensalt(rounds=12)).decode()
    sal = os.urandom(16)
    dk = hashlib.scrypt(dados, salt=sal, **_SCRYPT)
    return f"scrypt${sal.hex()}${dk.hex()}"


def verificar_hash(senha, armazenado):
    dados = senha.encode("utf-8")
    if armazenado.startswith("scrypt$"):
        _, sal_hex, dk_hex = armazenado.split("$")
        dk = hashlib.scrypt(dados, salt=bytes.fromhex(sal_hex), **_SCRYPT)
        return hmac.compare_digest(dk, bytes.fromhex(dk_hex))
    if bcrypt is None:
        return False
    try:
        return bcrypt.checkpw(dados, armazenado.encode())
    except ValueError:
        return False


def registrar(conn, username, senha, contato=None):
    """Cria o usuário. Devolve o id. O contato (opcional) é gravado cifrado."""
    if not USERNAME_RE.match(username or ""):
        raise ErroValidacao("Usuário inválido: use 3 a 50 caracteres (letras, números, _ . -).")
    validar_senha(senha)
    if conn.consultar("SELECT id FROM usuarios WHERE username = %s", (username,)):
        raise ErroValidacao("Esse nome de usuário já está em uso.")
    contato_cifrado = cifrar(contato) if contato else None
    novo_id = conn.inserir(
        "INSERT INTO usuarios (username, senha_hash, contato_cifrado, criado_em) "
        "VALUES (%s, %s, %s, %s)",
        (username, gerar_hash(senha), contato_cifrado,
         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    registrar_log(conn, "cadastro", True, novo_id, username)
    return novo_id


def _bloqueado(conn, username):
    limite = (datetime.now(timezone.utc) - timedelta(minutes=JANELA_MINUTOS)).strftime(
        "%Y-%m-%d %H:%M:%S")
    linhas = conn.consultar(
        "SELECT COUNT(*) AS total FROM logs_acesso "
        "WHERE acao = %s AND sucesso = 0 AND username_tentado = %s AND criado_em >= %s",
        ("login", username[:50], limite),
    )
    return int(linhas[0]["total"]) >= MAX_TENTATIVAS


def login(conn, username, senha):
    """Autentica. Devolve {'id', 'username'} ou levanta ErroAutenticacao."""
    global _hash_falso
    username = username or ""
    senha = senha or ""
    if _bloqueado(conn, username):
        registrar_log(conn, "login_bloqueado", False, None, username)
        raise ErroAutenticacao(
            f"Muitas tentativas. Tente novamente em {JANELA_MINUTOS} minutos.")
    linhas = conn.consultar(
        "SELECT id, username, senha_hash FROM usuarios WHERE username = %s", (username,))
    if linhas:
        valido = verificar_hash(senha, linhas[0]["senha_hash"])
    else:
        # gasta o mesmo tempo de um usuário real (evita descobrir usuários pelo tempo)
        if _hash_falso is None:
            _hash_falso = gerar_hash("senha-falsa-123")
        verificar_hash(senha, _hash_falso)
        valido = False
    if not valido:
        registrar_log(conn, "login", False, None, username)
        raise ErroAutenticacao("Usuário ou senha inválidos.")
    registrar_log(conn, "login", True, linhas[0]["id"], username)
    return {"id": linhas[0]["id"], "username": linhas[0]["username"]}


def obter_contato(conn, usuario_id):
    linhas = conn.consultar(
        "SELECT contato_cifrado FROM usuarios WHERE id = %s", (usuario_id,))
    if linhas and linhas[0]["contato_cifrado"]:
        return decifrar(linhas[0]["contato_cifrado"])
    return None
