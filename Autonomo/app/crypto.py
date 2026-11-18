"""Cifragem simétrica (Fernet = AES-128-CBC + HMAC-SHA256) dos campos sensíveis.

A chave vem da variável de ambiente GT_ENC_KEY, nunca do código-fonte.
Gerar uma chave:  python -m app.crypto
"""
import os

from cryptography.fernet import Fernet, InvalidToken


class ErroCripto(Exception):
    pass


def gerar_chave():
    return Fernet.generate_key().decode()


def _fernet():
    chave = os.environ.get("GT_ENC_KEY")
    if not chave:
        raise ErroCripto("GT_ENC_KEY não definida. Gere uma com: python -m app.crypto")
    try:
        return Fernet(chave.encode())
    except ValueError as exc:
        raise ErroCripto("GT_ENC_KEY inválida.") from exc


def cifrar(texto):
    return _fernet().encrypt(texto.encode("utf-8")).decode()


def decifrar(token):
    try:
        return _fernet().decrypt(token.encode()).decode("utf-8")
    except InvalidToken as exc:
        raise ErroCripto("Não foi possível decifrar (chave errada ou dado adulterado).") from exc


if __name__ == "__main__":
    print(gerar_chave())
