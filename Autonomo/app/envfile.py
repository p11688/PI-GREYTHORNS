"""Leitura opcional de um arquivo .env (linhas CHAVE=VALOR), sem dependências externas.

O arquivo .env fica na pasta do projeto, ao lado de main.py, e nunca deve ser versionado.
Variáveis já definidas no sistema têm prioridade sobre as do arquivo.
"""
import os
from pathlib import Path


def carregar_env(caminho=None):
    """Carrega o .env. Devolve True se o arquivo existia, False caso contrário."""
    arquivo = Path(caminho) if caminho else Path(__file__).resolve().parent.parent / ".env"
    if not arquivo.is_file():
        return False
    for linha in arquivo.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        chave, valor = linha.split("=", 1)
        chave = chave.strip()
        valor = valor.strip().strip('"').strip("'")
        if chave and valor and chave not in os.environ:
            os.environ[chave] = valor
    return True
