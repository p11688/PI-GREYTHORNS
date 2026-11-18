"""Mostra o conteúdo do banco, como o administrador o enxergaria. Funciona com SQLite e MySQL.

Uso:  python ver_banco.py
Mostra senha_hash (hash) e os campos cifrados (gAAAA...) para provar que nada fica em texto puro.
"""
from app import db
from app.envfile import carregar_env

LIMITE = 60

CONSULTAS = [
    ("usuarios", "SELECT id, username, senha_hash, contato_cifrado, criado_em FROM usuarios ORDER BY id", True),
    ("execucoes", "SELECT id, usuario_id, dominio, observacoes_cifradas, executado_em FROM execucoes ORDER BY id", True),
    ("resultados", "SELECT execucao_id, verificacao, status, gravidade FROM resultados ORDER BY id", False),
    ("logs_acesso", "SELECT id, acao, sucesso, username_tentado, criado_em FROM logs_acesso ORDER BY id", False),
]


def _cortar(valor):
    texto = "" if valor is None else str(valor)
    return texto if len(texto) <= LIMITE else texto[:LIMITE] + "..."


def main():
    carregar_env()
    conn = db.abrir_conexao()
    if conn.backend == "sqlite":
        db.criar_esquema(conn)
    for nome, sql, vertical in CONSULTAS:
        linhas = conn.consultar(sql)
        print(f"\n=== {nome} ({len(linhas)} linhas) ===")
        for i, linha in enumerate(linhas[:30], 1):
            if vertical:
                print(f"--- linha {i} ---")
                for campo, valor in linha.items():
                    print(f"  {campo}: {_cortar(valor)}")
            else:
                print("  " + " | ".join(_cortar(v) for v in linha.values()))
        if len(linhas) > 30:
            print(f"  ... (mostrando 30 de {len(linhas)})")
    conn.close()


if __name__ == "__main__":
    main()
