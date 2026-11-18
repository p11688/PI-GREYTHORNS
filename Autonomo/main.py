"""Interface de linha de comando da ferramenta de verificação GreyThorns."""
import getpass

from app import auth, checker, db, history, report
from app.audit import registrar_log
from app.crypto import ErroCripto
from app.envfile import carregar_env


def _cadastrar(conn):
    usuario = input("Novo usuário: ").strip()
    senha = getpass.getpass("Senha (mín. 8, letras e números): ")
    if senha != getpass.getpass("Repita a senha: "):
        print("As senhas não conferem.")
        return
    contato = input("E-mail de contato (opcional): ").strip() or None
    try:
        auth.registrar(conn, usuario, senha, contato)
        print("Usuário criado. Faça login.")
    except auth.ErroValidacao as exc:
        print(f"Erro: {exc}")


def _login(conn):
    usuario = input("Usuário: ").strip()
    senha = getpass.getpass("Senha: ")
    try:
        return auth.login(conn, usuario, senha)
    except auth.ErroAutenticacao as exc:
        print(f"Erro: {exc}")
        return None


def _nova_verificacao(conn, usuario):
    dominio = input("Domínio (ex.: greythorns.myshopify.com): ")
    obs = input("Observações (opcional, serão gravadas cifradas): ").strip() or None
    try:
        resultados = checker.executar_todas(dominio)
    except checker.ErroDominio as exc:
        print(f"Erro: {exc}")
        return
    exec_id = history.salvar_execucao(conn, usuario["id"], checker.validar_dominio(dominio),
                                      resultados, obs)
    registrar_log(conn, "verificacao", True, usuario["id"], usuario["username"])
    print(report.gerar_relatorio_texto(history.obter_execucao(conn, usuario["id"], exec_id)))


def _historico(conn, usuario):
    for e in history.listar_execucoes(conn, usuario["id"]):
        print(f"#{e['id']}  {e['executado_em']}  {e['dominio']}  ({e['aprovadas']}/{e['total']} ok)")


def _ver(conn, usuario):
    try:
        ex = history.obter_execucao(conn, usuario["id"], int(input("Número da execução: ")))
    except ValueError:
        print("Número inválido.")
        return
    if not ex:
        print("Execução não encontrada.")
        return
    print(report.gerar_relatorio_texto(ex))
    if input("Exportar CSV? (s/N): ").lower() == "s":
        caminho = f"relatorio_{ex['id']}.csv"
        report.exportar_csv(ex, caminho)
        print(f"Arquivo gravado: {caminho}")


def _comparar(conn, usuario):
    try:
        a = int(input("Execução anterior: "))
        b = int(input("Execução nova: "))
        difs = history.comparar(conn, usuario["id"], a, b)
    except ValueError:
        print("Número inválido.")
        return
    except LookupError as exc:
        print(f"Erro: {exc}")
        return
    if not difs:
        print("Nenhuma diferença.")
    for d in difs:
        print(f"{d['verificacao']}: {d['antes']} -> {d['depois']}")


def _menu_usuario(conn, usuario):
    acoes = {"1": _nova_verificacao, "2": _historico, "3": _ver, "4": _comparar}
    while True:
        print(f"\n[{usuario['username']}] 1) Nova verificação  2) Histórico  "
              "3) Ver/exportar relatório  4) Comparar  0) Sair")
        op = input("> ").strip()
        if op == "0":
            return
        if op in acoes:
            acoes[op](conn, usuario)


def main():
    carregar_env()  # lê o arquivo .env da pasta do projeto, se existir
    try:
        conn = db.abrir_conexao()
    except RuntimeError as exc:
        print(f"Configuração: {exc}")
        return
    if conn.backend == "sqlite":
        db.criar_esquema(conn)  # no SQLite o esquema é criado automaticamente (IF NOT EXISTS)
    try:
        while True:
            print("\n=== Verificador GreyThorns ===\n1) Entrar  2) Cadastrar  0) Sair")
            op = input("> ").strip()
            if op == "1":
                usuario = _login(conn)
                if usuario:
                    _menu_usuario(conn, usuario)
            elif op == "2":
                _cadastrar(conn)
            elif op == "0":
                break
    except ErroCripto as exc:
        print(f"Configuração de criptografia: {exc}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
