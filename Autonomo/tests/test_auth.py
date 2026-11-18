import pytest

from app import auth


def test_mesma_senha_gera_hashes_diferentes_por_causa_do_salt():
    h1 = auth.gerar_hash("Senha1234")
    h2 = auth.gerar_hash("Senha1234")
    assert h1 != h2
    assert "Senha1234" not in h1


def test_verificar_hash_aceita_senha_correta_e_rejeita_errada():
    h = auth.gerar_hash("Senha1234")
    assert auth.verificar_hash("Senha1234", h)
    assert not auth.verificar_hash("Senha12345", h)


def test_senha_nao_e_gravada_em_texto_puro(conn):
    auth.registrar(conn, "alice", "Senha1234")
    linha = conn.consultar("SELECT senha_hash FROM usuarios WHERE username = %s", ("alice",))[0]
    assert "Senha1234" not in linha["senha_hash"]
    assert len(linha["senha_hash"]) > 40


@pytest.mark.parametrize("senha", ["curta1", "somenteletras", "12345678", "a1" * 40])
def test_senhas_fracas_ou_longas_sao_rejeitadas(conn, senha):
    with pytest.raises(auth.ErroValidacao):
        auth.registrar(conn, "alice", senha)


@pytest.mark.parametrize("nome", ["ab", "com espaco", "a'b", "x" * 51, ""])
def test_usernames_invalidos_sao_rejeitados(conn, nome):
    with pytest.raises(auth.ErroValidacao):
        auth.registrar(conn, nome, "Senha1234")


def test_usuario_duplicado_e_rejeitado(conn):
    auth.registrar(conn, "alice", "Senha1234")
    with pytest.raises(auth.ErroValidacao):
        auth.registrar(conn, "alice", "OutraSenha9")


def test_login_correto_e_incorreto(conn):
    uid = auth.registrar(conn, "alice", "Senha1234")
    assert auth.login(conn, "alice", "Senha1234") == {"id": uid, "username": "alice"}
    with pytest.raises(auth.ErroAutenticacao):
        auth.login(conn, "alice", "errada123")


def test_mensagem_de_erro_nao_revela_se_usuario_existe(conn):
    auth.registrar(conn, "alice", "Senha1234")
    with pytest.raises(auth.ErroAutenticacao) as e1:
        auth.login(conn, "alice", "errada123")
    with pytest.raises(auth.ErroAutenticacao) as e2:
        auth.login(conn, "naoexiste", "errada123")
    assert str(e1.value) == str(e2.value)


def test_bloqueio_apos_varias_tentativas_erradas(conn):
    auth.registrar(conn, "alice", "Senha1234")
    for _ in range(auth.MAX_TENTATIVAS):
        with pytest.raises(auth.ErroAutenticacao):
            auth.login(conn, "alice", "errada123")
    with pytest.raises(auth.ErroAutenticacao, match="Muitas tentativas"):
        auth.login(conn, "alice", "Senha1234")  # mesmo com a senha certa


def test_contato_e_gravado_cifrado_e_recuperado(conn):
    uid = auth.registrar(conn, "alice", "Senha1234", contato="alice@exemplo.com")
    bruto = conn.consultar("SELECT contato_cifrado FROM usuarios WHERE id = %s", (uid,))[0]
    assert "alice@exemplo.com" not in bruto["contato_cifrado"]
    assert auth.obter_contato(conn, uid) == "alice@exemplo.com"


def test_logs_de_acesso_sao_registrados(conn):
    auth.registrar(conn, "alice", "Senha1234")
    auth.login(conn, "alice", "Senha1234")
    with pytest.raises(auth.ErroAutenticacao):
        auth.login(conn, "alice", "errada123")
    acoes = conn.consultar("SELECT acao, sucesso FROM logs_acesso ORDER BY id")
    assert [(a["acao"], a["sucesso"]) for a in acoes] == [
        ("cadastro", 1), ("login", 1), ("login", 0)]
