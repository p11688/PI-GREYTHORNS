import os

import pytest

from app.envfile import carregar_env


@pytest.fixture(autouse=True)
def ambiente_isolado(monkeypatch):
    # troca os.environ por uma cópia: o que o teste carregar some no fim
    monkeypatch.setattr(os, "environ", dict(os.environ))


def test_carrega_valores_do_arquivo(tmp_path):
    arq = tmp_path / ".env"
    arq.write_text('GT_TESTE_A=abc\nGT_TESTE_B="com aspas"\n', encoding="utf-8")
    assert carregar_env(arq) is True
    assert os.environ["GT_TESTE_A"] == "abc"
    assert os.environ["GT_TESTE_B"] == "com aspas"


def test_ignora_comentarios_linhas_vazias_e_valores_vazios(tmp_path):
    arq = tmp_path / ".env"
    arq.write_text("# comentário\n\nGT_TESTE_C=\nsem_igual\nGT_TESTE_D=ok\n", encoding="utf-8")
    carregar_env(arq)
    assert "GT_TESTE_C" not in os.environ
    assert os.environ["GT_TESTE_D"] == "ok"


def test_nao_sobrescreve_variavel_ja_definida(tmp_path):
    os.environ["GT_TESTE_E"] = "do_sistema"
    arq = tmp_path / ".env"
    arq.write_text("GT_TESTE_E=do_arquivo\n", encoding="utf-8")
    carregar_env(arq)
    assert os.environ["GT_TESTE_E"] == "do_sistema"


def test_arquivo_inexistente_nao_da_erro(tmp_path):
    assert carregar_env(tmp_path / "nao_existe.env") is False
