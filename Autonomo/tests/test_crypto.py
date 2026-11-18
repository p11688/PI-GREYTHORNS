import pytest
from cryptography.fernet import Fernet

from app.crypto import ErroCripto, cifrar, decifrar


def test_cifrar_e_decifrar_devolve_o_texto_original():
    assert decifrar(cifrar("observação confidencial: ação")) == "observação confidencial: ação"


def test_texto_cifrado_nao_contem_o_texto_original():
    assert "segredo" not in cifrar("meu segredo")


def test_mesmo_texto_gera_cifrados_diferentes():
    assert cifrar("igual") != cifrar("igual")


def test_dado_adulterado_e_rejeitado():
    token = cifrar("texto")
    meio = len(token) // 2
    adulterado = token[:meio] + ("A" if token[meio] != "A" else "B") + token[meio + 1:]
    with pytest.raises(ErroCripto):
        decifrar(adulterado)


def test_chave_errada_nao_decifra(monkeypatch):
    token = cifrar("texto")
    monkeypatch.setenv("GT_ENC_KEY", Fernet.generate_key().decode())
    with pytest.raises(ErroCripto):
        decifrar(token)


def test_sem_chave_configurada_da_erro_claro(monkeypatch):
    monkeypatch.delenv("GT_ENC_KEY")
    with pytest.raises(ErroCripto, match="GT_ENC_KEY"):
        cifrar("x")


def test_chave_invalida_da_erro_claro(monkeypatch):
    monkeypatch.setenv("GT_ENC_KEY", "nao-e-uma-chave")
    with pytest.raises(ErroCripto):
        cifrar("x")
