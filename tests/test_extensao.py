"""
Projeto Integrador — Cibersegurança em Programação Segura (PUC-Campinas)
Entrega 2 — Suíte de Testes Automatizados (Atividade de Extensão)

Módulo: tests/test_extensao.py
Descrição:
    Implementa os casos de teste unitários (CT-E01 a CT-E06) previstos no
    Plano de Testes da Atividade de Extensão utilizando o framework pytest.
    Cobre tanto os cenários nominais de classificação de scripts, cabeçalhos e
    consolidação de checklist quanto os caminhos de erro para entradas inválidas.
"""

import sys
from pathlib import Path

import pytest

# Adiciona a pasta src/ ao sys.path para permitir importação direta do módulo
# independentemente do diretório em que o comando pytest for invocado.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from auditor_extensao import AuditorVitrineShopify, ConsolidadorDiagnosticoExtensao


def test_ct_e01_separacao_scripts_nativos_e_terceiros():
    """
    CT-E01 (Funcional - Requisito E4):
    Verifica se o parser HTML distingue corretamente scripts hospedados na CDN
    nativa da Shopify de scripts externos pertencentes a aplicativos/rastreadores.
    """
    html_vitrine = """
    <html>
      <head>
        <script src="https://cdn.shopify.com/shopifycloud/boomerang/shopify-boomerang-1.0.0.min.js"></script>
        <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
      </head>
      <body></body>
    </html>
    """
    resultado = AuditorVitrineShopify.analisar_html_tema(html_vitrine)

    assert resultado["total_scripts_externos"] == 2
    assert len(resultado["scripts_nativos_shopify"]) == 1
    assert len(resultado["scripts_terceiros"]) == 1


def test_ct_e02_deteccao_script_e_formulario_sem_https():
    """
    CT-E02 (Segurança - Requisito E4):
    Verifica se o analisador identifica recursos carregados ou submetidos via
    HTTP sem criptografia (http://) e os classifica com severidade ALTA.
    """
    html_inseguro = """
    <html>
      <body>
        <script src="http://widget-legado.exemplo.com/app.js"></script>
        <form action="http://coleta-externa.exemplo.com/newsletter" method="POST"></form>
      </body>
    </html>
    """
    resultado = AuditorVitrineShopify.analisar_html_tema(html_inseguro)
    achados_altos = [a for a in resultado["achados_tema"] if a["severidade"] == "ALTA"]

    assert len(achados_altos) == 2


def test_ct_e03_avaliacao_cabecalhos_seguranca():
    """
    CT-E03 (Segurança - Requisito E5):
    Verifica se a avaliação de cabeçalhos HTTP sinaliza status ALERTA e lista
    exatamente os cabeçalhos obrigatórios ausentes na resposta simulada.
    """
    headers_simulados = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
    }
    res = AuditorVitrineShopify.avaliar_cabecalhos(headers_simulados)

    assert res["status"] == "ALERTA"
    assert "Content-Security-Policy" in res["ausentes"]
    assert "X-Content-Type-Options" in res["ausentes"]


def test_ct_e04_consolidacao_diagnostico_checklist_nao_conforme():
    """
    CT-E04 (Funcional - Requisitos E2, E6 e E7):
    Verifica se o consolidador filtra apenas os itens marcados como NAO_CONFORME
    e gera o diagnóstico técnico com código, severidade e recomendação.
    """
    checklist = {
        "empresa": "GreyThorns",
        "dominio": "https://greythorns.myshopify.com/",
        "itens": [
            {
                "codigo": "E2",
                "descricao": "Conta administrativa sem 2FA ativo",
                "status": "NAO_CONFORME",
                "severidade": "ALTA",
                "recomendacao": "Habilitar 2FA imediatamente.",
            },
            {
                "codigo": "E1",
                "descricao": "Revisão de contas",
                "status": "CONFORME",
                "severidade": "MEDIA",
                "recomendacao": "Manter revisão trimestral.",
            },
        ],
    }
    diag = ConsolidadorDiagnosticoExtensao.consolidar(checklist)

    assert diag["empresa"] == "GreyThorns"
    assert diag["total_achados"] == 1
    assert diag["achados"][0]["codigo"] == "E2"
    assert diag["achados"][0]["severidade"] == "ALTA"


def test_ct_e05_caminho_erro_url_invalida():
    """
    CT-E05 (Caminho de Erro - Validação de Entrada):
    Garante que URLs malformadas ou com esquemas fora de HTTP/HTTPS sejam
    rejeitadas com ValueError antes de qualquer tentativa de conexão externa.
    """
    auditor = AuditorVitrineShopify()

    with pytest.raises(ValueError):
        auditor.validar_url("ftp://greythorns.myshopify.com/")
    with pytest.raises(ValueError):
        auditor.validar_url("url-malformada")


def test_ct_e06_caminho_erro_checklist_incompleto():
    """
    CT-E06 (Caminho de Erro - Integridade do Checklist):
    Garante que dicionários de checklist sem os campos obrigatórios (empresa,
    dominio, itens) disparem ValueError com mensagem descritiva.
    """
    with pytest.raises(ValueError):
        ConsolidadorDiagnosticoExtensao.consolidar({"empresa": "GreyThorns"})