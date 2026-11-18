"""Geração de relatório das verificações (A6)."""
import csv

_ROTULO = {"ok": "OK", "atencao": "ATENCAO", "falha": "FALHA", "erro": "ERRO"}


def gerar_relatorio_texto(execucao):
    linhas = [
        "RELATÓRIO DE VERIFICAÇÃO - GreyThorns",
        f"Execução #{execucao['id']}  |  Domínio: {execucao['dominio']}  |  "
        f"Data (UTC): {execucao['executado_em']}",
    ]
    if execucao.get("observacoes"):
        linhas.append(f"Observações: {execucao['observacoes']}")
    linhas.append("-" * 70)
    for r in execucao["resultados"]:
        linhas.append(f"[{_ROTULO.get(r['status'], r['status'])}] {r['verificacao']} "
                      f"(gravidade: {r['gravidade']}) - {r['detalhe']}")
    total = len(execucao["resultados"])
    ok = sum(1 for r in execucao["resultados"] if r["status"] == "ok")
    linhas += ["-" * 70, f"Resumo: {ok} de {total} verificações aprovadas."]
    return "\n".join(linhas)


def _csv_seguro(valor):
    """Evita injeção de fórmulas ao abrir o CSV no Excel."""
    valor = "" if valor is None else str(valor)
    return "'" + valor if valor[:1] in ("=", "+", "-", "@") else valor


def exportar_csv(execucao, caminho):
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["verificacao", "status", "gravidade", "detalhe"])
        for r in execucao["resultados"]:
            w.writerow([_csv_seguro(r[c]) for c in ("verificacao", "status", "gravidade", "detalhe")])
