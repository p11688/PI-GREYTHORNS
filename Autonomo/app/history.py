"""Registro e consulta do histórico de execuções (A3, A4, A5)."""
from app.audit import agora_utc
from app.crypto import cifrar, decifrar


def salvar_execucao(conn, usuario_id, dominio, resultados, observacoes=None):
    """Grava a execução e seus resultados. As observações vão cifradas."""
    try:
        exec_id = conn.inserir(
            "INSERT INTO execucoes (usuario_id, dominio, observacoes_cifradas, executado_em) "
            "VALUES (%s, %s, %s, %s)",
            (usuario_id, dominio, cifrar(observacoes) if observacoes else None, agora_utc()),
        )
        for r in resultados:
            conn.inserir(
                "INSERT INTO resultados (execucao_id, verificacao, status, gravidade, detalhe) "
                "VALUES (%s, %s, %s, %s, %s)",
                (exec_id, r["verificacao"], r["status"], r["gravidade"], r["detalhe"]),
            )
        conn.commit()
        return exec_id
    except Exception:
        conn.rollback()
        raise


def listar_execucoes(conn, usuario_id):
    linhas = conn.consultar(
        "SELECT e.id, e.dominio, e.executado_em, "
        "SUM(CASE WHEN r.status = 'ok' THEN 1 ELSE 0 END) AS aprovadas, "
        "COUNT(r.id) AS total "
        "FROM execucoes e LEFT JOIN resultados r ON r.execucao_id = e.id "
        "WHERE e.usuario_id = %s "
        "GROUP BY e.id, e.dominio, e.executado_em ORDER BY e.id DESC",
        (usuario_id,),
    )
    for l in linhas:
        l["aprovadas"] = int(l["aprovadas"] or 0)
        l["total"] = int(l["total"] or 0)
        l["executado_em"] = str(l["executado_em"])
    return linhas


def obter_execucao(conn, usuario_id, exec_id):
    """Devolve a execução com observações decifradas, ou None.
    Só enxerga execuções do próprio usuário."""
    ex = conn.consultar(
        "SELECT id, dominio, observacoes_cifradas, executado_em "
        "FROM execucoes WHERE id = %s AND usuario_id = %s",
        (exec_id, usuario_id),
    )
    if not ex:
        return None
    e = ex[0]
    resultados = conn.consultar(
        "SELECT verificacao, status, gravidade, detalhe FROM resultados "
        "WHERE execucao_id = %s ORDER BY id",
        (exec_id,),
    )
    return {
        "id": e["id"],
        "dominio": e["dominio"],
        "executado_em": str(e["executado_em"]),
        "observacoes": decifrar(e["observacoes_cifradas"]) if e["observacoes_cifradas"] else None,
        "resultados": resultados,
    }


def comparar(conn, usuario_id, id_antes, id_depois):
    """Lista as verificações cujo status mudou entre duas execuções."""
    a = obter_execucao(conn, usuario_id, id_antes)
    b = obter_execucao(conn, usuario_id, id_depois)
    if a is None or b is None:
        raise LookupError("Execução não encontrada.")
    antes = {r["verificacao"]: r["status"] for r in a["resultados"]}
    depois = {r["verificacao"]: r["status"] for r in b["resultados"]}
    return [
        {"verificacao": v, "antes": antes.get(v, "-"), "depois": depois.get(v, "-")}
        for v in sorted(set(antes) | set(depois))
        if antes.get(v) != depois.get(v)
    ]
