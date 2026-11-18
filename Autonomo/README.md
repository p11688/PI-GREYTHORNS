# Verificador de segurança GreyThorns (atividade autônoma)

Ferramenta de linha de comando que verifica certificado, redirecionamento HTTPS e cabeçalhos de
segurança de um domínio autorizado, e guarda o histórico em MySQL com campos sensíveis cifrados.

| Requisito | Onde está |
|---|---|
| A1 cadastro/login, hash com salt | `app/auth.py` |
| A2 verificações passivas | `app/checker.py` |
| A3 registro em banco relacional | `schema.sql`, `app/db.py`, `app/history.py` |
| A4 campos sensíveis cifrados | `app/crypto.py` (observações e contato) |
| A5 histórico e comparação | `app/history.py` |
| A6 relatório (texto e CSV) | `app/report.py` |
| A7 logs de acesso | `app/audit.py`, tabela `logs_acesso` |

## Instalação

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Banco MySQL

```bash
mysql -u root -p < grants.sql                 # cria o banco e o usuário gt_app (só SELECT/INSERT)
mysql -u root -p greythorns < schema.sql      # cria as tabelas
```

As senhas provisórias de `grants.sql` devem ser substituídas antes da execução.

## Configuração (arquivo .env, nada de segredo no código)

1. Copie `.env.example` para `.env` (na mesma pasta do `main.py`).
2. Gere a chave com `python -m app.crypto` e grave o valor em `GT_ENC_KEY=`.
3. Preencha `GT_DB_PASSWORD=` com a senha definida para `gt_app` no `grants.sql`.

O programa lê o `.env` sozinho ao iniciar. Guarde a `GT_ENC_KEY`: sem ela os campos cifrados não podem ser lidos.

## Uso

```bash
python main.py
```

### Modo rápido com SQLite (sem instalar MySQL)

No `.env`, basta configurar:

```
GT_DB_BACKEND=sqlite
GT_SQLITE_PATH=greythorns.db
GT_ENC_KEY=<chave gerada por python -m app.crypto>
GT_DOMINIOS_AUTORIZADOS=greythorns.myshopify.com
```

O arquivo `greythorns.db` e as tabelas são criados automaticamente na primeira execução.
Para ver o que ficou gravado (hash da senha e campos cifrados): `python ver_banco.py`.

## Testes e análise estática

```bash
pytest -v
bandit -r app
```

Os testes usam SQLite em memória e respostas simuladas, então não precisam de MySQL nem de internet

## Backup

`GT_BACKUP_PASSWORD=... ./backup.sh` (agendar no cron).
