# Projeto Integrador — Cibersegurança em Programação Segura (PUC-Campinas)
## Atividade de Extensão — Auditoria Passiva e Diagnóstico de Segurança (GreyThorns)

Repositório referente à **Entrega 2 (Protótipo Inicial e Plano de Testes)** da **Atividade de Extensão**, desenvolvido para apoiar o diagnóstico de segurança e conformidade com a Lei Geral de Proteção de Dados Pessoais (LGPD) da loja virtual da **GreyThorns** (`https://greythorns.myshopify.com/`) na plataforma Shopify.

- **Instituição:** Pontifícia Universidade Católica de Campinas (PUC-Campinas) — Curso de Cibersegurança
- **Disciplina:** Projeto Integrador — Cibersegurança em Programação Segura
- **Docente:** Prof. Dr. Felix Carvalho Rodrigues
- **Integrantes:** Bruno Henrique dos Santos, Eduardo Guimaro Pereira, Igor Nunes das Neves, Rodrigo Quintanilha Granato
- **Empresa Parceira:** GreyThorns (`https://greythorns.myshopify.com/`)

---

## Escopo Técnico do Protótipo

O protótipo atua de forma **estritamente passiva** (requisições `GET` somente leitura), respeitando integralmente o termo de aceite formalizado com a empresa parceira:

- **E4 — Inspeção de Tema e Scripts de Terceiros:** Analisa o HTML público da vitrine para inventariar scripts nativos da CDN Shopify versus scripts externos de terceiros, sinalizando carregamentos sem criptografia (`http://`) ou sem integridade sub-recurso (`SRI`), além de verificar formulários inseguros.
- **E5 — Segurança de Transporte e Cabeçalhos HTTP:** Verifica o redirecionamento para HTTPS, a validade/emissor do certificado TLS e a presença de cabeçalhos de segurança (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` e `Referrer-Policy`).
- **E1–E3, E6 e E7 — Consolidação de Checklist Painel/LGPD e Diagnóstico:** Valida a estrutura JSON com os critérios administrativos (contas, privilégios, 2FA, aplicativos instalados e mapeamento LGPD) e gera um diagnóstico consolidado classificado por severidade (`ALTA`, `MEDIA`, `BAIXA`).

---

## Estrutura do Projeto

```text
greythorns-extensao-pi4/
├── .gitignore
├── README.md
├── requirements.txt
├── data/
│   └── checklist_greythorns.json    # Estrutura de verificação administrativa e LGPD (E1-E3, E6)
├── src/
│   └── auditor_extensao.py          # Módulo de auditoria passiva da vitrine e consolidação (E4, E5, E7)
└── tests/
    └── test_extensao.py             # Suíte de testes automatizados (CT-E01 a CT-E06)
```

---

## Pré-requisitos e Instalação

1. Certifique-se de ter o **Python 3.10+** instalado.
2. Clone este repositório e acesse a pasta raiz:
   ```bash
   git clone https://github.com/SEU_USUARIO/greythorns-extensao-pi4.git
   cd greythorns-extensao-pi4
   ```
3. Crie e ative o ambiente virtual:
   ```powershell
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Instale as dependências de teste e análise estática:
   ```bash
   pip install -r requirements.txt
   ```

---

## Como Executar

### 1. Rodar a auditoria passiva na vitrine da GreyThorns
```bash
python src/auditor_extensao.py
```

### 2. Executar os testes automatizados (`pytest`)
```bash
pytest -v
```

### 3. Executar a análise estática de segurança (`Bandit`)
```bash
bandit -r src/
```

---

## Ética, Sigilo e Limites de Escopo

- Nenhuma varredura intrusiva, teste de carga ou tentativa de exploração contra a infraestrutura da Shopify é realizada por este software.
- Nenhum dado pessoal real de clientes da GreyThorns é coletado, armazenado ou versionado neste repositório.
