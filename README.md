# Vigília

Investigue vulnerabilidades com exploração conhecida e acompanhe os produtos que importam para você.

Projeto do **CP 5 de Python**: crawler independente, MongoDB, API FastAPI, dashboard web e alertas SMTP por produto. O enunciado está em [`CP 5 Python.pdf`](CP%205%20Python.pdf).

## Executar

Pré-requisitos: Docker com Compose. Para os testes locais, Python 3.12+; Node é usado apenas para conferir a sintaxe do JavaScript.

**Em um clone novo**, copie a configuração. Se `.env` já existe, preserve-o:

```bash
cp .env.example .env
docker compose up -d --build --wait
docker compose exec web python -m app.cli bootstrap
```

O bootstrap cria o pool Cognito, o app client, o grupo `admin` e o administrador. `ADMIN_EMAIL` e `ADMIN_PASSWORD` são configuráveis no `.env`. Se a senha estiver vazia, uma senha aleatória é exibida **somente na primeira criação**. O comando é idempotente e não altera a senha de uma conta existente.

| Interface | Endereço |
|---|---|
| Bancada pública | http://localhost:8000 |
| Panorama | http://localhost:8000/panorama |
| Assinaturas e histórico | http://localhost:8000/alertas |
| Administração | http://localhost:8000/admin |
| Documentação interativa da API | http://localhost:8000/docs |
| OpenAPI | http://localhost:8000/openapi.json |
| Mailpit | http://localhost:8025 |

A carga inicial começa automaticamente no worker. Aguarde sua conclusão no admin antes da demonstração completa. O limite padrão `0` percorre todo o catálogo; uma execução manual pode limitar páginas. Cada página HTML tem até 20 registros. A coleta e o enriquecimento fazem requisições sequenciais, com pausas; uma carga completa leva alguns minutos.

MongoDB e Cognito persistem em volumes Docker. `docker compose down` para os processos mantendo os volumes.

## O que está implementado

- **Investigar:** busca literal por CVE, título, fornecedor ou produto; filtros combinados; tabela paginada; inspeção sem perder a busca; detalhes públicos.
- **Panorama:** total, fornecedores, ransomware conhecido, cobertura CVSS, concentração nos cinco maiores fornecedores, inclusões recentes e críticas associadas a ransomware. Cinco gráficos com alternativa tabular acessível.
- **Evidências:** descrição, ação CISA, datas, referências, CWE, avaliações CVSS e condições CPE/versões. Dados originais e fontes explícitas.
- **Acompanhar:** cadastro/login, múltiplos produtos por assinatura, e-mail da conta ou outro destinatário, pausa, edição, exclusão e avisos opcionais de alterações.
- **Operar:** intervalo configurável de 1 a 168 horas, limite de páginas, execução imediata em fila, progresso, histórico, entregas, novas tentativas e simulação identificada.
- **Entregar alertas:** outbox transacional, um resumo por assinatura/execução, SMTP para Mailpit e até cinco tentativas automáticas.

Login é exigido para assinaturas, histórico privado e administração; o catálogo e os detalhes são públicos. O backend valida a propriedade das assinaturas e a associação ao grupo `admin`.

## Fontes e coleta

1. **CISA KEV:** HTTPX visita o [catálogo HTML](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); BeautifulSoup extrai cartões, campos rotulados e links de próxima página.
2. **Reconciliação:** a paginação pode repetir CVEs em páginas com datas empatadas. Se uma coleta completa tiver menos identificadores únicos que o total informado, o crawler consulta a [exportação oficial](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) e adiciona somente os ausentes. A origem do documento é preservada. Essa é uma importação complementar, distinta do rastreamento HTML.
3. **NVD:** a [API 2.0](https://nvd.nist.gov/developers/vulnerabilities) enriquece CVEs em lotes de até 100 IDs. Há pausa mínima de 6,1 segundos entre inícios de requisições. `NVD_API_KEY` é opcional.

A verificação real em **07/10/2026** percorreu **87 páginas HTML + uma exportação de reconciliação**, completou **1.734 CVEs únicos** e enriqueceu os 1.734. Esses números são uma fotografia da verificação, não constantes da aplicação.

Recoletas fazem upsert pelo CVE: preservam a primeira coleta, atualizam a última e não removem outros registros. Alterações de URL de paginação não geram alertas. A primeira coleta completa estabelece a base sem envio retroativo; execuções iniciais parciais não encerram essa fase.

HTTP 403/429 encerra a coleta; falhas transitórias têm tentativas limitadas. Uma falha preserva registros já confirmados. Falha da NVD mantém a evidência anterior e permite novo enriquecimento na execução seguinte.

## Zerar os dados operacionais

Em **Administração → Limpeza de dados**, digite **ZERAR** e clique **Zerar dados operacionais**.

A ação remove CVEs/enriquecimentos, execuções (incluindo as que estão na fila) e histórico de entregas da aplicação. Contas, sessões, assinaturas e configuração da programação são preservadas. A limpeza é transacional e recusada se houver coleta ou envio ativo.

A próxima execução programada é recalculada conforme o intervalo configurado; a próxima coleta completa estabelece uma nova base sem alertas retroativos. Para preencher a base imediatamente, solicite uma execução manual com limite **0**. Mensagens já capturadas no Mailpit são gerenciadas na própria caixa.

## Conceitos e interpretação

| Termo | Significado |
|---|---|
| CVE | Identificador de uma vulnerabilidade; não é uma nota. |
| KEV | Catálogo de vulnerabilidades com evidências de exploração, mantido pela CISA. |
| CWE | Classificação do tipo de fraqueza. |
| CVSS | Avaliação de severidade técnica, de 0 a 10, acompanhada de versão, fonte e vetor. |
| CPE | Identificação padronizada de produtos; participa de condições de aplicabilidade. |

`Unknown` em ransomware significa **não confirmado**, não ausência de uso. O prazo da CISA não é uma obrigação universal. Contagens por fornecedor não medem sua segurança. O KEV não representa todas as vulnerabilidades publicadas.

A avaliação principal usa a ordem **4.0 → 3.1 → 3.0 → 2.0**, depois `Primary`, fonte NVD e ordem alfabética da fonte. Todas as avaliações continuam disponíveis. Ausência não vira score zero. Condições CPE, operadores e limites inclusivos/exclusivos são preservados; a aplicação não diagnostica inventários automaticamente.

Datas operacionais são UTC; datas NVD sem offset são explicitadas como UTC. O navegador apresenta horários no seu fuso. Datas CISA de inclusão/prazo são datas de calendário.

## Identidade e e-mails locais

Cognito Local **5.3.0** oferece cadastro, confirmação e login via SDK. A confirmação é simulada com código **123456**, conforme informado na interface. Ela não comprova propriedade do e-mail. Os alertas são enviados por SMTP ao Mailpit, não para caixas externas.

As sessões usam identificadores aleatórios em cookies `HttpOnly`, `SameSite=Strict`, proteção CSRF e tokens assinados RS256 validados por JWKS, issuer, app client, expiração e tipo. O endpoint interno de JWKS pode ser `http://cognito:9229`, enquanto o issuer do emulador é `http://0.0.0.0:9229`.

## Coleta independente

Com a aplicação ou somente os serviços de infraestrutura disponíveis:

```bash
# Uma página HTML; 0 ou ausência do argumento percorre o catálogo completo.
docker compose run --rm --no-deps worker python -m app.cli collect --pages 1

# Logs do processamento agendado e SMTP.
docker compose logs -f worker
```

O comando não depende das rotas FastAPI. O worker também executa `python -m app.cli worker`, consultando a fila a cada cinco segundos. Execuções concorrentes respeitam a reserva global do coletor.

## Testes e cobertura

```bash
python3 -m venv .venv
.venv/bin/pip install -c constraints.txt -e '.[test,browser]'
docker compose up -d --wait mongo cognito mailpit
.venv/bin/ruff check app tests scripts
.venv/bin/black --check app tests scripts
.venv/bin/pytest --cov --cov-report=term-missing --cov-report=json:.coverage.json
.venv/bin/python scripts/check_coverage.py
node --check app/presentation/static/app.js
```

Os testes usam MongoDB replica set, Cognito Local e SMTP/Mailpit reais. Bancos de teste são isolados e removidos ao término. HTML e respostas NVD controladas tornam a verificação de parsing e regras independente da disponibilidade externa.

A meta é **85% de linhas e 85% de branches**, verificadas separadamente por `scripts/check_coverage.py`. O relatório opcional HTML é gerado com `--cov-report=html`.

Para os testes de navegador, mantenha a aplicação com a carga inicial concluída e as credenciais do administrador no `.env`:

```bash
.venv/bin/playwright install chromium
.venv/bin/pytest -m browser tests/test_browser.py
```

Eles exercitam investigação, cadastro, login, assinatura com destinatário alternativo, teste SMTP, simulação pelo admin, Mailpit, redirecionamento seguro, seleção por teclado e navegação móvel. O teste ponta a ponta exclui sua assinatura de teste ao terminar.

## Qualidade de código

[Ruff](https://docs.astral.sh/ruff/) faz o lint (erros, imports ordenados com `I`, bugbear `B` e modernização `UP`) e [Black](https://black.readthedocs.io/) formata o código. Ambos usam linha de 100 colunas e Python 3.12, configurados em `pyproject.toml`, e são instalados com o extra `test`.

```bash
.venv/bin/ruff check app tests scripts          # lint
.venv/bin/ruff check --fix app tests scripts    # lint com correções automáticas
.venv/bin/black app tests scripts               # formata
.venv/bin/black --check app tests scripts       # só verifica (CI)
```

`B008` (`Depends` em argumentos padrão) e `B904` (encadeamento de exceções nas rotas) ficam desativadas por serem o idioma usado com FastAPI neste projeto.

## Documentação

- [Arquitetura e responsabilidades](docs/ARCHITECTURE.md)
- [Estrutura do banco e garantias](docs/DATABASE.md)
- [Endpoints e exemplos](docs/API.md)
- [Roteiro da demonstração](docs/DEMONSTRATION.md)

Chart.js 4.4.8 e Public Sans são distribuídos localmente com suas licenças em `app/presentation/static/vendor/`. Os dados KEV possuem [licença CC0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt). O uso da NVD é identificado na interface, sem sugerir endosso.
