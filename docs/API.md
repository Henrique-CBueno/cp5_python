# API do Vigília

Base: `http://localhost:8000`. Contrato completo e validações: `/openapi.json`; interface interativa: `/docs`.

## Consultas públicas

| Método / caminho | Retorno |
|---|---|
| `GET /api/vulnerabilities` | `items`, `total`, `page`, `page_size`. |
| `GET /api/vulnerabilities/{cve_id}` | Evidência CISA, enriquecimento NVD e datas de coleta; 404 se ausente ou sintético. |
| `GET /api/statistics` | Total, fornecedores, ransomware, cobertura CVSS, insights e séries dos gráficos. |
| `GET /api/products` | Chaves fornecedor/produto, nomes e contagens reais. |
| `GET /api/health` | Estado do serviço e comunicação com MongoDB. |
| `GET /api/session` | Usuário da sessão, quando válido, e token CSRF. |

Listagem e estatísticas aceitam os mesmos filtros, combinados por **AND**:

- `q`: busca literal, sem interpretar regex, em CVE/título/produto/fornecedor.
- `vendor`, `product_key`: valores do catálogo.
- `ransomware`: `Known` ou `Unknown`.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, `UNASSESSED`.
- `date_from`, `date_to`: inclusão CISA, formato `YYYY-MM-DD`.

Listagem: `page >= 1`; `page_size` de 1 a 100, padrão 20. A interface usa páginas de 10 registros. Estatísticas não recebem paginação.

```bash
curl 'http://localhost:8000/api/vulnerabilities?q=Log4j&page=1&page_size=10'
curl 'http://localhost:8000/api/vulnerabilities/CVE-2021-44228'
curl 'http://localhost:8000/api/statistics?ransomware=Known&severity=CRITICAL'
```

## Identidade e assinaturas

| Método / caminho | Ação |
|---|---|
| `POST /api/auth/signup` | Cadastro: `email`, `password`; 201. |
| `POST /api/auth/confirm` | Confirmação: `email`, `code`. Código local: `123456`. |
| `POST /api/auth/login` | Login: `email`, `password`; cookies e novo CSRF. |
| `POST /api/auth/logout` | Revoga sessão; 204. |
| `GET /api/subscriptions` | Assinaturas do proprietário autenticado. |
| `POST /api/subscriptions` | Cria assinatura; 201. |
| `PUT /api/subscriptions/{id}` | Atualiza somente assinatura própria. |
| `DELETE /api/subscriptions/{id}` | Exclui somente assinatura própria; 204. |
| `POST /api/subscriptions/{id}/test` | Agenda demonstração de entrega SMTP para assinatura própria ativa; 202. |
| `GET /api/alerts` | Até 100 entregas recentes do próprio usuário. |

Configuração de assinatura:

```json
{
  "name": "Produtos da infraestrutura",
  "products": ["apache::log4j2", "microsoft::windows"],
  "email": "destinatario@example.org",
  "changes": true,
  "enabled": true
}
```

Omitir `email` ou enviar `null` usa o endereço da conta. Produtos precisam existir na base. O proprietário é obtido da sessão; campos extras são recusados.

## Administração

Todos os caminhos abaixo exigem sessão com grupo `admin`:

| Método / caminho | Ação |
|---|---|
| `GET /api/admin/status` | Estado do catálogo, programação, execuções recentes e contagens de entrega. |
| `PUT /api/admin/schedule` | `enabled`, `interval_hours` (1–168), `max_pages` (0–1000). |
| `GET /api/admin/runs` | Até 50 execuções recentes. |
| `POST /api/admin/runs` | `max_pages` opcional; enfileira execução; 202. |
| `GET /api/admin/deliveries` | Até 100 entregas recentes. |
| `POST /api/admin/deliveries/{id}/retry` | Reabre uma entrega em `failed`; 202. |
| `POST /api/admin/simulate` | `product_key`; cria evento sintético identificado; 201. |
| `POST /api/admin/reset` | `{"confirmation":"ZERAR"}`; remove catálogo, execuções e histórico de entregas, preservando contas/assinaturas/configuração. 409 durante coleta ou envio ativo. |

## Cookies e CSRF

Operações mutáveis exigem `X-CSRF-Token` correspondente ao cookie. Em sessão autenticada, também deve corresponder ao registro da sessão. O login troca o token; obtenha o novo valor da resposta ou de `GET /api/session`.

Para usar curl, mantenha cookies com `-c`/`-b` em um arquivo local. Primeiro consulte `/api/session`, copie o campo `csrf` e use-o no header. Após login, use o novo valor. Arquivos de cookies e senhas não devem ser adicionados ao repositório.

Respostas comuns: 401 sem sessão válida; 403 por autorização/CSRF; 404 para recurso indisponível ao proprietário; 422 para dados/filtros inválidos; 409 se já há cinco solicitações aguardando; 503 se a identidade ainda não foi provisionada.
