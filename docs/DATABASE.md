# Estrutura do MongoDB

Banco padrão: `vigilia`. MongoDB 7 em replica set `rs0`, necessário às transações entre documentos.

## `vulnerabilities`

Um documento por CVE, com índice único em `cve_id`:

```json
{
  "cve_id": "CVE-2021-44228",
  "vendor": "Apache",
  "product": "Log4j2",
  "product_key": "apache::log4j2",
  "title": "Apache Log4j2 Remote Code Execution Vulnerability",
  "description": "Descrição original da fonte",
  "action": "Ação recomendada pela fonte",
  "date_added": "2021-12-10",
  "due_date": "2021-12-24",
  "ransomware": "Known",
  "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  "references": [],
  "cwes": ["CWE-502"],
  "simulated": false,
  "revision": 1,
  "fingerprint": "hash dos campos de evidência, excluindo source_url",
  "first_collected_at": "BSON datetime UTC",
  "last_collected_at": "BSON datetime UTC",
  "nvd_status": "ready",
  "nvd_checked_at": "BSON datetime UTC",
  "nvd_updated_at": "BSON datetime UTC",
  "nvd": {
    "primary": {"version": "3.1", "score": 10.0, "severity": "CRITICAL"},
    "assessments": [],
    "descriptions": [],
    "weaknesses": [],
    "configurations": [],
    "references": [],
    "status": "Analyzed",
    "published": "ISO 8601 UTC",
    "last_modified": "ISO 8601 UTC",
    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  }
}
```

O exemplo mostra o formato, não reproduz todos os dados do CVE. Em produção local, cada avaliação inclui fonte, tipo, vetor e métricas originais. As configurações CPE preservam operadores, negações, identificadores e limites de versões. `primary` é `null` se não há avaliação.

## `subscriptions`

- `id`: UUID próprio, único.
- `owner`: `sub` validado do Cognito.
- `name`, `email`, `products`: nome, destinatário e lista de chaves fornecedor/produto.
- `changes`, `enabled`: preferências.
- `created_at`, `updated_at`: BSON datetime UTC.

Índices: `id` único e `owner`. Alteração e exclusão sempre filtram por `id` **e proprietário**.

## `outbox`

- `id`: identifica assinatura + execução; sem execução, assinatura + CVE + revisão.
- `owner`, `subscription_id`, `name`, `email`: snapshot do destino.
- `items`: CVE, revisão, tipo de evento, produto, título, ação e indicador sintético.
- `run_id`, `created_at`, `ready`: vínculo e liberação operacional.
- `status`: `pending`, `sending`, `sent`, `failed` ou `cancelled`.
- `attempts`, `next_attempt`, `claim`, `lease_until`, `finished_at`, `error`.

Índices: `id` único e `(status, next_attempt)`. Eventos de vários CVEs da mesma assinatura/execução são agrupados em uma entrega.

## `runs`

Identificador único `id`, solicitante, limite de páginas, datas, flag de carga inicial, estado, progresso, aviso e erro. Estados: `queued`, `running`, `completed`, `failed`.

`progress.pages` conta documentos de coleta: páginas HTML e eventual exportação de reconciliação. `new`, `changed` e `unchanged` contam operações de coleta; o total de CVEs únicos é consultado no catálogo. `enriched` e `missing` são resultados do enriquecimento.

## `settings`

Três documentos identificados por `_id`:

- `identity`: pool Cognito e app client.
- `schedule`: atividade, intervalo, limite, próxima execução e conclusão da base inicial.
- `collector`: reserva global, dono da execução e validade da reserva.

A reserva do coletor dura 15 minutos e é renovada por progresso. Uma reserva expirada permite recuperação e marca a execução interrompida como falha. Escritas CISA e confirmação de execução por um trabalhador que perdeu a reserva são recusadas.

## `sessions`

O `_id` é SHA-256 do identificador aleatório do cookie. Guarda token Cognito, CSRF e expiração. Índice TTL em `expires_at`; a expiração também é verificada nas consultas, sem depender da frequência do coletor TTL. Logout exclui a sessão.

## Garantias

1. **Identidade:** índice único CVE + upsert evita duplicação.
2. **Preservação:** primeira coleta não é sobrescrita; outros documentos não são apagados em recoletas.
3. **Atomicidade:** atualização do CVE e criação/agrupamento da outbox pertencem à mesma transação. Falha da outbox desfaz a alteração do CVE.
4. **Reservas:** coletor e entrega são adquiridos atomicamente. Confirmação de entrega verifica o identificador da reserva, impedindo confirmação por dono antigo.
5. **SMTP:** há persistência e novas tentativas, mas não garantia de exatamente uma entrega. Uma queda após aceitação SMTP e antes da confirmação pode duplicar o e-mail.
6. **Histórico:** revisões identificam mudanças, mas não preservam todas as versões de todos os campos. Alertas mantêm os snapshots que originaram o envio.
7. **Demonstração:** `simulated=true` é excluído de consultas públicas, produtos e estatísticas. Os eventos sintéticos aparecem nos históricos autorizados e no Mailpit.
