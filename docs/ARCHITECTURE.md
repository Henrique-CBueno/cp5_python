# Arquitetura do Vigília

## Dependências

```text
presentation ──→ application ──→ domain
                      ↑             ↑
                      └── infrastructure

main.py / cli.py conectam contratos e implementações.
```

O domínio não importa FastAPI, MongoDB, HTTPX ou boto3. Pydantic é utilizado para validação dos valores do domínio. Detalhes MongoDB, incluindo filtros, índices e transações, permanecem no adaptador de persistência.

## Organização

| Diretório / entrada | Responsabilidade |
|---|---|
| `app/domain/` | Identidade CVE, invariantes, detecção de mudanças, avaliações CVSS e configuração de assinaturas. |
| `app/application/` | Coleta, enriquecimento, execução, assinatura, envio e simulação. Contratos para fontes e SMTP. |
| `app/infrastructure/` | Parsing CISA, NVD, MongoDB, Cognito e SMTP. |
| `app/presentation/` | Validação HTTP, autorização, endpoints, templates e recursos web. |
| `app/main.py` | Montagem do servidor FastAPI, middleware CSRF e ciclo de vida. |
| `app/cli.py` | Bootstrap, coleta manual e worker independente. |
| `app/worker.py` | Um ciclo: reservar execução, executar casos de uso e processar entregas. |

## Domínio

O contexto é o **acompanhamento de vulnerabilidades com exploração conhecida**:

- **Vulnerabilidade:** entidade identificada pelo CVE. Valida campos, datas e ransomware; produz a identidade fornecedor/produto e distingue novo, alterado e inalterado.
- **Avaliação CVSS:** valor validado com versão, score, severidade, fonte, tipo e vetor. Define a precedência usada para escolher a avaliação principal.
- **Assinatura:** configuração de produtos, destinatário, atividade e preferência por alterações. O proprietário vem da identidade autenticada, não do formulário.
- **Entrega:** snapshot dos eventos e do destinatário, com reserva, tentativas e estado. Recoleta idêntica não cria outro evento.

Um contexto e um catálogo são suficientes para o escopo. Não há eventos distribuídos nem broker: as entregas persistidas representam o trabalho assíncrono existente.

## Fluxos

### Coletar

1. Admin, programação ou CLI solicita uma execução.
2. O worker reserva a execução e o coletor, impedindo coletas simultâneas.
3. A fonte visita HTML paginado e, se necessário, reconcilia identificadores ausentes com a exportação oficial.
4. Cada CVE e suas entregas correspondentes são gravados na mesma transação.
5. A NVD enriquece a base; falhas mantêm dados anteriores e produzem aviso operacional.
6. O encerramento registra o resultado e libera entregas já confirmadas.

### Consultar

Templates entregam a estrutura da interface. JavaScript chama apenas endpoints FastAPI para dados de catálogo, filtros, gráficos, detalhes, assinaturas e administração. Não há consulta direta ao MongoDB pelo dashboard.

Filtros são critérios independentes do banco na aplicação. O adaptador MongoDB os traduz em consultas e agregações; busca literal escapa metacaracteres. Paginação afeta a listagem, enquanto estatísticas abrangem todo o conjunto filtrado.

### Notificar

O worker reserva uma entrega pronta, confirma que a assinatura continua ativa e envia pelo contrato SMTP. O adaptador gera um resumo textual com links, identificação da origem e indicação de demonstração quando aplicável. Falhas recebem novas tentativas persistidas; depois da quinta, uma ação admin permite reabrir a entrega.

## Verificação

Os testes atravessam as interfaces acordadas: casos de uso, HTTP, persistência/outbox e adaptadores. MongoDB, Cognito e Mailpit são exercitados realmente. O navegador verifica tarefas completas, sem substituir autenticação ou SMTP por mocks.
