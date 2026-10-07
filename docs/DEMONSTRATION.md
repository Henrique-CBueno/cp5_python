# Roteiro de apresentação

## Preparar

1. Execute `docker compose up -d --build --wait`.
2. Provisione o administrador com `docker compose exec web python -m app.cli bootstrap`.
3. Aguarde a carga inicial completa em `/admin`. Verifique total, último resultado e enriquecimento.
4. Abra três abas: Vigília, `/docs` e Mailpit em `http://localhost:8025`.
5. Tenha disponível a senha do `.env` ou a exibida na primeira criação.

## Mostrar o fluxo obrigatório

### 1. Crawler independente

No admin, solicite uma página e acompanhe a fila/progresso. Mostre também a entrada CLI:

```bash
docker compose run --rm --no-deps worker python -m app.cli collect --pages 1
```

Explique que HTTPX acessa páginas, BeautifulSoup extrai campos e segue a paginação; o limite controla as páginas HTML. Na carga completa, uma reconciliação oficial recupera CVEs que a fonte repetiu/omitiu entre páginas. O enriquecimento NVD usa lotes e pausas, portanto o estado `running` pode permanecer após a coleta HTML.

### 2. Persistência

Mostre no MongoDB um CVE e as datas. A inspeção pelo container é opcional:

```bash
docker compose exec mongo mongosh vigilia --quiet --eval 'db.vulnerabilities.findOne({cve_id:"CVE-2021-44228"}, {fingerprint:0})'
```

Mostre que a recoleta idêntica não duplica registros, preserva a primeira coleta e atualiza a última.

### 3. API

Em `/docs`, consulte listagem, um CVE e estatísticas. Aplique fornecedor ou ransomware. Explique paginação e filtros, além da separação entre dados reais e demonstrações.

### 4. Dashboard

- Busque `CVE-2021-44228` ou um produto.
- Selecione o CVE na primeira coluna: a inspeção muda sem perder a busca.
- Abra os detalhes: ação, avaliações, vetores, condições CPE e referências.
- No panorama, explique dois gráficos e dois indicadores além do total.
- Mostre que os filtros atualizam indicadores e gráficos de todo o conjunto.

## Demonstrar notificações

1. Crie uma conta de usuário ou use uma conta já cadastrada. A confirmação local usa `123456`.
2. Em **Meus alertas**, crie uma assinatura para um ou mais produtos, por exemplo Apache / Log4j2 e Microsoft / Windows.
3. Escolha outro e-mail para demonstrar o destinatário configurável.
4. Clique **Testar e-mail**; aguarde o worker e abra a mensagem no Mailpit.
5. Entre como administrador. Em **Demonstração de alerta**, escolha um produto da assinatura e simule uma nova vulnerabilidade.
6. Confira o histórico privado e a entrega SMTP. O e-mail indica **DEMONSTRAÇÃO** e descreve o evento sintético.
7. Mostre que o total real e os gráficos não aumentaram por causa da simulação.

Não é necessário esperar uma vulnerabilidade real surgir durante a apresentação. A simulação usa o mesmo caminho de correspondência, persistência transacional e envio.

## Explicar as decisões

- Clean Architecture separa domínio, casos de uso, infraestrutura e apresentação.
- DDD fornece identidade CVE, configuração de assinatura, avaliação CVSS e regras de mudança.
- MongoDB replica set permite gravar vulnerabilidade e outbox atomicamente.
- Worker separado mantém coleta independente da API e permite programação pelo admin.
- Cognito Local gerencia identidade; autorização e propriedade são verificadas no backend.
- Mailpit recebe SMTP local e permite demonstrar e-mails sem caixas externas.
- Testes verificam duplicidade, rollback, reservas, expiração, autorização, parsing, filtros e fluxo de navegador; cobertura mínima de 85% de linhas e decisões.
