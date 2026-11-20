# Arquitetura do portal cativo

**Etapa 10.1 · Proposta para o protótipo acadêmico**

## Objetivo

Permitir que um usuário autenticado por passkey solicite acesso à internet para o dispositivo conectado à rede Wi-Fi restrita. A primeira implementação será validada com um gateway simulado. Uma etapa posterior vai avaliar OpenWrt com openNDS em uma rede de laboratório.

**A sessão autenticada responde quem é o usuário. A sessão de rede identifica qual conexão o gateway pode liberar.** Uma passkey verificada ou um cookie válido, por si só, não concede acesso à rede. O portal só anuncia a liberação após confirmação do gateway.

## Arquitetura e reaproveitamento

```mermaid
flowchart LR
    D["Dispositivo e navegador"] -->|"Conexão Wi-Fi restrita"| G["Gateway · aplicação da política de rede"]
    D -->|"HTTPS"| P["Portal web"]
    P -->|"Mesma origem · cookie e CSRF"| A["SafeNet-ZKP API"]
    A --> C["Application · política e coordenação"]
    C --> S[("PostgreSQL · identidade e sessões")]
    C --> I["ICaptivePortalGateway"]
    I -.-> M["Adaptador simulado"]
    I -.-> N["Adaptador openNDS / FAS"]
    M -->|"Estado simulado"| G
    N -->|"Integração autenticada"| G
```

As duas opções de adaptador são alternativas de implantação. No simulador, o gateway e a aplicação da política são representados por estado controlado no laboratório. No cenário real, o gateway controla o tráfego e a API coordena a decisão.

| Componente | Responsabilidade | Reaproveitamento |
|---|---|---|
| Portal web | Exibir o estado, iniciar o login e enviar a solicitação de acesso na mesma origem da API | A página experimental ilustra a chamada WebAuthn. A interface futura terá seu próprio fluxo e não dependerá da página de teste. |
| Backend SafeNet-ZKP | Confirmar identidade e sessão, validar a associação ao dispositivo, aplicar a política e coordenar a operação com o gateway | Os controllers WebAuthn existentes verificam as passkeys. `HttpCurrentUserContext` implementa `ICurrentUserContext` e resolve a identidade a partir do principal. O esquema de cookies, a autorização e o CSRF continuam sendo a fronteira das operações do navegador. |
| Sessão autenticada | Representar a sessão do usuário, hoje com validade de 20 minutos, sem renovação automática | `AuthenticatedSession`, `AuthenticatedSessionService` e `IAuthenticatedSessionRepository`. A integração futura precisa expor internamente a referência da sessão já validada e seu prazo, sem repassar o valor bruto do ticket. |
| Sessão de rede | Representar uma conexão observada pelo gateway, com identidade opaca, geração, estado e prazo próprios | Conceito novo. Uma reconexão que exija nova autorização recebe outra geração. O vínculo usa a sessão autenticada específica e a tupla gateway, sessão de rede e geração. |
| Gateway | Observar a conexão e aplicar, expirar e retirar a liberação de tráfego | Fonte de verdade para a sessão de rede e a liberação efetiva. IP e MAC podem ser atributos observados internamente pelo gateway, com alcance local e validade limitada. |
| Adaptadores | Traduzir consulta, liberação e revogação em operações do simulador ou do equipamento | Porta de saída sugerida em Application. Implementações futuras em Infrastructure, selecionadas pela composição da API. |

O projeto **Domain** já define `User`, `WebAuthnCredential` e `AuthenticatedSession`. Uma futura regra de concessão pode viver no domínio sem depender de ASP.NET Core, EF Core ou openNDS. **Application** já fornece os contratos de identidade e persistência. **Infrastructure** implementa os repositórios PostgreSQL, os serviços FIDO2 e o cache de desafios. **Api** mantém o controle de HTTPS, cookies, autorização e rate limiting. O login e a inscrição WebAuthn funcionam hoje em Development. A escolha de como habilitar um laboratório real fica para uma etapa própria.

## Fluxo de autorização de rede

```mermaid
sequenceDiagram
    actor U as Usuário e dispositivo
    participant G as Gateway
    participant S as Portal e SafeNet-ZKP
    participant W as WebAuthn existente
    U->>G: Conecta à rede restrita
    G->>G: Cria sessão de rede restrita e sua geração
    G->>S: Registra contexto temporário por canal autenticado
    G-->>U: Orienta a abrir o portal HTTPS
    U->>S: Abre portal com referência opaca
    S->>G: Confirma referência e vínculo com a conexão observada
    U->>W: Autentica com passkey
    W-->>U: Cookie de sessão autenticada
    U->>S: Solicita acesso com a sessão e CSRF
    S->>S: Revalida e consome a associação de forma atômica
    S->>G: Solicita liberação com identificação da operação e prazo
    alt Liberação confirmada para a geração atual
        G-->>S: Concessão ativa com prazo efetivo
        S-->>U: Acesso liberado
    else Recusa ou resultado incerto
        G-->>S: Recusa ou ausência de confirmação
        S-->>U: Acesso pendente ou indisponível
    end
    G->>G: Encerra a concessão no prazo ou ao desconectar
```

1. **Conectar e identificar.** O gateway começa com tráfego restrito e cria a sessão pela conexão que observa. No laboratório real, a rede pré-autorizada permite os destinos necessários para descoberta, DNS e portal HTTPS com certificado confiável. O acesso normal à internet permanece bloqueado.
2. **Abrir o portal.** O navegador recebe apenas uma referência opaca, curta e de uso único. O contexto correspondente é registrado pelo gateway em canal autenticado e vinculado a gateway, sessão, geração, finalidade, emissão e expiração. Se a referência entrar em uma URL, trocá-la por estado de navegação do servidor e redirecionar para uma URL limpa antes de navegar externamente. Impedir cache, propagação por `Referer` e registro de referências sensíveis.
3. **Confirmar o dispositivo.** Validar a procedência do contexto e comprovar que a navegação veio da conexão observada pelo gateway por um mecanismo confiável de ingresso ou desafio vinculado ao cliente nessa rede. O artefato de abertura sozinho é transferível e não prova essa posse. O vínculo deve sobreviver ao login no estado do servidor. Se a implantação não conseguir revalidar a conexão no momento da associação, manter o acesso restrito. No simulador, a associação é produzida pelo gateway fictício em ambiente controlado e sua validade fica limitada ao teste.
4. **Autenticar o usuário.** Reutilizar login WebAuthn e cookie existentes. Passkeys estão vinculadas ao RP. O portal e a API devem usar uma origem HTTPS compatível com o RP configurado. A troca para navegador completo, quando necessária, exige nova correlação confiável entre a navegação e o dispositivo.
5. **Associar e solicitar.** A ação do usuário deve ser um POST autenticado e protegido contra CSRF. O backend obtém do servidor a sessão autenticada e o contexto de rede, confirma que ambos continuam válidos e reserva atomicamente a associação. Os identificadores enviados pelo navegador são apenas referências. IP, MAC, cabeçalhos encaminhados por clientes e IDs arbitrários não autorizam acesso.
6. **Confirmar.** Enviar ao gateway uma operação idempotente para aquela geração. Aceitação de uma solicitação assíncrona significa pendência. Só apresentar acesso liberado depois de obter estado autoritativo da concessão, por consulta ou evento autenticado.
7. **Encerrar.** O gateway aplica um prazo local limitado ao menor entre o tempo restante da sessão autenticada, o máximo da política de rede e o limite do equipamento. Desconexão ou troca de geração encerra o acesso daquela conexão. Logout revoga a sessão autenticada e deve solicitar a revogação das concessões vinculadas a ela, por mecanismo confiável de entrega e reconciliação. Em caso de indisponibilidade, o prazo local limita o acesso residual. A confirmação da rede é independente do resultado do logout web.

### Falhas e concorrência

| Situação | Comportamento proposto |
|---|---|
| Gateway indisponível antes da liberação | Manter a restrição e mostrar indisponibilidade. Usar timeout e tentativas limitadas dentro do prazo original. |
| Timeout depois do envio | Tratar como resultado desconhecido. Consultar a mesma operação antes de declarar sucesso ou erro. Repetir apenas com a mesma chave e o mesmo conteúdo válidos. |
| Solicitação duplicada | Retornar o mesmo resultado ao mesmo contexto vinculado. Reutilizar a chave com conteúdo divergente gera conflito. A repetição não cria nova concessão nem estende a vigência. |
| Referência reutilizada, vencida ou apresentada por outra conexão | Recusar a associação, inclusive em corrida entre requisições. A reserva atômica permite uma única associação. Uma referência copiada ou a geração anterior não pode iniciar nova concessão. |
| Logout, reconexão ou expiração enquanto a solicitação está pendente | Invalidar a solicitação local e rejeitar confirmação tardia. O gateway deve rejeitar geração ou revisão obsoleta. Se uma liberação já estiver em vigor, reconciliar e revogar a concessão específica. |
| Revogação sem confirmação | Manter o estado de encerramento pendente, repetir de forma idempotente sem atingir uma concessão posterior e respeitar a expiração local no gateway. |

## Contratos sugeridos

`ICaptivePortalGateway` seria uma porta de saída de Application. As assinaturas abaixo são propostas de documentação.

| Operação | Entrada | Saída |
|---|---|---|
| `GetSessionAsync` | Gateway, referência interna da sessão de rede e geração | Estado observado, prazo e concessão vigente, ou sessão ausente |
| `AuthorizeAsync` | Sessão de rede e geração, ID da concessão, ID da operação, revisão, limite de validade da solicitação e expiração máxima do acesso | Aplicada, pendente ou recusada, com identificador de correlação |
| `GetOperationAsync` | Gateway e ID de operação já conhecido pelo backend | Pendente, confirmada, recusada, expirada ou desconhecida, com o prazo efetivo quando disponível |
| `RevokeAsync` | Sessão de rede e geração, ID da concessão, ID da operação de revogação e revisão | Encerrada, já encerrada, pendente ou recusada |

As operações aceitam cancelamento. Cancelar a espera local não cancela uma ação que já chegou ao gateway. A entrada de contextos ou notificações do gateway é uma fronteira distinta, autenticada e validada pelo adaptador. O contrato não transporta cookies, credenciais WebAuthn nem dados pessoais desnecessários.

Para o futuro canal entre serviços, preferir TLS mútuo com identidade segregada por gateway se a implantação permitir. Um agente de integração pode terminar esse canal quando o equipamento não oferecer a capacidade nativamente. Vincular cada mensagem à identidade do remetente, destinatário e operação, e verificar validade com tolerância de relógio limitada. A política deve manter o histórico de idempotência pelo menos durante a janela de aceitação de mensagens. Usar geração e revisão monotônica para ordenar concessão e revogação e impedir que mensagens atrasadas reabram o acesso. Somente o simulador em processo pode substituir o canal de rede por chamadas internas com origem controlada.

### Contrato implementado na etapa 10.2

A porta mantém as quatro operações propostas. `AuthorizeAsync` recebe também uma associação interna previamente verificada. `RevokeAsync` inclui o prazo da solicitação, assim como `AuthorizeAsync`. O identificador da operação permite consultar o resultado pelo gateway correspondente. Uma leitura retorna o estado observado naquele instante, portanto uma consulta posterior à expiração ou revogação nunca confirma uma concessão antiga como ativa.

No simulador, o ingresso emite uma instância de observação e uma referência aleatória temporária, armazenada apenas como hash. A associação precisa da instância original, da referência e da identidade fornecida pelo chamador confiável. A consulta retorna uma cópia informativa que não vale como prova. O primeiro vínculo consome a referência e fixa usuário e sessão autenticada durante a geração. Uma reconexão explícita invalida a geração anterior e permite nova associação. A referência GUID da sessão autenticada é interna e sintética nesta etapa. A etapa 10.3 precisa obter ou mapear uma referência de sessão a partir do contexto autenticado do servidor.

| Estado | Interpretação e transição |
|---|---|
| `Pending` | Reservado para adaptadores assíncronos. A consulta pode confirmar, recusar ou apontar encerramento. |
| `Indeterminate` | O chamador ainda desconhece o resultado. No cenário de timeout do simulador, o acesso já foi aplicado, mas a primeira resposta omite a concessão. A consulta ou uma repetição idêntica revela o estado vigente. |
| `Denied` | A solicitação foi recusada. Não há liberação para essa operação. |
| `Authorized` | Concessão ativa e confirmada. Pode expirar, ser revogada ou ser encerrada por mudança de geração. |
| `Expired` e `Revoked` | Estados terminais da concessão. Um novo acesso na mesma geração exige associação ainda válida, outra concessão, nova operação e revisão superior. |

O simulador serializa as alterações em um único processo e calcula prazos com `TimeProvider`. A revogação pode chegar antes da autorização e reservar o ID da concessão como encerrado, impedindo a aplicação de um comando atrasado. Os registros de operação e de concessão permanecem em memória até o encerramento do processo. O simulador não representa persistência, perda real de conectividade nem aplicação de política sobre tráfego.

O adaptador real deve validar a identidade do gateway no canal entre serviços, conferir geração, revisão, vigência e conteúdo das mensagens, e correlacionar confirmações com a concessão, o dispositivo e a operação esperados. A confirmação deve vir de consulta autoritativa ou evento autenticado que represente a política aplicada. A identidade do usuário e o contexto da sessão não devem ser repassados ao equipamento.

### Orquestração implementada na etapa 10.3

`NetworkAccessService` recebe um `ICurrentUserContext` confiável e o identificador extraído do ticket autenticado, em um `NetworkAccessCaller` criado no servidor. O serviço de sessões aplica a mesma condição de atividade usada pelo cookie e lê o vencimento persistido sem alterar o fluxo WebAuthn. Para manter o GUID previsto no contrato da etapa anterior, deriva uma referência interna de 128 bits a partir do hash SHA-256 do identificador. O identificador original não entra na associação nem nas operações do gateway. O vínculo exige a identidade e a sessão autenticada específica, inclusive para duas sessões do mesmo usuário.

`ICaptivePortalAssociationGateway` é uma porta separada para verificar a observação e consumir a referência uma única vez, de forma atômica. O caso de uso confere o vínculo retornado antes de criar uma associação utilizável. O adaptador simulado reutiliza a verificação da etapa 10.2. A origem da observação e do contexto autenticado pertence à composição confiável do servidor. O navegador nunca deve construir esses objetos.

Os objetos de operação são criados no servidor e retêm a mesma concessão, revisão, prazo e chave de idempotência ao repetir. A revisão e os limites de tempo são fornecidos pela composição confiável. O prazo de acesso é limitado pela sessão autenticada e pela conexão observada. Após o prazo de envio, uma repetição só consulta a operação. Confirmações precisam corresponder à operação, concessão e conexão esperadas. O caso de uso revalida a sessão antes de devolver acesso confirmado. Um timeout ou uma falha de transporte ao enviar ou consultar uma concessão resulta em `Indeterminate`. Falha na verificação da associação impede a concessão.

**Logout web e encerramento da rede continuam separados.** Uma sessão web revogada impede novas operações do usuário, inclusive confirmação tardia. Se o gateway já tiver aplicado acesso, ele pode mantê-lo até o vencimento local. O logout existente revoga o ticket no PostgreSQL, sem chamar o gateway. A revogação antecipada automática após logout exigirá um fluxo de serviço independente da sessão já revogada, entrega confiável e reconciliação. A ação explícita de revogar pelo caso de uso exige a sessão proprietária ativa.

Para a etapa 10.4, a composição deverá resolver o ticket no servidor, guardar associações e operações por sessão, alocar revisões concorrentes de modo seguro e reutilizar a operação durante uma repetição. Cada execução concorrente com PostgreSQL deve usar seu próprio escopo de repositório. O simulador e os objetos internos atuais perdem estado ao reiniciar. Antes de integrar múltiplas instâncias ou um gateway real, definir a persistência, a origem verificável da observação e a coordenação do encerramento de rede.

### Persistência e logout na etapa 10.4A

`PersistentNetworkAccessService` é a entrada de Application para o fluxo durável. A associação usa a prova viva verificada pelo gateway e grava gateway, conexão, geração, usuário, hash SHA-256 completo da sessão e datas UTC. Consultas e pedidos de revogação exigem a mesma sessão ativa, inclusive quando o usuário possui outras sessões. O hash, embora protegido contra a recuperação do identificador de alta entropia, é um dado interno. O banco não recebe o cookie, o identificador bruto nem a prova temporária. O vínculo histórico não tem exclusão em cascata a partir da sessão, para preservar revogações pendentes quando a retenção de sessões for definida.

A migration `20261120155643_AddPersistentNetworkAccess` cria `NetworkAccessAssociations` e `NetworkAccessOperations`. Aplicar a migration explicitamente antes de usar esta versão, inclusive para o logout web. A API não aplica migrations na inicialização.

- A associação é única por gateway, conexão e geração. Reservar uma autorização bloqueia primeiro a sessão ativa e depois a associação no PostgreSQL. As restrições únicas protegem a chave de idempotência por associação, a revisão e os IDs das concessões e revogações.
- A primeira reserva fixa o ID da operação, o ID da concessão, a revisão e os prazos. Repetir a chave preserva esses valores e não estende a vigência. A revisão seguinte fica reservada para revogação antes mesmo de o gateway confirmar o acesso. Após o prazo de envio, o caso de uso só consulta. Um reinício sem a observação viva permite consultar pedidos persistidos, mas não repetir o envio de autorização com uma prova recriada.
- A linha de operação funciona como **outbox da revogação**. A escrita que revoga a sessão web registra também a intenção de revogar todas as concessões potencialmente aplicadas daquela sessão, na mesma transação. O logout pode retornar `204` após o commit e a remoção do cookie. Esse retorno confirma o logout web. O estado da rede pode permanecer pendente.
- `NetworkRevocationProcessor` lê pedidos pendentes e indeterminados sem precisar de uma sessão web ativa. Consulta ou envia pelo mesmo ID de revogação e revisão, sem manter transação aberta durante a chamada ao gateway. Processos concorrentes podem repetir a entrega, que exige idempotência no gateway. Respostas sem correlação permanecem indeterminadas. Uma atualização condicional impede que uma confirmação de autorização atrasada substitua a intenção de revogar ou reabra um estado terminal.
- Para o laboratório, `CaptivePortal__ProcessRevocations=true` habilita em Development o consumidor em lotes após a aplicação da migration. Se estiver desativado, a intenção permanece persistida para processamento posterior. A perda do simulador impede confirmar operações antigas. Nesse caso o pedido pode permanecer indeterminado até o prazo máximo originalmente imposto à concessão. `Expired` registra esse limite, enquanto `Revoked` exige confirmação correlacionada do gateway. O adaptador real precisa garantir a vigência máxima no equipamento para essa distinção ser válida.

Na 10.4B, os endpoints devem extrair o principal e o identificador do ticket já validado, montar `NetworkAccessCaller` no servidor, resolver a observação em contexto confiável e reutilizar a chave de idempotência nas repetições. As operações que alteram estado devem exigir HTTPS e CSRF. A resposta ao cliente deve distinguir logout web, revogação de rede pendente, resultado indeterminado e confirmação. Ainda é necessário definir como reter a capacidade viva entre requisições e a política de retenção do histórico.

### API experimental na etapa 10.4B

As rotas abaixo usam o prefixo `/api/captive-portal` e só são registradas em Development. Exigem HTTPS e o cookie autenticado. Todos os POSTs exigem o cabeçalho `X-CSRF-TOKEN` obtido em `GET /api/auth/csrf`. O limite por IP e minuto é de 12 escritas e 60 leituras. As respostas não devem ser armazenadas em cache.

| Operação | Contrato |
|---|---|
| `POST /associations` | Recebe `reference` e retorna `201` com `associationId` apenas se houver uma observação preparada para a sessão e a associação for consumida com sucesso. |
| `POST /operations` | Recebe `associationId` e `idempotencyKey` (GUID). O servidor fixa até um minuto para envio e cinco minutos de acesso, limitados pelo vínculo e pela sessão. Repetir a mesma chave. Uma associação sem capacidade viva retorna `404`. Uma reserva recusada pelo estado da associação retorna `409`. |
| `GET /operations/{operationId}` | Consulta ou reconcilia operação da sessão atual. Retorna `200` com `operationId` e `state`. O campo `expiresAt` tem valor apenas quando o acesso está confirmado. |
| `GET /grants` | Lista até 50 registros da sessão atual em ordem recente, com `operationId`, `lastKnownState` e `accessUntil`. A lista descreve o histórico local. Consultar a operação para confirmar o estado atual. |
| `POST /operations/{operationId}/revocation` | Solicita revogação idempotente da operação pertencente à sessão. O processamento usa a fila transacional existente e precisa do consumidor configurado. |

Nas escritas de autorização e revogação, `202` com `Location` indica estado `pending` ou `indeterminate`. `200` informa estado confirmado ou terminal. Uma recusa do gateway pode retornar `403` com `denied`; uma operação ausente ou de outra sessão retorna `404`. A API revalida a sessão após o caso de uso. Quando detecta revogação durante a requisição, retorna `401` sem confirmação de acesso. Falha de armazenamento após a validação inicial pode retornar `503`; falha ao validar o cookie pode resultar em `401`. Um timeout do gateway após a reserva mantém a operação indeterminada.

`CaptivePortalIngress` recebe observações apenas de código confiável em processo, depois que esse produtor comprovar o vínculo da conexão à sessão web. Guarda a observação e o vínculo vivo por prazo limitado e chaves derivadas de hash. O navegador apenas localiza uma observação já preparada para sua sessão. O serviço de aplicação e o gateway ainda validam a instância da observação e o uso único da referência. Os testes preparam observações diretamente no simulador. A API atual não tem produtor HTTP ou integração de gateway que faça essa comprovação, portanto novas associações e autorizações ficam indisponíveis por padrão. A perda do cache impede novas utilizações da capacidade viva, mas as consultas e revogações continuam usando o estado persistido.

Na etapa 10.5, a interface pode consumir os estados e seguir `Location` para reconciliação. Deve diferenciar estado histórico e confirmado, mostrar que o logout web e o encerramento de rede são operações distintas, e manter as ações de associação bloqueadas enquanto não houver ingresso confiável configurado.

## Padrões e integração openNDS

| Referência | Escopo e implicação |
|---|---|
| RFC 8952 | Documento informativo de arquitetura. Orienta a separação entre provisionamento, API consultada pelo cliente, portal do usuário e aplicação da política. [RFC 8952](https://www.rfc-editor.org/rfc/rfc8952) |
| RFC 8908 | Padrão para a API CAPPORT consultada pelo cliente. Exige TLS com certificado válido, resposta `application/captive+json` e campo `captive`. Pode fornecer a URL do portal e o tempo restante. O estado deve refletir o dispositivo consultado e a aplicação efetiva da política. [RFC 8908, §§ 4–5](https://www.rfc-editor.org/rfc/rfc8908#section-4) |
| RFC 8910 | Padrão de descoberta da URI da API CAPPORT via DHCPv4 (opção 114), DHCPv6 e anúncios de roteador IPv6. A URI provisionada aponta para a API de estado, distinta da página de login. [RFC 8910, § 2](https://www.rfc-editor.org/rfc/rfc8910#section-2) |
| openNDS/FAS | Integração de fornecedor. O FAS verifica as credenciais e o openNDS aplica a liberação no firewall. A documentação descreve HTTPS e Authmon nos níveis 3 e 4 do FAS. Avaliar o modo suportado pela versão escolhida e validar em laboratório como obter confirmação, revogar e impor a vigência efetiva. [Documentação oficial do FAS](https://opennds.readthedocs.io/en/stable/fas.html) |

Passkeys, cookie de 20 minutos, associação de uso único, canal entre serviços e política de concessões são decisões do SafeNet-ZKP. A API CAPPORT para clientes e o contrato interno de comando do gateway têm finalidades distintas. A simulação inicial não implica conformidade CAPPORT nem compatibilidade verificada com FAS.

## Comparação, riscos e limitações

| Aspecto | Simulado | OpenWrt com openNDS |
|---|---|---|
| Origem da sessão de rede | Eventos sintéticos emitidos pelo simulador | Conexão observada pelo gateway e traduzida pelo adaptador |
| Efeito da concessão | Transição de estado verificável | Liberação de tráfego aplicada no equipamento |
| Prazo e revogação | Relógio controlado e falhas determinísticas | Resolução de prazo e confirmação dependentes da versão e do mecanismo disponível. Arredondar para baixo ou recusar a liberação se o prazo máximo não puder ser respeitado. |
| Cobertura | Exercita regras, concorrência e falhas da aplicação | Exige validar descoberta, IPv4 e IPv6, isolamento, DNS, portal HTTPS, restrições pré-autorização e comportamento de clientes reais |

- **Vínculo com o dispositivo.** A passkey identifica o usuário. A força do vínculo com a conexão depende do gateway e da topologia. Endereços podem mudar ou ser compartilhados. Sem comprovação confiável, o cenário fica restrito à demonstração.
- **Compatibilidade.** Mininavegadores de detecção de portal podem ter suporte incompleto a passkeys ou fechar ao detectar internet. Testar os sistemas-alvo e uma abertura segura no navegador completo.
- **Disponibilidade e observabilidade.** A API e o gateway podem divergir temporariamente. Registrar resultados e IDs de correlação internos, sem cookies ou referências de abertura, e definir reconciliação e retenção antes de persistir dados de rede. O cache WebAuthn e o rate limiting hoje são locais ao processo.

## Plano incremental

1. **10.2 · Simulação da política.** Implementar a porta e o adaptador em memória com relógio controlável, sob identidade de teste. Exercitar o caso de uso de associação, consulta, concessão e revogação. A aceitação exige confirmação explícita para o sucesso e testes de dois dispositivos, uso único, geração obsoleta, duplicata concorrente, timeout com resultado desconhecido, expiração e revogação. Começar sem portal público ou integração com firewall.
2. **Protótipo integrado.** Definir estado durável para associações, operações e revogação, incluindo recuperação após reinício. Integrar a interface HTTPS à autenticação existente e validar separadamente logout web e encerramento de rede com o simulador.
3. **Laboratório OpenWrt.** Fixar versões de OpenWrt/openNDS e testar FAS/Authmon, prova de vínculo, prazos, consulta e revogação em rede isolada. Só então incorporar descoberta e API CAPPORT conforme a interoperabilidade exigida e testar o tráfego real.

### Questões em aberto

- Qual domínio, RP ID e conjunto de navegadores serão usados no laboratório? O que fazer quando o navegador do portal não oferecer WebAuthn?
- Qual mecanismo do gateway comprovará o vínculo da navegação com a conexão, inclusive na passagem para o navegador completo?
- Quais são os prazos máximos de abertura, autorização e acesso? Qual política de reconexão e retenção se aplica às concessões?
- A versão de openNDS escolhida oferece confirmação e revogação suficientes para o contrato? Como o agente será autenticado e como as chaves serão provisionadas e rotacionadas?
