# SafeNet-ZKP

Protótipo de autenticação com passkeys em .NET 10, ASP.NET Core, FIDO2/WebAuthn e PostgreSQL. A autenticação foi validada em ambiente de desenvolvimento. O módulo ainda exige decisões operacionais e de segurança antes de uma implantação.

## Arquitetura da autenticação

- **API** — expõe os fluxos WebAuthn e aplica autorização por padrão aos controllers. As exceções públicas são a sonda de disponibilidade e as etapas que antecedem uma sessão. As rotas sensíveis da API exigem HTTPS. Em Development, HTTP recebe `403` nessas rotas e a sonda continua disponível. Fora de Development, o redirecionamento HTTPS existente pode ocorrer antes desse bloqueio.
- **Application e Domain** — definem os casos de uso, o contexto do usuário, a entidade de sessão e os contratos de repositório.
- **Infrastructure** — verifica WebAuthn com Fido2NetLib, usa cache em memória para operações temporárias e persiste usuários, credenciais e sessões via EF Core e PostgreSQL.

## Registro e login com passkeys

1. Em Development, `POST /api/webauthn/enrollment/start` cria uma conta experimental e emite um token temporário. `enrollment/options` consome a autorização inicial e gera o desafio de registro. `enrollment/complete` exige o mesmo token vinculado à operação e verifica a resposta antes de persistir a credencial.
2. Em Development, `POST /api/webauthn/authentication/options` inicia o login. `authentication/complete` exige HTTPS e uma origem que corresponda à requisição e à configuração do RP. O servidor consome o desafio, verifica a assinatura, a verificação do usuário e a titularidade da credencial, e atualiza seu contador quando aplicável.
3. Os grupos de cadastro e login têm janelas independentes por IP, de cinco requisições por minuto em cada grupo e por processo. As etapas do mesmo grupo compartilham a cota. Os desafios ficam em memória por cinco minutos e são de uso único neste processo.

A página `/webauthn-test/index.html` e a documentação interativa são exclusivas de Development. Para uma verificação manual no banco de teste já provisionado, o script `scripts/start-webauthn-test.ps1` valida o destino e inicia a API em `https://localhost:4200`.

## Sessões e logout

- Após verificar a passkey, a API gera 32 bytes aleatórios, grava apenas seu hash SHA-256 com o usuário e os horários UTC e, após a gravação, emite o cookie `__Host-SafeNetZKP`. O ticket protegido contém o identificador original e a identidade verificada. O cookie é `HttpOnly`, `Secure` e `SameSite=Strict`, com validade de 20 minutos e sem renovação automática.
- A cada requisição com um ticket válido, o esquema consulta o PostgreSQL para exigir uma sessão existente, do mesmo usuário, ativa e dentro da validade. Uma falha de leitura impede acesso autenticado. `GET /api/auth/me` devolve a identidade da sessão. A consulta por GUID responde `404` para recursos de terceiros.
- `GET /api/auth/csrf` fornece o token para o cabeçalho `X-CSRF-TOKEN`. O logout e a criação direta de usuários exigem esse token. `POST /api/auth/logout` revoga atomicamente só a sessão atual e remove o cookie após a gravação. Outra sessão do mesmo usuário continua válida. Requisições que passaram pela validação antes da revogação podem terminar.

A migration `20261120133706_AddAuthenticatedSessions` define `AuthenticatedSessions` com chave primária no hash, restrição de 32 bytes, expiração posterior à criação, chave estrangeira para `Users` com exclusão em cascata e índices de usuário e expiração. A etapa 9.6 revisou o modelo e a migration. A confirmação dos índices no banco ativo depende de uma conexão de teste validada.

## Data Protection e reinício

A API usa a configuração padrão de Data Protection do ASP.NET Core. No perfil Windows inspecionado, havia um arquivo de chave no diretório padrão `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys`. Com o mesmo perfil, conjunto de chaves e isolamento da aplicação, um reinício pode preservar cookies ainda válidos que tenham sessão ativa no PostgreSQL. Se o host usar chaves efêmeras ou perder as chaves anteriores, os cookies deixam de ser legíveis e exigem novo login. Desafios e autorizações de inscrição em andamento são perdidos ao reiniciar porque ficam em memória.

Para múltiplas instâncias, definir um repositório persistente de chaves compartilhado pela mesma implantação, nome de aplicação estável, isolamento entre ambientes, controle de acesso, criptografia em repouso e política de rotação e recuperação. Validar a leitura de tickets durante reinícios e atualizações antes da implantação. Referências da Microsoft sobre [persistência padrão](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/default-settings?view=aspnetcore-10.0) e [configuração de Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-10.0).

## Revisão de segurança e pendências para o portal cativo

| Classificação | Resultado |
|---|---|
| **Falha corrigida** | Em Development, algumas leituras privadas e etapas de inscrição podiam ser processadas via HTTP, e a configuração WebAuthn aceitava uma origem HTTP. O pipeline agora bloqueia HTTP nas rotas sensíveis antes de processar autenticação ou payloads e exige origens HTTPS na configuração do RP. |
| **Risco de implantação** | O cadastro experimental é aberto em Development e cria contas mesmo se o registro da credencial não for concluído. Manter Development isolado e definir onboarding, recuperação e gestão de credenciais antes de habilitar WebAuthn fora desse ambiente. |
| **Risco operacional** | Desafios, autorizações de inscrição e quotas de IP são locais ao processo. Antes de distribuir tráfego, definir o consumo atômico de desafios em múltiplas instâncias e a estratégia de limitação. Validar o IP e o esquema encaminhados somente por proxies confiáveis e definir a política HTTPS/HSTS da implantação. |
| **Melhoria operacional** | As sessões expiradas e revogadas já são rejeitadas, mas os registros acumulam. Definir prazo de retenção e finalidade de auditoria antes de agendar limpeza. O índice de expiração pode apoiar a limpeza em lotes. Avaliar índice de revogação conforme a consulta e o volume reais. |
| **Integração pendente** | Definir o domínio HTTPS e RP ID do portal e validar a disponibilidade de WebAuthn nos navegadores usados pelos clientes do portal. Definir como a autorização de rede vai acompanhar o resultado da autenticação e o encerramento da sessão. |

## Testes da etapa 9.6

O comando `dotnet test tests/SafeNetZKP.UnitTests --no-restore -c Release` passou com **137 testes aprovados, zero falhas e zero ignorados**.

Os testes HTTP usam ASP.NET Core TestServer, passkeys sintéticas e repositórios em memória. Cobrem repetição de cookie revogado com uma segunda sessão ainda ativa, sessões inválidas, cookie adulterado, falhas de leitura e gravação, transporte HTTP e CSRF. O cenário de indisponibilidade usa uma falha simulada do repositório de sessão.

A suíte PostgreSQL compilou em Release. O contêiner isolado expôs `127.0.0.1:5433`, mas a checagem inicial recebeu `28P01` (autenticação recusada). A consulta ao catálogo e a suíte completa ficaram pendentes. Os nove testes PostgreSQL aprovados anteriormente são o resultado informado na entrada desta etapa. Para repetir a validação, usar uma `SAFENET_TEST_CONNECTION_STRING` válida para `safenet_zkp_test` nessa porta.
