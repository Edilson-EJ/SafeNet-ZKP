# SafeNet-ZKP

Protótipo de autenticação com passkeys em .NET 10, ASP.NET Core, FIDO2/WebAuthn e PostgreSQL. A autenticação foi validada em ambiente de desenvolvimento. O módulo ainda exige decisões operacionais e de segurança antes de uma implantação.

## Arquitetura do backend

- **API** — expõe os fluxos WebAuthn e aplica autorização por padrão aos controllers. As exceções públicas são a sonda de disponibilidade e as etapas que antecedem uma sessão. As rotas sensíveis da API exigem HTTPS. Em Development, HTTP recebe `403` nessas rotas e a sonda continua disponível. Fora de Development, o redirecionamento HTTPS existente pode ocorrer antes desse bloqueio.
- **Domain** — representa usuários, credenciais, sessões, conexões observadas, concessões e seus estados.
- **Application** — coordena cadastro, sessão, associação, autorização, reconciliação e revogação. Define as portas de persistência, gateway e contexto de usuário.
- **Infrastructure** — verifica WebAuthn com Fido2NetLib, mantém provas temporárias em memória, implementa os repositórios EF Core/PostgreSQL e fornece o gateway simulado.

## Registro e login com passkeys

1. Em Development, `POST /api/webauthn/enrollment/start` cria uma conta experimental e emite um token temporário. `enrollment/options` consome a autorização inicial e gera o desafio de registro. `enrollment/complete` exige o mesmo token vinculado à operação e verifica a resposta antes de persistir a credencial.
2. Em Development, `POST /api/webauthn/authentication/options` inicia o login. `authentication/complete` exige HTTPS e uma origem que corresponda à requisição e à configuração do RP. O servidor consome o desafio, verifica a assinatura, a verificação do usuário e a titularidade da credencial, e atualiza seu contador quando aplicável.
3. Os grupos de cadastro e login têm janelas independentes por IP, de cinco requisições por minuto em cada grupo e por processo. As etapas do mesmo grupo compartilham a cota. Os desafios ficam em memória por cinco minutos e são de uso único neste processo.

A página `/webauthn-test/index.html` e a documentação interativa são exclusivas de Development. Para uma verificação manual no banco de teste já provisionado, o script `scripts/start-webauthn-test.ps1` valida o destino e inicia a API em `https://localhost:4200`.

## Sessões e logout

- Após verificar a passkey, a API gera 32 bytes aleatórios, grava apenas seu hash SHA-256 com o usuário e os horários UTC e, após a gravação, emite o cookie `__Host-SafeNetZKP`. O ticket protegido contém o identificador original e a identidade verificada. O cookie é `HttpOnly`, `Secure` e `SameSite=Strict`, com validade de 20 minutos e sem renovação automática.
- A cada requisição com um ticket válido, o esquema consulta o PostgreSQL para exigir uma sessão existente, do mesmo usuário, ativa e dentro da validade. Uma falha de leitura impede acesso autenticado. `GET /api/auth/me` devolve a identidade da sessão. A consulta por GUID responde `404` para recursos de terceiros.
- `GET /api/auth/csrf` fornece o token para o cabeçalho `X-CSRF-TOKEN`. Os POSTs autenticados de usuário exigem esse token. `POST /api/auth/logout` revoga a sessão atual e enfileira suas revogações de rede na mesma transação. O cookie é removido após a gravação. Outra sessão do mesmo usuário continua válida. A liberação simulada pode permanecer ativa até o worker obter confirmação ou até o prazo máximo local.

## Observação, associação e concessão simulada

1. O gateway envia uma observação por HTTPS assinada com HMAC-SHA256. O PostgreSQL grava o relato e consome atomicamente o nonce por gateway. O relato autenticado permanece separado da prova de origem do navegador.
2. No laboratório, código interno confiável prepara a observação viva para uma sessão WebAuthn. Uma referência aleatória de uso único, vinculada à sessão e à geração, permite consumir essa associação. A associação concluída é persistida. O ingresso temporário é perdido em reinícios.
3. A operação de autorização usa idempotência e só retorna `Authorized` após confirmação correlacionada do simulador. `Pending` é uma operação reservada e `Indeterminate` indica incerteza. O histórico local pode ficar defasado até a consulta individual reconciliar o estado.
4. A revogação explícita e o logout usam a fila persistida. O worker retoma a fila e confirma `Revoked` somente após evidência correlacionada. `Expired` representa o limite local. A aplicação física desse limite exige suporte do gateway real.

### Endpoints

| Rotas | Restrições |
|---|---|
| `GET /api/health` | Público. Sonda do processo, sem verificação do PostgreSQL ou do gateway. |
| `POST /api/webauthn/enrollment/{start,options,complete}` e `POST /api/webauthn/authentication/{options,complete}` | HTTPS, cotas por grupo e operações efetivas apenas em Development. Fora dele retornam indisponibilidade. |
| `GET /api/auth/{me,csrf}`, `POST /api/auth/logout`, `GET /api/users/{id}` e `POST /api/users` | HTTPS e sessão. A leitura de usuário é restrita ao titular. Os POSTs exigem CSRF, e a criação de usuário é restrita a Development. |
| `POST /api/captive-portal/gateway/observations` | HTTPS e mensagem HMAC, somente em Development. |
| `POST /api/captive-portal/associations`, `POST /api/captive-portal/operations`, `GET /api/captive-portal/operations/{id}`, `GET /api/captive-portal/grants` e `POST /api/captive-portal/operations/{id}/revocation` | Somente em Development. HTTPS, sessão proprietária e CSRF nos POSTs. A associação exige ingresso confiável já preparado. |

Consulte o protocolo HMAC, as transições e a política proposta de retenção na [arquitetura do portal cativo](docs/architecture/captive-portal.md).

## Data Protection e reinício

A API usa o armazenamento padrão de Data Protection do ASP.NET Core e separa os tickets por aplicação, ambiente e raiz de conteúdo (`SafeNet-ZKP:<ambiente>:<raiz-de-conteúdo>`). A introdução desse identificador exige novo login para cookies emitidos antes da Etapa 11.6. Em Windows, um processo com perfil disponível pode usar o diretório padrão `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys`. Verifique o local efetivo, permissões e proteção em repouso no perfil que executa o laboratório. Com o mesmo ambiente e raiz de conteúdo, o conjunto de chaves preservado e a sessão ativa no PostgreSQL, o cookie pode sobreviver ao reinício. A perda das chaves exige novo login. Desafios e autorizações de inscrição em andamento são perdidos ao reiniciar porque ficam em memória.

O teste de reinício usa um diretório temporário fora do repositório e um certificado efêmero de teste para cifrar as chaves. O isolamento pelo nome protege o uso normal do ticket em outro ambiente mesmo se a pasta for compartilhada. Para isolar também o acesso aos segredos, use contas, conjuntos de chaves e permissões separados por ambiente. A configuração padrão do perfil real precisa ser verificada antes do laboratório.

Para múltiplas instâncias, definir um repositório persistente de chaves compartilhado pela mesma implantação, nome de aplicação estável, isolamento entre ambientes, controle de acesso, criptografia em repouso e política de rotação e recuperação. Validar a leitura de tickets durante reinícios e atualizações antes da implantação. Referências da Microsoft sobre [persistência padrão](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/default-settings?view=aspnetcore-10.0) e [configuração de Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-10.0).

## Configuração de laboratório e testes

- Use .NET SDK 10, um certificado HTTPS confiável no cliente e PostgreSQL isolado com as migrations do repositório já aplicadas por procedimento explícito. A API não aplica migrations na inicialização. Nesta revisão, o esquema permaneceu o mesmo.
- O perfil documentado usa `https://localhost:4200`, `Fido2__RPID=localhost`, `Fido2__RPName` e `Fido2__Origins__0=https://localhost:4200`. Configure origens HTTPS como esquema, host DNS e porta quando não padrão, sem barra final. Cada host deve corresponder ao RP ID ou ser subdomínio dele. Em uma implantação de laboratório remota, use o domínio do certificado e valide o RP ID no navegador. Reinicie o host após mudar a configuração WebAuthn.
- Forneça a conexão da API por `ConnectionStrings__DefaultConnection` fora do código-fonte. O script de laboratório valida `SAFENET_TEST_CONNECTION_STRING` e a usa temporariamente como conexão da API. Configure `CaptivePortal__ProcessRevocations=true` antes de iniciar a API quando quiser habilitar o worker em Development. O script reduz o nível padrão de logs para `Warning`. Use uma configuração de nível específica para a categoria de auditoria se precisar dos eventos informativos.
- Uma chave HMAC é opcional para o fluxo WebAuthn. Para testes do canal do gateway, forneça `CaptivePortal__GatewayKeys__<uuid-canônico>` por configuração externa. Use um valor Base64 canônico para 32 bytes aleatórios e exclusivos por gateway e ambiente.

```powershell
dotnet test tests/SafeNetZKP.UnitTests
# Execute o projeto a seguir somente com a variável validada para safenet_zkp_test em 127.0.0.1:5433.
dotnet test tests/SafeNetZKP.IntegrationTests
```

Os testes HTTP usam ASP.NET Core TestServer, incluindo registro e asserção WebAuthn com dados criptográficos de teste. A suíte unitária/HTTP inclui um cenário PostgreSQL de reinício que é ignorado se a variável estiver ausente. O projeto de integração verifica o destino antes de abrir o banco e requer o esquema já preparado.

Mantenha Development em rede isolada. O cadastro é experimental e pode criar contas cujo registro não termina. Desafios, autorizações de inscrição e cotas são locais ao processo. Para testar múltiplas instâncias, defina primeiro o consumo distribuído e a limitação de tráfego. O laboratório simula concessões. Um gateway físico ainda precisa comprovar a origem da navegação, aplicar a política de acesso e expiração, confirmar resultados correlacionados e reconciliar operações depois de falhas ou reinício.

## Portal cativo Angular

O código do portal está em `SafeNetZKP.Portal/`. Use Node.js 24 LTS e execute na raiz do checkout:

```powershell
npm.cmd --prefix SafeNetZKP.Portal ci
npm.cmd --prefix SafeNetZKP.Portal test
npm.cmd --prefix SafeNetZKP.Portal run build
```

O build gera os arquivos estáticos em `SafeNetZKP.Api/wwwroot/captive-portal/`. Em Development, o ASP.NET Core serve esses arquivos e a API na mesma origem. O build precisa ser repetido após alterações no frontend.

Para testar com uma passkey real, use um certificado de desenvolvimento confiável (`dotnet dev-certs https --trust`) e uma `SAFENET_TEST_CONNECTION_STRING` já configurada para `safenet_zkp_test` em `127.0.0.1:5433`, com as migrations existentes aplicadas. Inicie a API com `./scripts/start-webauthn-test.ps1` e abra [o portal local](https://localhost:4200/captive-portal/index.html). Para cadastrar uma passkey de teste, use primeiro [a página experimental](https://localhost:4200/webauthn-test/index.html), na mesma origem. O portal faz login com passkeys cadastradas.

O portal distingue o histórico local da confirmação do gateway simulado e acompanha respostas `202` somente em rotas de operação da própria origem. A associação de novas conexões segue indisponível até existir ingresso confiável para o navegador. Consultas e revogação podem ser verificadas com concessões da mesma sessão preparadas por um ambiente de teste confiável. O logout termina a sessão web. A revogação de rede segue a fila existente até confirmação ou vencimento.
