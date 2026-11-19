using Fido2NetLib;
using Fido2NetLib.Objects;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed class WebAuthnAuthenticationOptionsService(IFido2 fido2, WebAuthnAuthenticationStore store)
{
    public (string OperationId, AssertionOptions Options) Generate()
    {
        // Uma lista vazia permite autenticação com credenciais descobríveis.
        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = UserVerificationRequirement.Required
        });
        return (store.Store(options), options);
    }
}
