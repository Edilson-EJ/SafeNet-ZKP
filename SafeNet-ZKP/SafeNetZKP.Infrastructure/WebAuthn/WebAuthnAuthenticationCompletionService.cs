using Fido2NetLib;
using SafeNetZKP.Application.Interfaces.Repositories;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed class WebAuthnAuthenticationCompletionService(
    IFido2 fido2,
    WebAuthnAuthenticationStore store,
    IWebAuthnCredentialRepository credentials,
    IWebAuthnCounterRepository counters)
{
    public async Task<Guid?> CompleteAsync(string? operationId,
        AuthenticatorAssertionRawResponse response, CancellationToken cancellationToken = default)
    {
        var options = store.Take(operationId);
        if (options is null || response?.RawId is not { Length: > 0 } ||
            response.Response?.UserHandle is not { Length: > 0 })
            return null;

        var credential = await credentials.GetByCredentialIdAsync(response.RawId, cancellationToken);
        if (credential is null || !response.Response.UserHandle.AsSpan().SequenceEqual(credential.UserId.ToByteArray()))
            return null;

        try
        {
            var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = options,
                StoredPublicKey = credential.PublicKeyCose,
                StoredSignatureCounter = credential.SignatureCounter,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(
                    args.CredentialId.AsSpan().SequenceEqual(credential.CredentialId) &&
                    args.UserHandle.AsSpan().SequenceEqual(credential.UserId.ToByteArray()))
            }, cancellationToken);

            if (result.SignCount <= credential.SignatureCounter &&
                (result.SignCount != 0 || credential.SignatureCounter != 0))
                return null;
            if (!await counters.TryUpdateCounterAsync(credential.Id, credential.SignatureCounter,
                    result.SignCount, cancellationToken))
                return null;
            return credential.UserId;
        }
        catch (Fido2VerificationException)
        {
            return null;
        }
    }
}
