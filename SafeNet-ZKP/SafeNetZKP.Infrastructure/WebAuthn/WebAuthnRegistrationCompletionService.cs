using Fido2NetLib;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed class WebAuthnRegistrationCompletionService(
    IFido2 fido2,
    WebAuthnRegistrationStore registrations,
    IWebAuthnCredentialRepository credentials)
{
    public async Task<bool> CompleteAsync(
        Guid operationId, string? token, AuthenticatorAttestationRawResponse response,
        CancellationToken cancellationToken = default)
    {
        var pending = registrations.TakeAuthorized(operationId, token);
        if (pending is null)
            return false;

        try
        {
            var verified = await fido2.MakeNewCredentialAsync(
                new MakeNewCredentialParams
                {
                    AttestationResponse = response,
                    OriginalOptions = pending.Value.Options,
                    IsCredentialIdUniqueToUserCallback = async (args, ct) =>
                        await credentials.GetByCredentialIdAsync(args.CredentialId, ct) is null
                }, cancellationToken);

            var credential = new WebAuthnCredential(
                pending.Value.UserId, verified.Id, verified.PublicKey, verified.SignCount);
            await credentials.AddAsync(credential, cancellationToken);
            return true;
        }
        catch (Fido2VerificationException)
        {
            return false;
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException
        {
            SqlState: PostgresErrorCodes.UniqueViolation,
            ConstraintName: "IX_WebAuthnCredentials_CredentialId"
        })
        {
            // A constraint também protege duas operações distintas concorrentes.
            return false;
        }
    }
}
