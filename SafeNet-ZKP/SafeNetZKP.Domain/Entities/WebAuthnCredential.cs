
namespace SafeNetZKP.Domain.Entities;

public sealed class WebAuthnCredential
{
    private byte[] _credentialId = [];
    private byte[] _publicKeyCose = [];

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public byte[] CredentialId =>
        (byte[])_credentialId.Clone();

    public byte[] PublicKeyCose =>
        (byte[])_publicKeyCose.Clone();

    public uint SignatureCounter { get; private set; }

    public DateTime CreatedAt { get; private set; }

    private WebAuthnCredential() { }

    public WebAuthnCredential(
        Guid userId,
        byte[] credentialId,
        byte[] publicKeyCose,
        uint signatureCounter)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException(
                "O usuário é obrigatório.",
                nameof(userId));

        if (credentialId is null || credentialId.Length == 0)
            throw new ArgumentException(
                "O identificador da credencial é obrigatório.",
                nameof(credentialId));

        if (publicKeyCose is null || publicKeyCose.Length == 0)
            throw new ArgumentException(
                "A chave pública é obrigatória.",
                nameof(publicKeyCose));

        Id = Guid.NewGuid();
        UserId = userId;

        _credentialId = (byte[])credentialId.Clone();
        _publicKeyCose = (byte[])publicKeyCose.Clone();

        SignatureCounter = signatureCounter;
        CreatedAt = DateTime.UtcNow;
    }
}
