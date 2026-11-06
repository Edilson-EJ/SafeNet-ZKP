
using SafeNetZKP.Domain.Entities;
using Xunit;

namespace SafeNetZKP.UnitTests.Domain.Entities;

public class WebAuthnCredentialTests
{
    [Fact]
    public void Constructor_WithValidData_ShouldCreateCredential()
    {
        // Arrange
        var userId = Guid.NewGuid();
        byte[] credentialId = [1, 2, 3];
        byte[] publicKey = [4, 5, 6];

        // Act
        var credential = new WebAuthnCredential(
            userId,
            credentialId,
            publicKey,
            0);

        // Assert
        Assert.NotEqual(Guid.Empty, credential.Id);
        Assert.Equal(userId, credential.UserId);
        Assert.Equal(credentialId, credential.CredentialId);
        Assert.Equal(publicKey, credential.PublicKeyCose);
        Assert.Equal(0u, credential.SignatureCounter);
        Assert.Equal(DateTimeKind.Utc, credential.CreatedAt.Kind);
    }

    [Fact]
    public void Constructor_WithEmptyUserId_ShouldThrowException()
    {
        // Act
        var action = () => new WebAuthnCredential(
            Guid.Empty,
            [1, 2, 3],
            [4, 5, 6],
            0);

        // Assert
        Assert.Throws<ArgumentException>(action);
    }

    [Fact]
    public void Constructor_WithEmptyCredentialId_ShouldThrowException()
    {
        // Act
        var action = () => new WebAuthnCredential(
            Guid.NewGuid(),
            [],
            [4, 5, 6],
            0);

        // Assert
        Assert.Throws<ArgumentException>(action);
    }

    [Fact]
    public void Constructor_WithEmptyPublicKey_ShouldThrowException()
    {
        // Act
        var action = () => new WebAuthnCredential(
            Guid.NewGuid(),
            [1, 2, 3],
            [],
            0);

        // Assert
        Assert.Throws<ArgumentException>(action);
    }

    [Fact]
    public void Constructor_ShouldCopyInputArrays()
    {
        // Arrange
        byte[] credentialId = [1, 2, 3];
        byte[] publicKey = [4, 5, 6];

        var credential = new WebAuthnCredential(
            Guid.NewGuid(),
            credentialId,
            publicKey,
            0);

        // Act
        credentialId[0] = 99;
        publicKey[0] = 99;

        // Assert
        Assert.Equal((byte)1, credential.CredentialId[0]);
        Assert.Equal((byte)4, credential.PublicKeyCose[0]);
    }

    
    [Fact]
    public void Properties_ShouldNotExposeInternalArrays()
    {
        // Arrange
        var credential = new WebAuthnCredential(
            Guid.NewGuid(),
            [1, 2, 3],
            [4, 5, 6],
            0);

        // Act
        var credentialId = credential.CredentialId;
        var publicKey = credential.PublicKeyCose;

        credentialId[0] = 99;
        publicKey[0] = 99;

        // Assert
        Assert.Equal((byte)1, credential.CredentialId[0]);
        Assert.Equal((byte)4, credential.PublicKeyCose[0]);
    }

}
