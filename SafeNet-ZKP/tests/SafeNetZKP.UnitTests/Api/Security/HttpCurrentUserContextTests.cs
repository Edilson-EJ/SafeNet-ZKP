
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using SafeNetZKP.Api.Security;
using Xunit;

namespace SafeNetZKP.UnitTests.Api.Security;

public class HttpCurrentUserContextTests
{
    [Fact]
    public void UserId_WithoutHttpContext_ShouldReturnNull()
    {
        // Arrange
        var accessor = new HttpContextAccessor
        {
            HttpContext = null
        };

        var currentUser = new HttpCurrentUserContext(accessor);

        // Act
        var result = currentUser.UserId;

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void UserId_WhenNotAuthenticated_ShouldReturnNull()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var claims = new[]
        {
            new Claim(
                ClaimTypes.NameIdentifier,
                userId.ToString())
        };

        // Sem authenticationType: identidade não autenticada.
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        var currentUser = CreateCurrentUser(principal);

        // Act
        var result = currentUser.UserId;

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void UserId_WithInvalidGuid_ShouldReturnNull()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(
                ClaimTypes.NameIdentifier,
                "identificador-invalido")
        };

        var identity = new ClaimsIdentity(
            claims,
            authenticationType: "TestScheme");

        var principal = new ClaimsPrincipal(identity);
        var currentUser = CreateCurrentUser(principal);

        // Act
        var result = currentUser.UserId;

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void UserId_WithValidGuid_ShouldReturnUserId()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var claims = new[]
        {
            new Claim(
                ClaimTypes.NameIdentifier,
                userId.ToString())
        };

        var identity = new ClaimsIdentity(
            claims,
            authenticationType: "TestScheme");

        var principal = new ClaimsPrincipal(identity);
        var currentUser = CreateCurrentUser(principal);

        // Act
        var result = currentUser.UserId;

        // Assert
        Assert.Equal(userId, result);
    }

    [Fact]
    public void UserId_WithSubClaim_ShouldReturnUserId()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var claims = new[]
        {
            new Claim("sub", userId.ToString())
        };

        var identity = new ClaimsIdentity(
            claims,
            authenticationType: "TestScheme");

        var principal = new ClaimsPrincipal(identity);
        var currentUser = CreateCurrentUser(principal);

        // Act
        var result = currentUser.UserId;

        // Assert
        Assert.Equal(userId, result);
    }

    private static HttpCurrentUserContext CreateCurrentUser(
        ClaimsPrincipal principal)
    {
        var httpContext = new DefaultHttpContext
        {
            User = principal
        };

        var accessor = new HttpContextAccessor
        {
            HttpContext = httpContext
        };

        return new HttpCurrentUserContext(accessor);
    }
}
