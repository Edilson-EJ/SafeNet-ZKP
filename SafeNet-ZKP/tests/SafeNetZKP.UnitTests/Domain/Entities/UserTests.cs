using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.UnitTests.Domain.Entities;

public class UserTests
{
    [Fact]
    public void ChangeName_ShouldUpdateName_WhenNameIsValid()
    {
        // Arrange
        var user = new User("Edilson");

        // Act
        user.ChangeName("Maria");

        // Assert
        Assert.Equal("Maria", user.Name);
    }

    [Fact]
    public void ChangeName_ShouldThrowException_WhenNameIsEmpty()
    {
        // Arrange
        var user = new User("Edilson");

        // Act
        var exception = Assert.Throws<ArgumentException>(
            () => user.ChangeName(""));

        // Assert
        Assert.Equal("newName", exception.ParamName);
        Assert.Equal("Edilson", user.Name);
    }
}