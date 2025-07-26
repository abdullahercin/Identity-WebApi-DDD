namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// User Not Found Exception
/// Aranılan user bulunamadığında fırlatılır
/// </summary>
public class UserNotFoundException : DomainException
{
    /// <summary>
    /// UserNotFoundException constructor with identifier
    /// </summary>
    /// <param name="identifier">User identifier (email, ID vs.)</param>
    public UserNotFoundException(string identifier) 
        : base($"User with identifier '{identifier}' was not found.")
    {
        Identifier = identifier;
    }

    /// <summary>
    /// UserNotFoundException constructor with user ID
    /// </summary>
    /// <param name="userId">User ID</param>
    public UserNotFoundException(Guid userId) 
        : base($"User with ID '{userId}' was not found.")
    {
        Identifier = userId.ToString();
    }

    /// <summary>
    /// Aranılan user'ın identifier'ı
    /// </summary>
    public string Identifier { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "User";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "USER_NOT_FOUND";
}