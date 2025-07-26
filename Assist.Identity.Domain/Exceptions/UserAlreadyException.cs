namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// User Already Exists Exception
/// Aynı email ile user oluşturulmaya çalışıldığında fırlatılır
/// </summary>
public class UserAlreadyExistsException : DomainException
{
    /// <summary>
    /// UserAlreadyExistsException constructor
    /// </summary>
    /// <param name="email">Duplicate email</param>
    public UserAlreadyExistsException(string email) 
        : base($"A user with email '{email}' already exists.")
    {
        Email = email;
    }

    /// <summary>
    /// Duplicate email adresi
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "User";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "USER_ALREADY_EXISTS";
}