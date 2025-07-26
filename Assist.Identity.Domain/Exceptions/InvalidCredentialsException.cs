namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Invalid Credentials Exception
/// Login sırasında geçersiz kimlik bilgileri girildiğinde fırlatılır
/// Security nedeniyle detaylı bilgi verilmez
/// </summary>
public class InvalidCredentialsException : DomainException
{
    /// <summary>
    /// InvalidCredentialsException default constructor
    /// </summary>
    public InvalidCredentialsException() 
        : base("The provided credentials are invalid.")
    {
    }

    /// <summary>
    /// InvalidCredentialsException constructor with custom message
    /// </summary>
    /// <param name="message">Custom error message</param>
    public InvalidCredentialsException(string message) : base(message)
    {
    }

    /// <summary>
    /// InvalidCredentialsException constructor with attempt info
    /// </summary>
    /// <param name="email">Attempted email</param>
    /// <param name="ipAddress">Attempt IP address</param>
    public InvalidCredentialsException(string email, string ipAddress) 
        : base("The provided credentials are invalid.")
    {
        Email = email;
        IpAddress = ipAddress;
        AttemptedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Denenen email adresi (security log için)
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Deneme yapılan IP adresi
    /// </summary>
    public string IpAddress { get; }

    /// <summary>
    /// Deneme zamanı
    /// </summary>
    public DateTime AttemptedAt { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "Authentication";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "INVALID_CREDENTIALS";
}