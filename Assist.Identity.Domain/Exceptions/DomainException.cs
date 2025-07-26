namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Base Domain Exception
/// Tüm domain-specific exception'ların base class'ı
/// Business rule violation'larını represent eder
/// </summary>
public abstract class DomainException : Exception
{
    /// <summary>
    /// DomainException constructor
    /// </summary>
    /// <param name="message">Exception mesajı</param>
    protected DomainException(string message) : base(message)
    {
        Timestamp = DateTime.UtcNow;
    }

    /// <summary>
    /// DomainException constructor with inner exception
    /// </summary>
    /// <param name="message">Exception mesajı</param>
    /// <param name="innerException">Inner exception</param>
    protected DomainException(string message, Exception innerException) : base(message, innerException)
    {
        Timestamp = DateTime.UtcNow;
    }

    /// <summary>
    /// Exception'ın oluşturulma zamanı
    /// Audit ve debugging için kullanılır
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Exception kategorisi - Subclass'lar override edebilir
    /// </summary>
    public virtual string Category => "Domain";

    /// <summary>
    /// Error code - API response'larda kullanılabilir
    /// </summary>
    public virtual string ErrorCode => GetType().Name.Replace("Exception", "");
}