namespace Assist.Identity.Domain.Events;

/// <summary>
/// User Logged In Domain Event
/// User başarılı login olduğunda fırlatılır
/// Login statistics, security monitoring, session tracking için kullanılır
/// </summary>
public sealed class UserLoggedInEvent : BaseDomainEvent
{
    /// <summary>
    /// UserLoggedInEvent constructor
    /// </summary>
    /// <param name="userId">Login olan user'ın ID'si</param>
    /// <param name="email">User'ın email adresi</param>
    /// <param name="tenantId">Tenant ID'si</param>
    /// <param name="ipAddress">Login IP adresi</param>
    /// <param name="userAgent">Browser/client bilgisi</param>
    /// <param name="loginTime">Login zamanı (opsiyonel, default şimdi)</param>
    public UserLoggedInEvent(
        Guid userId,
        string? email,
        Guid tenantId,
        string? ipAddress = null,
        string? userAgent = null,
        DateTime? loginTime = null) : base(tenantId)
    {
        UserId = userId;
        Email = email ?? throw new ArgumentNullException(nameof(email));
        IpAddress = ipAddress;
        UserAgent = userAgent;
        LoginTime = loginTime ?? DateTime.UtcNow;
    }

    /// <summary>
    /// Login olan user'ın ID'si
    /// </summary>
    public Guid UserId { get; }

    /// <summary>
    /// User'ın email adresi
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Login IP adresi
    /// Security monitoring için kritik
    /// </summary>
    public string? IpAddress { get; }

    /// <summary>
    /// Browser/client bilgisi
    /// User experience analytics için kullanılır
    /// </summary>
    public string? UserAgent { get; }

    /// <summary>
    /// Login zamanı
    /// User'ın son login zamanını track etmek için
    /// </summary>
    public DateTime LoginTime { get; }

    /// <summary>
    /// Has IP address check
    /// </summary>
    public bool HasIpAddress => !string.IsNullOrWhiteSpace(IpAddress);

    /// <summary>
    /// Has user agent check
    /// </summary>
    public bool HasUserAgent => !string.IsNullOrWhiteSpace(UserAgent);
}