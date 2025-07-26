namespace Assist.Identity.Domain.Events;

/// <summary>
/// Password Changed Domain Event
/// User'ın password'ü değiştirildiğinde fırlatılır
/// Security notification, audit log, session invalidation için kullanılır
/// </summary>
public sealed class PasswordChangedEvent : BaseDomainEvent
{
    /// <summary>
    /// PasswordChangedEvent constructor
    /// </summary>
    /// <param name="userId">Password'ü değiştirilen user'ın ID'si</param>
    /// <param name="email">User'ın email adresi</param>
    /// <param name="tenantId">Tenant ID'si</param>
    /// <param name="changedBy">Değişikliği yapan user'ın ID'si (self-service ise aynı olabilir)</param>
    /// <param name="ipAddress">Değişiklik yapılan IP adresi</param>
    /// <param name="userAgent">Browser/client bilgisi</param>
    /// <param name="reason">Password değişiklik nedeni (opsiyonel)</param>
    public PasswordChangedEvent(
        Guid userId,
        string? email,
        Guid tenantId,
        string? changedBy = null,
        string? ipAddress = null,
        string? userAgent = null,
        string? reason = null) : base(tenantId)
    {
        UserId = userId;
        Email = email ?? throw new ArgumentNullException(nameof(email));
        ChangedBy = changedBy;
        ChangedAt = DateTime.UtcNow;
        IpAddress = ipAddress;
        UserAgent = userAgent;
        Reason = reason;
    }

    /// <summary>
    /// Password'ü değiştirilen user'ın ID'si
    /// </summary>
    public Guid UserId { get; }

    /// <summary>
    /// User'ın email adresi
    /// Security notification gönderimi için
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Password değişiklik zamanı
    /// </summary>
    public DateTime ChangedAt { get; }

    /// <summary>
    /// Değişikliği yapan user'ın ID'si
    /// Self-service ise UserId ile aynı, admin tarafından yapıldıysa farklı
    /// </summary>
    public string? ChangedBy { get; }

    /// <summary>
    /// Değişiklik yapılan IP adresi
    /// Security monitoring için
    /// </summary>
    public string? IpAddress { get; }

    /// <summary>
    /// Browser/client bilgisi
    /// </summary>
    public string? UserAgent { get; }

    /// <summary>
    /// Password değişiklik nedeni
    /// "Forgot password", "Admin reset", "Policy compliance" gibi
    /// </summary>
    public string? Reason { get; }

    /// <summary>
    /// Self-service password change mi kontrolü
    /// </summary>
    public bool IsSelfServiceChange => ChangedBy == UserId.ToString();

    /// <summary>
    /// Has reason check
    /// </summary>
    public bool HasReason => !string.IsNullOrWhiteSpace(Reason);
}