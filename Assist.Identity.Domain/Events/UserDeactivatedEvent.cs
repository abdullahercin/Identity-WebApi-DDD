namespace Assist.Identity.Domain.Events;

/// <summary>
/// User Deactivated Domain Event
/// User deaktive edildiğinde fırlatılır
/// Session cleanup, notification, audit, ERP synchronization için kullanılır
/// </summary>
public sealed class UserDeactivatedEvent : BaseDomainEvent
{
    /// <summary>
    /// UserDeactivatedEvent constructor
    /// </summary>
    /// <param name="userId">Deaktive edilen user'ın ID'si</param>
    /// <param name="email">User'ın email adresi</param>
    /// <param name="tenantId">Tenant ID'si</param>
    /// <param name="deactivatedBy">Deaktive işlemini yapan user'ın ID'si</param>
    /// <param name="reason">Deaktive etme nedeni</param>
    /// <param name="isTemporary">Geçici deaktive mi (örn: account lock)</param>
    /// <param name="reactivationDate">Yeniden aktive olacağı tarih (geçici ise)</param>
    public UserDeactivatedEvent(
        Guid userId,
        string? email,
        Guid tenantId,
        string? deactivatedBy = null,
        string? reason = null,
        bool isTemporary = false,
        DateTime? reactivationDate = null) : base(tenantId)
    {
        UserId = userId;
        Email = email ?? throw new ArgumentNullException(nameof(email));
        DeactivatedBy = deactivatedBy;
        DeactivatedAt = DateTime.UtcNow;
        Reason = reason;
        IsTemporary = isTemporary;
        ReactivationDate = reactivationDate;
    }

    /// <summary>
    /// Deaktive edilen user'ın ID'si
    /// </summary>
    public Guid UserId { get; }

    /// <summary>
    /// User'ın email adresi
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Deaktive edilme zamanı
    /// </summary>
    public DateTime DeactivatedAt { get; }

    /// <summary>
    /// Deaktive işlemini yapan user'ın ID'si
    /// System tarafından yapıldıysa null olabilir
    /// </summary>
    public string? DeactivatedBy { get; }

    /// <summary>
    /// Deaktive etme nedeni
    /// "Account violation", "Employee termination", "Suspicious activity" gibi
    /// </summary>
    public string? Reason { get; }

    /// <summary>
    /// Geçici deaktive mi
    /// True ise account lock, false ise permanent deactivation
    /// </summary>
    public bool IsTemporary { get; }

    /// <summary>
    /// Yeniden aktive olacağı tarih
    /// IsTemporary=true ise dolu olmalı
    /// </summary>
    public DateTime? ReactivationDate { get; }

    /// <summary>
    /// System tarafından mı deaktive edildi kontrolü
    /// </summary>
    public bool IsSystemDeactivated => string.IsNullOrWhiteSpace(DeactivatedBy);

    /// <summary>
    /// Has reason check
    /// </summary>
    public bool HasReason => !string.IsNullOrWhiteSpace(Reason);

    /// <summary>
    /// Has reactivation date check
    /// </summary>
    public bool HasReactivationDate => ReactivationDate.HasValue;
}