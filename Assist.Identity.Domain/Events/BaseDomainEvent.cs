using Assist.Identity.Domain.Common;

namespace Assist.Identity.Domain.Events;

/// <summary>
/// Base Domain Event Class
/// Tüm domain events'lerin inherit edeceği base class
/// Event'lerin ortak davranışlarını ve özelliklerini sağlar
/// </summary>
public abstract class BaseDomainEvent : IDomainEvent
{
    /// <summary>
    /// Protected constructor - Sadece derived classes tarafından çağrılabilir
    /// Event oluşturulurken temel alanları initialize eder
    /// </summary>
    protected BaseDomainEvent(Guid tenantId)
    {
        EventId = Guid.NewGuid();
        OccurredOn = DateTime.UtcNow;
        TenantId = tenantId;
    }

    /// <summary>
    /// Event'in benzersiz tanımlayıcısı
    /// Duplicate processing'i engellemek için kullanılır
    /// </summary>
    public Guid EventId { get; }

    /// <summary>
    /// Event'in oluşturulma zamanı
    /// Audit trail ve event ordering için kritik
    /// </summary>
    public DateTime OccurredOn { get; }

    /// <summary>
    /// Event'in ait olduğu tenant
    /// Multi-tenant yapıda event'lerin de tenant'a ait olması gerekir
    /// </summary>
    public Guid TenantId { get; }

    /// <summary>
    /// String representation for logging
    /// </summary>
    public override string ToString()
    {
        return $"{GetType().Name} [EventId: {EventId}, TenantId: {TenantId}, OccurredOn: {OccurredOn:O}]";
    }
}
