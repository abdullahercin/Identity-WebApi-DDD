namespace Assist.Identity.Domain.Common;

/// <summary>
/// Domain Event Interface
/// Domain içinde olan önemli olayları temsil eder
/// ERP integration, notifications, audit gibi cross-cutting concerns için kullanılır
/// </summary>
public interface IDomainEvent
{
    /// <summary>
    /// Event'in benzersiz tanımlayıcısı
    /// Duplicate processing'i engellemek için kullanılır
    /// </summary>
    Guid EventId { get; }

    /// <summary>
    /// Event'in oluşturulma zamanı
    /// Audit trail ve event ordering için kritik
    /// </summary>
    DateTime OccurredOn { get; }

    /// <summary>
    /// Event'in ait olduğu tenant
    /// Multi-tenant yapıda event'lerin de tenant'a ait olması gerekir
    /// </summary>
    Guid TenantId { get; }
}
