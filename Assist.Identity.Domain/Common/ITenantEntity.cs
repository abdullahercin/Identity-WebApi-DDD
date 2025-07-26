namespace Assist.Identity.Domain.Common;

/// <summary>
/// Tenant Entity Marker Interface
/// Multi-tenant yapıda tüm entities'lerin implement etmesi gereken contract
/// Bu interface sayesinde tenant filtering'i otomatik olarak yapılabilir
/// </summary>
public interface ITenantEntity
{
    /// <summary>
    /// Tenant identifier - Her entity bir tenant'a ait olmalı
    /// Guid.Empty olmamalı, mutlaka valid bir tenant ID olmalı
    /// </summary>
    Guid TenantId { get; }
}
