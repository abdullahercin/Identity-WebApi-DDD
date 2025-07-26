using Assist.Identity.Application.Models;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Current Tenant Service Contract
/// Multi-tenant operations için current tenant bilgisi sağlar
/// 
/// Bu service şu kaynaklardan tenant bilgisi alabilir:
/// - HTTP header'dan (X-Tenant-Id)
/// - Subdomain'den (tenant1.yourapp.com)
/// - JWT token'dan
/// - Database lookup'tan
/// </summary>
public interface ICurrentTenantService
{
    /// <summary>
    /// Current tenant ID
    /// Bu property request scope'unda set edilir ve
    /// tüm database operations'lar bu tenant'a scope'lanır
    /// </summary>
    Guid TenantId { get; }

    /// <summary>
    /// Current tenant bilgilerini getir
    /// Caching ile optimize edilebilir
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Tenant bilgileri</returns>
    Task<TenantInfo?> GetCurrentTenantAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Tenant existence kontrolü
    /// Security validation için
    /// </summary>
    /// <param name="tenantId">Kontrol edilecek tenant ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Tenant varsa true</returns>
    Task<bool> TenantExistsAsync(Guid tenantId, CancellationToken cancellationToken = default);
}