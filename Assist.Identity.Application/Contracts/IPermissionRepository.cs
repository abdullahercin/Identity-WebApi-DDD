using Assist.Identity.Domain.Entities;
using Assist.Identity.Application.Models;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Permission Repository Contract
/// Permission entity için data access operations
/// 
/// Fine-grained authorization için permission management
/// Role'ler permission'larla ilişkilendirilir
/// </summary>
public interface IPermissionRepository
{
    #region Basic CRUD Operations

    /// <summary>
    /// Permission ID ile getir
    /// </summary>
    /// <param name="permissionId">Permission ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Permission entity veya null</returns>
    Task<Permission?> GetByIdAsync(Guid permissionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Permission name ile getir
    /// </summary>
    /// <param name="name">Permission adı</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Permission entity veya null</returns>
    Task<Permission?> GetByNameAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tüm permission'ları getir
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Permission listesi</returns>
    Task<IEnumerable<Permission>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Permission ekleme
    /// </summary>
    /// <param name="permission">Eklenecek permission</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Eklenen permission</returns>
    Task<Permission> AddAsync(Permission permission, CancellationToken cancellationToken = default);

    /// <summary>
    /// Permission güncelleme
    /// </summary>
    /// <param name="permission">Güncellenecek permission</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Güncellenen permission</returns>
    Task<Permission> UpdateAsync(Permission permission, CancellationToken cancellationToken = default);

    /// <summary>
    /// Permission silme
    /// </summary>
    /// <param name="permission">Silinecek permission</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task DeleteAsync(Permission permission, CancellationToken cancellationToken = default);

    #endregion

    #region Business Queries

    /// <summary>
    /// Kategori bazında permission'ları getir
    /// Admin interface'te grouping için kullanılır
    /// </summary>
    /// <param name="category">Permission kategorisi</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Kategorideki permission'lar</returns>
    Task<IEnumerable<Permission>> GetByCategoryAsync(string category, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role'e ait permission'ları getir
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role'ün permission'ları</returns>
    Task<IEnumerable<Permission>> GetByRoleIdAsync(Guid roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Permission adı varlığını kontrol et
    /// Duplicate önlemek için
    /// </summary>
    /// <param name="name">Kontrol edilecek permission adı</param>
    /// <param name="excludeId">Hariç tutulacak permission ID (update için)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Permission varsa true</returns>
    Task<bool> ExistsAsync(string name, Guid? excludeId = null, CancellationToken cancellationToken = default);

    #endregion

    #region Pagination & Search

    /// <summary>
    /// Sayfalanmış permission listesi
    /// Admin interface için
    /// </summary>
    /// <param name="pageNumber">Sayfa numarası</param>
    /// <param name="pageSize">Sayfa boyutu</param>
    /// <param name="searchTerm">Arama terimi (opsiyonel)</param>
    /// <param name="category">Kategori filtresi (opsiyonel)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Sayfalanmış permission sonucu</returns>
    Task<PagedResult<Permission>> GetPagedAsync(
        int pageNumber,
        int pageSize,
        string? searchTerm = null,
        string? category = null,
        CancellationToken cancellationToken = default);

    #endregion
}