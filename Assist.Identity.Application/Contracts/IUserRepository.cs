using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// User Repository Contract
/// User entity için data access operations
/// Infrastructure layer bu interface'i implement edecek
/// </summary>
public interface IUserRepository
{
    #region Basic CRUD Operations

    /// <summary>
    /// User ID'ye göre user getirme
    /// Eager loading ile ilişkili veriler de gelir (roles, refresh tokens)
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User entity veya null</returns>
    Task<User?> GetByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email adresine göre user getirme
    /// Login işlemi için kullanılır
    /// </summary>
    /// <param name="email">Email value object</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User entity veya null</returns>
    Task<User?> GetByEmailAsync(Email email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Yeni user ekleme
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Eklenen user entity</returns>
    Task<User> AddAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>
    /// User güncelleme
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task UpdateAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>
    /// User silme (soft delete)
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task DeleteAsync(User user, CancellationToken cancellationToken = default);

    #endregion

    #region Existence Checks

    /// <summary>
    /// User existence kontrolü
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User varsa true</returns>
    Task<bool> ExistsAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email existence kontrolü
    /// User registration sırasında duplicate check için kullanılır
    /// </summary>
    /// <param name="email">Email value object</param>
    /// <param name="excludeUserId">Hariç tutulacak user ID (update scenario için)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Email varsa true</returns>
    Task<bool> EmailExistsAsync(Email email, Guid? excludeUserId = null, CancellationToken cancellationToken = default);

    #endregion

    #region Business Queries

    /// <summary>
    /// Aktif user'ları getirme
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Aktif user'lar</returns>
    Task<IEnumerable<User>> GetActiveUsersAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Role'e sahip user'ları getirme
    /// </summary>
    /// <param name="roleName">Role adı</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Belirtilen role'e sahip user'lar</returns>
    Task<IEnumerable<User>> GetUsersByRoleAsync(string roleName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Permission'a sahip user'ları getirme
    /// Authorization queries için kullanılır
    /// </summary>
    /// <param name="permissionName">Permission adı</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Belirtilen permission'a sahip user'lar</returns>
    Task<IEnumerable<User>> GetUsersByPermissionAsync(string permissionName, CancellationToken cancellationToken = default);

    #endregion

    #region Pagination & Search

    /// <summary>
    /// Sayfalanmış user listesi
    /// Admin paneli için kullanılır
    /// </summary>
    /// <param name="pageNumber">Sayfa numarası (1-based)</param>
    /// <param name="pageSize">Sayfa boyutu</param>
    /// <param name="searchTerm">Arama terimi (email, ad, soyad)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Sayfalanmış user listesi</returns>
    Task<PagedResult<User>> GetPagedAsync(int pageNumber, int pageSize, string? searchTerm = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Toplam user sayısı
    /// Dashboard statistics için
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Toplam aktif user sayısı</returns>
    Task<int> GetTotalUserCountAsync(CancellationToken cancellationToken = default);

    #endregion

    #region Multi-Tenant Operations

    /// <summary>
    /// Tenant'a ait user'ları getirme
    /// Multi-tenant operations için
    /// </summary>
    /// <param name="tenantId">Tenant ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Tenant'a ait user'lar</returns>
    Task<IEnumerable<User>> GetUsersByTenantAsync(Guid tenantId, CancellationToken cancellationToken = default);

    #endregion
}