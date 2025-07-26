using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Role Repository Contract
/// Role entity için data access operations
/// </summary>
public interface IRoleRepository
{
    #region Basic CRUD Operations

    /// <summary>
    /// Role ID'ye göre role getirme
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role entity veya null</returns>
    Task<Role?> GetByIdAsync(Guid roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role adına göre role getirme
    /// </summary>
    /// <param name="roleName">Role adı</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role entity veya null</returns>
    Task<Role?> GetByNameAsync(string roleName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Yeni role ekleme
    /// </summary>
    /// <param name="role">Role entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Eklenen role entity</returns>
    Task<Role> AddAsync(Role role, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role güncelleme
    /// </summary>
    /// <param name="role">Role entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task UpdateAsync(Role role, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role silme
    /// </summary>
    /// <param name="role">Role entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task DeleteAsync(Role role, CancellationToken cancellationToken = default);

    #endregion

    #region Business Queries

    /// <summary>
    /// Tüm aktif role'leri getirme
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Aktif role'ler</returns>
    Task<IEnumerable<Role>> GetActiveRolesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın sahip olduğu role'leri getirme
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User'ın role'leri</returns>
    Task<IEnumerable<Role>> GetRolesByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role existence kontrolü
    /// </summary>
    /// <param name="roleName">Role adı</param>
    /// <param name="excludeRoleId">Hariç tutulacak role ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role varsa true</returns>
    Task<bool> RoleExistsAsync(string roleName, Guid? excludeRoleId = null, CancellationToken cancellationToken = default);

    #endregion
}