namespace Assist.Identity.Application.Abstractions;

using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// Role Service Interface
/// Role management use case'lerini tanımlar
/// RBAC (Role-Based Access Control) operations
/// </summary>
public interface IRoleService
{
    #region Role CRUD Operations

    /// <summary>
    /// Yeni role oluşturma
    /// Admin operations için
    /// </summary>
    /// <param name="request">Role creation data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Oluşturulan role bilgileri</returns>
    Task<ApiResponse<RoleResponse>> CreateRoleAsync(CreateRoleRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role ID'ye göre role getirme
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role bilgileri</returns>
    Task<ApiResponse<RoleResponse>> GetRoleByIdAsync(Guid roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role adına göre role getirme
    /// </summary>
    /// <param name="roleName">Role name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role bilgileri</returns>
    Task<ApiResponse<RoleResponse>> GetRoleByNameAsync(string roleName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role güncelleme
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="request">Update data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Güncellenmiş role bilgileri</returns>
    Task<ApiResponse<RoleResponse>> UpdateRoleAsync(Guid roleId, CreateRoleRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role silme
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> DeleteRoleAsync(Guid roleId, CancellationToken cancellationToken = default);

    #endregion

    #region Role Assignment Operations

    /// <summary>
    /// User'a role atama
    /// </summary>
    /// <param name="request">Role assignment data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> AssignRoleToUserAsync(AssignRoleRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'dan role kaldırma
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="roleName">Role name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> RemoveRoleFromUserAsync(Guid userId, string roleName, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın role'lerini getirme
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User'ın role'leri</returns>
    Task<ApiResponse<List<RoleResponse>>> GetUserRolesAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion

    #region Role Listing & Search

    /// <summary>
    /// Tüm aktif role'leri getirme
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role listesi</returns>
    Task<ApiResponse<List<RoleResponse>>> GetAllRolesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Sayfalanmış role listesi
    /// Admin panel için
    /// </summary>
    /// <param name="pageNumber">Page number</param>
    /// <param name="pageSize">Page size</param>
    /// <param name="searchTerm">Search term</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Sayfalanmış role listesi</returns>
    Task<PaginatedResponse<RoleResponse>> GetRolesAsync(int pageNumber = 1, int pageSize = 10, string? searchTerm = null, CancellationToken cancellationToken = default);

    #endregion

    #region Permission Management

    /// <summary>
    /// Role'e permission ekleme
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="permissionName">Permission name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> AddPermissionToRoleAsync(Guid roleId, string permissionName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Role'den permission kaldırma
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="permissionName">Permission name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> RemovePermissionFromRoleAsync(Guid roleId, string permissionName, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın permission'larını getirme
    /// Authorization için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User'ın permission'ları</returns>
    Task<ApiResponse<List<string>>> GetUserPermissionsAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın specific permission'a sahip olup olmadığını kontrol etme
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="permissionName">Permission name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Permission check result</returns>
    Task<ApiResponse<bool>> CheckUserPermissionAsync(Guid userId, string permissionName, CancellationToken cancellationToken = default);

    #endregion
}