namespace Assist.Identity.Application.Abstractions;

using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// User Service Interface
/// User management use case'lerini tanımlar
/// WebAPI layer bu interface'i kullanacak
/// </summary>
public interface IUserService
{
    #region User CRUD Operations

    /// <summary>
    /// Yeni user oluşturma
    /// Registration flow'u için kullanılır
    /// </summary>
    /// <param name="request">User creation data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Oluşturulan user bilgileri</returns>
    Task<ApiResponse<UserResponse>> CreateUserAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// User ID'ye göre user getirme
    /// Profile view, admin panels için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User bilgileri</returns>
    Task<ApiResponse<UserResponse>> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email'e göre user getirme
    /// Admin search, lookup operations için
    /// </summary>
    /// <param name="email">Email address</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User bilgileri</returns>
    Task<ApiResponse<UserResponse>> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// User bilgilerini güncelleme
    /// Profile update için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="request">Update data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Güncellenmiş user bilgileri</returns>
    Task<ApiResponse<UserResponse>> UpdateUserAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ı deaktive etme
    /// Admin operations için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="reason">Deactivation reason</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> DeactivateUserAsync(Guid userId, string? reason = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ı yeniden aktive etme
    /// Admin operations için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> ReactivateUserAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion

    #region Password Management

    /// <summary>
    /// Password değiştirme
    /// User'ın kendi password'ünü değiştirmesi için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="request">Password change data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Password reset request
    /// Forgot password flow'u için
    /// </summary>
    /// <param name="request">Reset request data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> RequestPasswordResetAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Password reset confirmation
    /// Reset token ile yeni password set etme
    /// </summary>
    /// <param name="request">Reset confirmation data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default);

    #endregion

    #region Email Management

    /// <summary>
    /// Email confirmation
    /// Email verification flow için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="token">Confirmation token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> ConfirmEmailAsync(Guid userId, string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email confirmation yeniden gönderme
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> ResendEmailConfirmationAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion

    #region User Search & Listing

    /// <summary>
    /// Sayfalanmış user listesi
    /// Admin panel, user management için
    /// </summary>
    /// <param name="pageNumber">Page number</param>
    /// <param name="pageSize">Page size</param>
    /// <param name="searchTerm">Search term</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Sayfalanmış user listesi</returns>
    Task<PaginatedResponse<UserResponse>> GetUsersAsync(int pageNumber = 1, int pageSize = 10, string? searchTerm = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Aktif user'ları getirme
    /// Dashboard, statistics için
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Aktif user listesi</returns>
    Task<ApiResponse<List<UserResponse>>> GetActiveUsersAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Role'e sahip user'ları getirme
    /// Role management operations için
    /// </summary>
    /// <param name="roleName">Role name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User listesi</returns>
    Task<ApiResponse<List<UserResponse>>> GetUsersByRoleAsync(string roleName, CancellationToken cancellationToken = default);

    #endregion

    #region User Statistics

    /// <summary>
    /// Toplam user sayısı
    /// Dashboard statistics için
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User count</returns>
    Task<ApiResponse<int>> GetTotalUserCountAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// User statistics
    /// Admin dashboard için detaylı istatistikler
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User statistics</returns>
    Task<ApiResponse<UserStatistics>> GetUserStatisticsAsync(CancellationToken cancellationToken = default);

    #endregion
}