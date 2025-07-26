namespace Assist.Identity.Application.Abstractions;

using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// Authentication Service Interface
/// Authentication use case'lerini tanımlar
/// Login, register, token management operations
/// </summary>
public interface IAuthenticationService
{
    #region Authentication Operations

    /// <summary>
    /// User login
    /// Credentials verify edilir, token generate edilir
    /// </summary>
    /// <param name="request">Login credentials</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authentication response with token</returns>
    Task<ApiResponse<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// User registration
    /// Yeni user oluşturulur ve otomatik login yapılır
    /// </summary>
    /// <param name="request">Registration data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authentication response with token</returns>
    Task<ApiResponse<AuthResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token refresh
    /// Expired access token'ı yeni token ile değiştirir
    /// </summary>
    /// <param name="request">Refresh token data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>New authentication response</returns>
    Task<ApiResponse<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// User logout
    /// Refresh token'ları revoke edilir, session cleanup yapılır
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="refreshToken">Refresh token to revoke</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> LogoutAsync(Guid userId, string? refreshToken = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Logout from all devices
    /// User'ın tüm device'larından logout edilir
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> LogoutFromAllDevicesAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion

    #region Token Management

    /// <summary>
    /// Token validation
    /// Token'ın geçerli olup olmadığını kontrol eder
    /// </summary>
    /// <param name="token">Token to validate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Validation result</returns>
    Task<ApiResponse<bool>> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token revocation
    /// Specific token'ı geçersiz kılar
    /// </summary>
    /// <param name="token">Token to revoke</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> RevokeTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get current user from token
    /// Token'dan user bilgilerini extract eder
    /// </summary>
    /// <param name="token">JWT token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User information</returns>
    Task<ApiResponse<UserResponse>> GetCurrentUserAsync(string token, CancellationToken cancellationToken = default);

    #endregion

    #region Session Management

    /// <summary>
    /// User'ın aktif session'larını getirme
    /// Security panel için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Active sessions</returns>
    Task<ApiResponse<List<UserSession>>> GetActiveSessionsAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Specific session'ı terminate etme
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="sessionId">Session ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result</returns>
    Task<ApiResponse<bool>> TerminateSessionAsync(Guid userId, string sessionId, CancellationToken cancellationToken = default);

    #endregion
}