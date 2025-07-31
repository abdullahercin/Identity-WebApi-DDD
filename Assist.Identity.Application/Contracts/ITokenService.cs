using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Token Service Contract
/// JWT token generation, validation ve management operations
/// </summary>
public interface ITokenService
{
    #region Token Generation

    /// <summary>
    /// Access token generate etme
    /// User login olduğunda çağrılır
    /// User entity'sinden tüm gerekli bilgiler extract edilir
    /// </summary>
    /// <param name="user">User entity - roles ve permissions buradan alınır</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>JWT access token</returns>
    Task<string> GenerateAccessTokenAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh token generate etme
    /// Long-term authentication için
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Refresh token string</returns>
    Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default);

    #endregion

    #region Token Validation

    /// <summary>
    /// Token validation
    /// Middleware tarafından kullanılır
    /// </summary>
    /// <param name="token">Validate edilecek token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token geçerliyse true</returns>
    Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token'dan user bilgilerini extract etme
    /// Authorization için kullanılır
    /// </summary>
    /// <param name="token">JWT token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token'dan çıkarılan user bilgileri</returns>
    Task<TokenUserInfo?> GetUserInfoFromTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token expiration kontrolü
    /// </summary>
    /// <param name="token">Kontrol edilecek token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token expire olduysa true</returns>
    Task<bool> IsTokenExpiredAsync(string token, CancellationToken cancellationToken = default);

    #endregion

    #region Token Management

    /// <summary>
    /// Token revocation
    /// Logout veya security breach durumunda
    /// </summary>
    /// <param name="token">Revoke edilecek token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın tüm token'larını revoke etme
    /// Password change, account deactivation gibi durumlarda
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion
}