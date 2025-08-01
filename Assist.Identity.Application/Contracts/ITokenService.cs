using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Token Service Contract
/// JWT token generation, validation ve management operations
/// 
/// Clean Architecture: Application Layer Contract
/// Infrastructure layer bu interface'i implement edecek (JwtTokenService)
/// Domain entities'leri kullanır ama infrastructure details'lere bağımlı değil
/// </summary>
public interface ITokenService
{
    #region Token Generation

    /// <summary>
    /// Access token generate etme
    /// User login olduğunda çağrılır
    /// 
    /// Clean Approach: Sadece User entity alır, tüm bilgileri User'dan extract eder
    /// User.GetRoleNames() ve User.GetPermissions() domain method'larını kullanır
    /// </summary>
    /// <param name="user">User entity - domain rich object</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>JWT access token string</returns>
    Task<string> GenerateAccessTokenAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh token generate etme
    /// Cryptographically secure random token
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Refresh token string</returns>
    Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default);

    #endregion

    #region Token Validation

    /// <summary>
    /// Token validation
    /// JWT middleware tarafından kullanılır
    /// Signature, expiration, issuer validation
    /// </summary>
    /// <param name="token">Validate edilecek JWT token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token valid ise true</returns>
    Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token'dan user bilgilerini extract etme
    /// JWT claims'lerden TokenUserInfo oluşturur
    /// Authorization pipeline'da kullanılır
    /// </summary>
    /// <param name="token">JWT access token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token'dan extract edilen user bilgileri</returns>
    Task<TokenUserInfo?> GetUserInfoFromTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token expiration kontrolü
    /// Token refresh gerekip gerekmediğini belirlemek için
    /// </summary>
    /// <param name="token">Kontrol edilecek token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token expire olduysa true</returns>
    Task<bool> IsTokenExpiredAsync(string token, CancellationToken cancellationToken = default);

    #endregion

    #region Token Management

    /// <summary>
    /// Token revocation
    /// Logout, security breach durumlarında
    /// 
    /// Note: JWT stateless nature nedeniyle revocation challenging
    /// Implementation blacklist veya short expiration kullanabilir
    /// </summary>
    /// <param name="token">Revoke edilecek token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın tüm token'larını revoke etme
    /// Security operation - user'ın tüm device'larından logout
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion

    #region Token Utilities

    /// <summary>
    /// Token'dan user ID extract etme
    /// Quick user identification için
    /// </summary>
    /// <param name="token">JWT token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User ID veya null</returns>
    Task<Guid?> GetUserIdFromTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token expiration time'ını getirme
    /// Client-side token management için
    /// </summary>
    /// <param name="token">JWT token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token expiration UTC time</returns>
    Task<DateTime?> GetTokenExpirationAsync(string token, CancellationToken cancellationToken = default);

    #endregion
}