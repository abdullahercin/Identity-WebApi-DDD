using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Refresh Token Repository Contract
/// JWT refresh token management için data access operations
/// 
/// Refresh token lifecycle:
/// 1. Generate (login sırasında)
/// 2. Validate (token refresh sırasında)
/// 3. Revoke (logout veya security breach)
/// 4. Cleanup (expired token'ları temizle)
/// </summary>
public interface IRefreshTokenRepository
{
    #region Basic CRUD Operations

    /// <summary>
    /// Refresh token ID ile getir
    /// </summary>
    /// <param name="tokenId">Token ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>RefreshToken entity veya null</returns>
    Task<RefreshToken?> GetByIdAsync(Guid tokenId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token string ile getir
    /// Token refresh sırasında kullanılır
    /// </summary>
    /// <param name="token">Token string</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>RefreshToken entity veya null</returns>
    Task<RefreshToken?> GetByTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh token ekleme
    /// Login sırasında yeni token oluşturulduğunda
    /// </summary>
    /// <param name="refreshToken">Eklenecek refresh token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Eklenen refresh token</returns>
    Task<RefreshToken> AddAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh token güncelleme
    /// Token usage tracking için
    /// </summary>
    /// <param name="refreshToken">Güncellenecek refresh token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Güncellenen refresh token</returns>
    Task<RefreshToken> UpdateAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh token silme
    /// Token revocation için
    /// </summary>
    /// <param name="refreshToken">Silinecek refresh token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task DeleteAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default);

    #endregion

    #region User-specific Operations

    /// <summary>
    /// User'ın tüm aktif refresh token'larını getir
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User'ın aktif refresh token'ları</returns>
    Task<IEnumerable<RefreshToken>> GetActiveTokensByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın tüm refresh token'larını revoke et
    /// Security operation - user'ın tüm device'larından logout
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Specific token'ı revoke et
    /// Logout işlemi için
    /// </summary>
    /// <param name="token">Revoke edilecek token string</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default);

    #endregion

    #region Maintenance Operations

    /// <summary>
    /// Expired refresh token'ları temizle
    /// Background job olarak çalıştırılmalı
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Temizlenen token sayısı</returns>
    Task<int> CleanupExpiredTokensAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// User'ın eski token'larını temizle
    /// Token limit'i aşılırsa eski token'lar silinir
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="keepCount">Tutulacak token sayısı</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Temizlenen token sayısı</returns>
    Task<int> CleanupOldUserTokensAsync(Guid userId, int keepCount = 5, CancellationToken cancellationToken = default);

    #endregion

    #region Validation & Security

    /// <summary>
    /// Token'ın aktif ve geçerli olduğunu kontrol et
    /// </summary>
    /// <param name="token">Kontrol edilecek token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token geçerliyse true</returns>
    Task<bool> IsTokenValidAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Token kullanım sayısını artır
    /// Suspicious activity detection için
    /// </summary>
    /// <param name="token">Kullanılan token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task IncrementUsageCountAsync(string token, CancellationToken cancellationToken = default);

    #endregion
}