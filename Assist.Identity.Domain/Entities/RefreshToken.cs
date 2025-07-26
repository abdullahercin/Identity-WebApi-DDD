using Assist.Identity.Domain.Common;

namespace Assist.Identity.Domain.Entities;

/// <summary>
/// Refresh Token Entity
/// JWT token yenileme için kullanılan token bilgisi
/// </summary>
public class RefreshToken : BaseEntity
{
    // Private constructor - EF için
    private RefreshToken() { }

    /// <summary>
    /// RefreshToken oluşturma constructor
    /// </summary>
    private RefreshToken(Guid userId, string token, DateTime expiresAt)
    {
        UserId = userId;
        Token = token ?? throw new ArgumentNullException(nameof(token));
        ExpiresAt = expiresAt;
        IsActive = true;
        RevokedAt = null;
    }

    #region Properties

    /// <summary>
    /// Token'ın ait olduğu user'ın ID'si
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// Refresh token string'i
    /// </summary>
    public string Token { get; private set; }

    /// <summary>
    /// Token'ın expiration zamanı
    /// </summary>
    public DateTime ExpiresAt { get; private set; }

    /// <summary>
    /// Token aktif mi
    /// </summary>
    public bool IsActive { get; private set; }

    /// <summary>
    /// Token'ın revoke edildiği zaman
    /// </summary>
    public DateTime? RevokedAt { get; private set; }

    #endregion

    #region Navigation Properties

    /// <summary>
    /// Token'ın ait olduğu user
    /// </summary>
    public virtual User? User { get; private set; }

    #endregion

    #region Factory Methods

    /// <summary>
    /// RefreshToken oluşturma factory method
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="token">Token string</param>
    /// <param name="expiresAt">Expiration time</param>
    /// <returns>Yeni RefreshToken entity</returns>
    public static RefreshToken Create(Guid userId, string token, DateTime expiresAt)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        if (expiresAt <= DateTime.UtcNow)
            throw new ArgumentException("Expiration time must be in the future.", nameof(expiresAt));

        return new RefreshToken(userId, token, expiresAt);
    }

    #endregion

    #region Business Methods

    /// <summary>
    /// Token'ı revoke et
    /// </summary>
    public void Revoke()
    {
        if (!IsActive)
            throw new InvalidOperationException("Token is already revoked.");

        IsActive = false;
        RevokedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Token geçerli mi kontrol et
    /// </summary>
    /// <returns>Geçerliyse true</returns>
    public bool IsValid()
    {
        return IsActive && DateTime.UtcNow < ExpiresAt;
    }

    /// <summary>
    /// Token expire olmuş mu kontrol et
    /// </summary>
    /// <returns>Expire olduysa true</returns>
    public bool IsExpired()
    {
        return DateTime.UtcNow >= ExpiresAt;
    }

    #endregion
}