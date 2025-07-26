namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Cache Service Contract
/// Caching operations abstraction
/// Redis, MemoryCache gibi farklı implementations destekler
/// </summary>
public interface ICacheService
{
    #region Basic Cache Operations

    /// <summary>
    /// Cache'den veri getirme
    /// </summary>
    /// <typeparam name="T">Veri tipi</typeparam>
    /// <param name="key">Cache key</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Cache'den getirilen veri veya null</returns>
    Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) where T : class;

    /// <summary>
    /// Cache'e veri kaydetme
    /// </summary>
    /// <typeparam name="T">Veri tipi</typeparam>
    /// <param name="key">Cache key</param>
    /// <param name="value">Cache'lenecek değer</param>
    /// <param name="expiration">Expiration süresi (opsiyonel)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class;

    /// <summary>
    /// Cache'den veri silme
    /// </summary>
    /// <param name="key">Cache key</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RemoveAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Key existence kontrolü
    /// </summary>
    /// <param name="key">Cache key</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Key varsa true</returns>
    Task<bool> ExistsAsync(string key, CancellationToken cancellationToken = default);

    #endregion

    #region Pattern Operations

    /// <summary>
    /// Pattern'e göre key'leri silme
    /// Bulk invalidation için kullanılır
    /// </summary>
    /// <param name="pattern">Arama pattern'i (örn: "user:*")</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task RemoveByPatternAsync(string pattern, CancellationToken cancellationToken = default);

    /// <summary>
    /// Pattern'e göre key'leri getirme
    /// </summary>
    /// <param name="pattern">Arama pattern'i</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pattern'e uyan key'ler</returns>
    Task<IEnumerable<string>> GetKeysByPatternAsync(string pattern, CancellationToken cancellationToken = default);

    #endregion

    #region Convenience Methods

    /// <summary>
    /// Get or Set pattern
    /// Cache miss durumunda veriyi getir ve cache'le
    /// </summary>
    /// <typeparam name="T">Veri tipi</typeparam>
    /// <param name="key">Cache key</param>
    /// <param name="getItem">Cache miss durumunda çağrılacak function</param>
    /// <param name="expiration">Expiration süresi</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Cache'den veya source'tan getirilen veri</returns>
    Task<T?> GetOrSetAsync<T>(string key, Func<Task<T?>> getItem, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class;

    #endregion

    #region User-Specific Cache Operations

    /// <summary>
    /// User-specific cache set
    /// Session management için
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="key">Cache key suffix</param>
    /// <param name="value">Cache'lenecek değer</param>
    /// <param name="expiration">Expiration süresi</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SetUserCacheAsync(Guid userId, string key, object value, TimeSpan? expiration = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// User-specific cache get
    /// </summary>
    /// <typeparam name="T">Veri tipi</typeparam>
    /// <param name="userId">User ID</param>
    /// <param name="key">Cache key suffix</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User cache'inden getirilen veri</returns>
    Task<T?> GetUserCacheAsync<T>(Guid userId, string key, CancellationToken cancellationToken = default) where T : class;

    /// <summary>
    /// User'ın tüm cache'ini temizleme
    /// Logout, deactivation durumlarında
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task ClearUserCacheAsync(Guid userId, CancellationToken cancellationToken = default);

    #endregion
}