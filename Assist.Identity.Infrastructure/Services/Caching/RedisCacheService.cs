using Assist.Identity.Application.Contracts;
using Assist.Identity.Infrastructure.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using System.Text.Json;
using System.IO.Compression;
using System.Text;

namespace Assist.Identity.Infrastructure.Services.Caching;

/// <summary>
/// Redis Cache Service Implementation
/// 
/// Bu service ICacheService interface'ini implement eder ve Redis'i backend olarak kullanır.
/// 
/// Redis nedir?
/// Redis (Remote Dictionary Server) in-memory key-value data store'dur.
/// "In-memory" demek tüm data RAM'de tutulur, bu yüzden çok hızlıdır.
/// "Key-value" demek data'yı anahtar-değer çiftleri halinde saklar.
/// 
/// Örnek: 
/// Key: "user:123:permissions"
/// Value: ["CanReadUsers", "CanEditProfile", "CanViewReports"]
/// 
/// Neden Redis kullanıyoruz?
/// 1. Performance: Database'den 1000x daha hızlı
/// 2. Scalability: Multiple server'lar aynı cache'i kullanabilir
/// 3. Distributed: Microservice architecture'da shared state
/// 4. Persistence: RAM'deki data disk'e de yazılabilir
/// 5. Advanced features: Pub/Sub, Lua scripts, data structures
/// 
/// Clean Architecture Integration:
/// - Infrastructure layer'da implement edilir
/// - Application layer sadece ICacheService interface'ini görür
/// - Domain layer cache'den tamamen habersizdir
/// - Redis değişse (MongoDB, Memcached, etc.) sadece bu class değişir
/// </summary>
public class RedisCacheService : ICacheService
{
    private readonly IDatabase _database;
    private readonly IConnectionMultiplexer _connectionMultiplexer;
    private readonly CacheSettings _cacheSettings;
    private readonly ILogger<RedisCacheService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    /// <summary>
    /// RedisCacheService constructor
    /// 
    /// Redis Connection Multiplexer Pattern:
    /// Redis connection'lar expensive'dir, bu yüzden connection pool kullanırız.
    /// IConnectionMultiplexer thread-safe'dir ve application lifetime boyunca reuse edilir.
    /// Multiple threads aynı connection'ı safely kullanabilir.
    /// 
    /// JSON Serialization:
    /// Redis sadece string ve binary data saklar, complex objects'leri JSON'a çevirmemiz gerekir.
    /// .NET'te System.Text.Json en performant JSON serializer'dır.
    /// </summary>
    /// <param name="connectionMultiplexer">Redis connection multiplexer</param>
    /// <param name="cacheOptions">Cache configuration settings</param>
    /// <param name="logger">Structured logging interface</param>
    public RedisCacheService(
        IConnectionMultiplexer connectionMultiplexer,
        IOptions<CacheSettings> cacheOptions,
        ILogger<RedisCacheService> logger)
    {
        _connectionMultiplexer = connectionMultiplexer ?? throw new ArgumentNullException(nameof(connectionMultiplexer));
        _cacheSettings = cacheOptions?.Value ?? throw new ArgumentNullException(nameof(cacheOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Redis database selection (0-15 available)
        // Database 0 is default, diğer database'ler logical separation için kullanılır
        _database = _connectionMultiplexer.GetDatabase(_cacheSettings.Redis.Database);

        // JSON serialization options for optimal performance
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false, // Compressed JSON for lower memory usage
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        _logger.LogInformation("RedisCacheService initialized with database {Database}", _cacheSettings.Redis.Database);
    }

    #region Basic Cache Operations

    /// <summary>
    /// Cache'den veri getirme
    /// 
    /// Redis GET operation flow:
    /// 1. Build full key with prefix (assist:user:123:permissions)
    /// 2. Execute Redis GET command
    /// 3. Check if value exists (null check)
    /// 4. Deserialize JSON string to C# object
    /// 5. Handle decompression if enabled
    /// 6. Return typed object or null
    /// 
    /// Performance: Typically 0.1-1ms for local Redis, 1-5ms for remote Redis
    /// </summary>
    public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) where T : class
    {
        try
        {
            ArgumentNullException.ThrowIfNull(key);

            var fullKey = BuildKey(key);
            _logger.LogDebug("Getting cache value for key: {Key}", fullKey);

            // Redis GET operation - this is where the magic happens!
            // Redis stores everything as RedisValue (which can be string or binary)
            var value = await _database.StringGetAsync(fullKey);

            // Check if key exists in Redis
            if (!value.HasValue)
            {
                _logger.LogDebug("Cache miss for key: {Key}", fullKey);
                return null;
            }

            _logger.LogDebug("Cache hit for key: {Key}", fullKey);

            // Deserialize the JSON string back to C# object
            var deserializedValue = await DeserializeValueAsync<T>(value);
            return deserializedValue;
        }
        catch (RedisException redisEx)
        {
            // Redis-specific errors (connection issues, server problems)
            _logger.LogError(redisEx, "Redis error while getting cache value for key: {Key}", key);
            return null; // Graceful degradation: return null instead of crashing
        }
        catch (Exception ex)
        {
            // General errors (serialization issues, etc.)
            _logger.LogError(ex, "Error while getting cache value for key: {Key}", key);
            return null; // Graceful degradation: cache should never break the application
        }
    }

    /// <summary>
    /// Cache'e veri kaydetme
    /// 
    /// Redis SET operation flow:
    /// 1. Validate input parameters
    /// 2. Serialize C# object to JSON string
    /// 3. Apply compression if value is large enough
    /// 4. Build full key with prefix
    /// 5. Calculate expiration time
    /// 6. Execute Redis SET command with expiration
    /// 7. Log operation for monitoring
    /// 
    /// Expiration types:
    /// - Absolute: Fixed time from now (cache for 30 minutes)
    /// - Sliding: Reset timer each time accessed (session timeout)
    /// - Never: No expiration (dangerous, use carefully!)
    /// </summary>
    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class
    {
        try
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(value);

            var fullKey = BuildKey(key);
            var expirationTime = expiration ?? TimeSpan.FromMinutes(_cacheSettings.Behavior.DefaultExpirationMinutes);

            _logger.LogDebug("Setting cache value for key: {Key} with expiration: {Expiration}", fullKey, expirationTime);

            // Serialize the C# object to JSON string
            var serializedValue = await SerializeValueAsync(value);

            // Redis SET operation with expiration
            // EX parameter sets expiration in seconds
            await _database.StringSetAsync(fullKey, serializedValue, expirationTime);

            _logger.LogDebug("Successfully cached value for key: {Key}", fullKey);
        }
        catch (RedisException redisEx)
        {
            _logger.LogError(redisEx, "Redis error while setting cache value for key: {Key}", key);
            throw; // Cache write errors should be visible to caller
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while setting cache value for key: {Key}", key);
            throw; // Serialization errors should be visible to caller
        }
    }

    /// <summary>
    /// Cache'den veri silme
    /// 
    /// Redis DEL operation:
    /// - Immediately removes key from Redis
    /// - Returns true if key existed, false if key didn't exist
    /// - Very fast operation (microseconds)
    /// 
    /// Use cases:
    /// - User logout: Remove session data
    /// - Permission change: Invalidate permission cache
    /// - Profile update: Remove outdated profile cache
    /// </summary>
    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(key);

            var fullKey = BuildKey(key);
            _logger.LogDebug("Removing cache value for key: {Key}", fullKey);

            // Redis DEL command - removes the key entirely
            var removed = await _database.KeyDeleteAsync(fullKey);

            if (removed)
            {
                _logger.LogDebug("Successfully removed cache value for key: {Key}", fullKey);
            }
            else
            {
                _logger.LogDebug("Cache key did not exist: {Key}", fullKey);
            }
        }
        catch (RedisException redisEx)
        {
            _logger.LogError(redisEx, "Redis error while removing cache value for key: {Key}", key);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while removing cache value for key: {Key}", key);
            throw;
        }
    }

    /// <summary>
    /// Key existence kontrolü
    /// 
    /// Redis EXISTS command:
    /// - Very fast operation (microseconds)
    /// - Doesn't retrieve the value, just checks existence
    /// - Useful for conditional operations
    /// 
    /// Use cases:
    /// - Check if user session exists before extending expiration
    /// - Prevent duplicate cache writes
    /// - Rate limiting implementations
    /// </summary>
    public async Task<bool> ExistsAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(key);

            var fullKey = BuildKey(key);

            // Redis EXISTS command - returns 1 if exists, 0 if not
            var exists = await _database.KeyExistsAsync(fullKey);

            _logger.LogDebug("Key existence check for {Key}: {Exists}", fullKey, exists);
            return exists;
        }
        catch (RedisException redisEx)
        {
            _logger.LogError(redisEx, "Redis error while checking key existence: {Key}", key);
            return false; // Graceful degradation
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while checking key existence: {Key}", key);
            return false; // Graceful degradation
        }
    }

    #endregion

    #region Pattern Operations

    /// <summary>
    /// Pattern'e göre key'leri silme
    /// 
    /// Redis pattern matching:
    /// - "*" matches any characters: "user:*" matches "user:123", "user:456:session"
    /// - "?" matches single character: "user:???" matches "user:123" but not "user:1234"
    /// - "[abc]" matches any of specified characters
    /// 
    /// Implementation strategy:
    /// 1. Use SCAN command to find matching keys (memory efficient)
    /// 2. Batch delete operations to avoid blocking Redis
    /// 3. Handle large result sets with pagination
    /// 
    /// CRITICAL WARNING:
    /// KEYS command is O(N) and blocks Redis server - NEVER use in production!
    /// SCAN command is O(1) per call and doesn't block - always use SCAN!
    /// 
    /// Use cases:
    /// - User logout: Remove all user-related cache ("user:123:*")
    /// - Role change: Remove all permission caches ("user:*:permissions")
    /// - Tenant switch: Remove all tenant-related cache ("tenant:456:*")
    /// </summary>
    public async Task RemoveByPatternAsync(string pattern, CancellationToken cancellationToken = default)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(pattern);

            var fullPattern = BuildKey(pattern);
            _logger.LogDebug("Removing cache values by pattern: {Pattern}", fullPattern);

            var keysToDelete = new List<RedisKey>();

            // Use SCAN instead of KEYS for production safety
            // SCAN is cursor-based iteration that doesn't block Redis
            await foreach (var key in ScanKeysAsync(fullPattern))
            {
                keysToDelete.Add(key);

                // Batch delete to avoid memory issues with large result sets
                if (keysToDelete.Count >= _cacheSettings.Performance.MaxBatchSize)
                {
                    await _database.KeyDeleteAsync(keysToDelete.ToArray());
                    _logger.LogDebug("Batch deleted {Count} keys for pattern: {Pattern}", keysToDelete.Count, fullPattern);
                    keysToDelete.Clear();
                }
            }

            // Delete remaining keys
            if (keysToDelete.Count > 0)
            {
                await _database.KeyDeleteAsync(keysToDelete.ToArray());
                _logger.LogDebug("Final batch deleted {Count} keys for pattern: {Pattern}", keysToDelete.Count, fullPattern);
            }

            _logger.LogInformation("Completed pattern deletion for: {Pattern}", fullPattern);
        }
        catch (RedisException redisEx)
        {
            _logger.LogError(redisEx, "Redis error while removing by pattern: {Pattern}", pattern);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while removing by pattern: {Pattern}", pattern);
            throw;
        }
    }

    /// <summary>
    /// Pattern'e göre key'leri getirme
    /// 
    /// Returns matching keys without their values.
    /// Useful for cache analysis, monitoring, and debugging.
    /// 
    /// Production considerations:
    /// - Limit result count to prevent memory issues
    /// - Use pagination for large result sets
    /// - Monitor performance impact
    /// </summary>
    public async Task<IEnumerable<string>> GetKeysByPatternAsync(string pattern, CancellationToken cancellationToken = default)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(pattern);

            var fullPattern = BuildKey(pattern);
            var keys = new List<string>();

            await foreach (var key in ScanKeysAsync(fullPattern))
            {
                // Remove prefix before returning to caller
                var cleanKey = RemoveKeyPrefix(key);
                keys.Add(cleanKey);

                // Limit results to prevent memory issues
                if (keys.Count >= 1000) // Configurable limit
                {
                    _logger.LogWarning("Key pattern search reached limit of 1000 results for pattern: {Pattern}", pattern);
                    break;
                }
            }

            _logger.LogDebug("Found {Count} keys for pattern: {Pattern}", keys.Count, fullPattern);
            return keys;
        }
        catch (RedisException redisEx)
        {
            _logger.LogError(redisEx, "Redis error while getting keys by pattern: {Pattern}", pattern);
            return Enumerable.Empty<string>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while getting keys by pattern: {Pattern}", pattern);
            return Enumerable.Empty<string>();
        }
    }

    #endregion

    #region Convenience Methods

    /// <summary>
    /// Get or Set pattern - Cache'in en powerful feature'ı!
    /// 
    /// Bu pattern cache miss durumunda automatic olarak data'yı source'tan alır ve cache'ler.
    /// 
    /// Workflow:
    /// 1. Cache'de key var mı kontrol et
    /// 2. Varsa cache'den döndür (cache hit)
    /// 3. Yoksa getItem function'ını çağır (cache miss)
    /// 4. Function sonucunu cache'e kaydet
    /// 5. Sonucu döndür
    /// 
    /// Benefits:
    /// - Boilerplate code'u eliminate eder
    /// - Consistent caching behavior
    /// - Automatic cache warming
    /// - Error handling built-in
    /// 
    /// Use case example:
    /// var userPermissions = await _cacheService.GetOrSetAsync(
    ///     $"user:{userId}:permissions",
    ///     async () => await _userRepository.GetUserPermissionsAsync(userId),
    ///     TimeSpan.FromMinutes(30)
    /// );
    /// </summary>
    public async Task<T?> GetOrSetAsync<T>(string key, Func<Task<T?>> getItem, TimeSpan? expiration = null, CancellationToken cancellationToken = default) where T : class
    {
        try
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(getItem);

            // First, try to get from cache
            var cachedValue = await GetAsync<T>(key, cancellationToken);

            if (cachedValue != null)
            {
                _logger.LogDebug("Cache hit for GetOrSet key: {Key}", key);
                return cachedValue;
            }

            _logger.LogDebug("Cache miss for GetOrSet key: {Key}, executing getItem function", key);

            // Cache miss - execute the function to get fresh data
            var freshValue = await getItem();

            if (freshValue != null)
            {
                // Cache the fresh value for future requests
                await SetAsync(key, freshValue, expiration, cancellationToken);
                _logger.LogDebug("Cached fresh value for GetOrSet key: {Key}", key);
            }
            else
            {
                _logger.LogDebug("GetItem function returned null for key: {Key}", key);
            }

            return freshValue;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in GetOrSet for key: {Key}", key);

            // Graceful degradation: if cache fails, still execute getItem
            try
            {
                return await getItem();
            }
            catch (Exception getItemEx)
            {
                _logger.LogError(getItemEx, "Both cache and getItem failed for key: {Key}", key);
                throw; // Re-throw getItem exception as it's more important
            }
        }
    }

    #endregion

    #region User-Specific Cache Operations

    /// <summary>
    /// User-specific cache operations
    /// 
    /// Bu methods user-related caching'i kolaylaştırır ve consistent key naming sağlar.
    /// Application layer'da developers bu helpers'ı kullanarak:
    /// - Key naming'i standardize eder
    /// - User-specific expiration policies uygular
    /// - Type-safe user data caching yapar
    /// 
    /// Benefits:
    /// - Consistent key patterns
    /// - Reduced boilerplate code
    /// - Type safety
    /// - User-specific expiration policies
    /// </summary>
    public async Task SetUserCacheAsync(Guid userId, string key, object value, TimeSpan? expiration = null, CancellationToken cancellationToken = default)
    {
        var userKey = _cacheSettings.Keys.User.Session.Replace("{userId}", userId.ToString());
        var fullKey = $"{userKey}:{key}";

        var userExpiration = expiration ?? TimeSpan.FromMinutes(_cacheSettings.Behavior.SessionExpirationMinutes);

        await SetAsync(fullKey, value, userExpiration, cancellationToken);
        _logger.LogDebug("Set user cache for user {UserId}, key: {Key}", userId, key);
    }

    /// <summary>
    /// User-specific cache retrieval
    /// </summary>
    public async Task<T?> GetUserCacheAsync<T>(Guid userId, string key, CancellationToken cancellationToken = default) where T : class
    {
        var userKey = _cacheSettings.Keys.User.Session.Replace("{userId}", userId.ToString());
        var fullKey = $"{userKey}:{key}";

        var result = await GetAsync<T>(fullKey, cancellationToken);
        _logger.LogDebug("Get user cache for user {UserId}, key: {Key}, found: {Found}", userId, key, result != null);

        return result;
    }

    /// <summary>
    /// User'ın tüm cache'ini temizleme
    /// 
    /// Bu method user logout, account deactivation, permission changes
    /// gibi durumlarda user'ın tüm cached data'sını temizler.
    /// 
    /// Clears:
    /// - Session data
    /// - Permission cache
    /// - Role cache
    /// - Profile cache
    /// - Any other user-specific cache
    /// </summary>
    public async Task ClearUserCacheAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var userPattern = $"user:{userId}:*";
        await RemoveByPatternAsync(userPattern, cancellationToken);
        _logger.LogInformation("Cleared all cache for user: {UserId}", userId);
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// Build full Redis key with prefix
    /// 
    /// Key building strategy:
    /// 1. Take configured prefix (assist:)
    /// 2. Append provided key
    /// 3. Ensure consistent naming
    /// 
    /// Examples:
    /// Input: "user:123:permissions"
    /// Output: "assist:user:123:permissions"
    /// 
    /// Benefits:
    /// - Namespace isolation (multiple apps can use same Redis)
    /// - Environment separation (dev:, prod:, test:)
    /// - Easier debugging and monitoring
    /// </summary>
    private string BuildKey(string key)
    {
        var prefix = _cacheSettings.Redis.KeyPrefix.TrimEnd(':');
        return $"{prefix}:{key}";
    }

    /// <summary>
    /// Remove prefix from Redis key for clean return values
    /// </summary>
    private string RemoveKeyPrefix(string fullKey)
    {
        var prefix = _cacheSettings.Redis.KeyPrefix.TrimEnd(':') + ":";
        return fullKey.StartsWith(prefix) ? fullKey.Substring(prefix.Length) : fullKey;
    }

    /// <summary>
    /// SCAN operation for safe key pattern matching
    /// 
    /// Redis SCAN vs KEYS:
    /// 
    /// KEYS command (DANGEROUS):
    /// - O(N) complexity - gets slower as database grows
    /// - Blocks Redis server - no other operations can execute
    /// - Returns all matches at once - can cause memory issues
    /// - Never use in production!
    /// 
    /// SCAN command (SAFE):
    /// - O(1) per call - consistent performance
    /// - Non-blocking - Redis can serve other requests
    /// - Cursor-based iteration - memory efficient
    /// - Production safe - always use this!
    /// 
    /// Custom Implementation Strategy:
    /// Since StackExchange.Redis versions have different SCAN APIs across versions,
    /// we implement a compatible approach that works across different library versions.
    /// This approach uses direct Redis commands which are more stable across versions.
    /// 
    /// Learning Note:
    /// This is a great example of why sometimes implementing your own solution
    /// is more reliable than depending on library-specific convenience methods.
    /// </summary>
    private async IAsyncEnumerable<RedisKey> ScanKeysAsync(string pattern)
    {
        // Move try-catch outside the yield return loop
        var database = _connectionMultiplexer.GetDatabase(_cacheSettings.Redis.Database);

        long cursor = 0;

        while (true)
        {
            RedisResult result;
            try
            {
                result = await database.ExecuteAsync("SCAN", cursor, "MATCH", pattern, "COUNT", 100);
            }
            catch (RedisException ex)
            {
                _logger.LogError(ex, "Redis SCAN operation failed for pattern: {Pattern}", pattern);
                yield break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during SCAN operation for pattern: {Pattern}", pattern);
                yield break;
            }

            if (result.IsNull)
                yield break;

            var resultArray = (RedisResult[])result;
            cursor = (long)resultArray[0];

            var keys = (RedisResult[])resultArray[1];
            foreach (RedisResult key in keys)
            {
                yield return (RedisKey)key;
            }

            if (cursor == 0)
                break;
        }
    }

    /// <summary>
    /// Serialize C# object to JSON string for Redis storage
    /// 
    /// Serialization considerations:
    /// 1. Choose fast serializer (System.Text.Json is fastest)
    /// 2. Optimize for size (no indentation, ignore nulls)
    /// 3. Handle special types (DateTime, Guid, Enum)
    /// 4. Consider compression for large objects
    /// 
    /// Why JSON instead of binary?
    /// - Human readable (great for debugging)
    /// - Language agnostic (other services can read)
    /// - Redis tooling support (Redis CLI can show values)
    /// - Smaller size than many binary formats
    /// </summary>
    private async Task<RedisValue> SerializeValueAsync<T>(T value)
    {
        var json = JsonSerializer.Serialize(value, _jsonOptions);

        // Apply compression if enabled and value is large enough
        if (_cacheSettings.Behavior.EnableCompression &&
            Encoding.UTF8.GetByteCount(json) >= _cacheSettings.Behavior.CompressionThresholdBytes)
        {
            var compressed = await CompressStringAsync(json);
            _logger.LogDebug("Applied compression, original: {OriginalSize} bytes, compressed: {CompressedSize} bytes",
                Encoding.UTF8.GetByteCount(json), compressed.Length);
            return compressed;
        }

        return json;
    }

    /// <summary>
    /// Deserialize JSON string from Redis back to C# object
    /// </summary>
    private async Task<T?> DeserializeValueAsync<T>(RedisValue value) where T : class
    {
        string json;

        // Check if value is compressed (binary data)
        if (value.HasValue && !value.IsNull)
        {
            if (IsCompressedValue(value))
            {
                json = await DecompressStringAsync(value);
                _logger.LogDebug("Decompressed cache value");
            }
            else
            {
                json = value.ToString();
            }

            return JsonSerializer.Deserialize<T>(json, _jsonOptions);
        }

        return null;
    }

    /// <summary>
    /// Compress string data for more efficient storage
    /// 
    /// Compression benefits:
    /// - Reduced memory usage in Redis
    /// - Faster network transfer (less bytes)
    /// - Lower costs on cloud Redis services
    /// 
    /// Compression trade-offs:
    /// - CPU overhead for compression/decompression
    /// - Slightly increased latency
    /// - More complex debugging (compressed data not readable)
    /// 
    /// When to use:
    /// - Large objects (> 1KB)
    /// - Frequently cached data
    /// - Network-constrained environments
    /// - Cost-sensitive cloud deployments
    /// </summary>
    private async Task<byte[]> CompressStringAsync(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);

        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest))
        {
            await gzip.WriteAsync(bytes, 0, bytes.Length);
        }

        return output.ToArray();
    }

    /// <summary>
    /// Decompress binary data back to string
    /// </summary>
    private async Task<string> DecompressStringAsync(byte[] compressedData)
    {
        using var input = new MemoryStream(compressedData);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();

        await gzip.CopyToAsync(output);

        return Encoding.UTF8.GetString(output.ToArray());
    }

    /// <summary>
    /// Detect if Redis value is compressed binary data or plain JSON text
    /// 
    /// Simple heuristic: if first byte is GZip magic number (0x1F), it's compressed
    /// </summary>
    private bool IsCompressedValue(RedisValue value)
    {
        if (value.IsNull || !value.HasValue) return false;

        // GZip magic number detection
        var bytes = (byte[])value;
        return bytes.Length > 2 && bytes[0] == 0x1F && bytes[1] == 0x8B;
    }

    #endregion
}