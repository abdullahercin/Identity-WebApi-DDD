namespace Assist.Identity.Infrastructure.Configuration;

/// <summary>
/// Redis Cache Configuration Settings
/// 
/// Redis adalah in-memory data structure store yang digunakan sebagai:
/// - Cache: Menyimpan data sementara untuk meningkatkan performance
/// - Session Store: Menyimpan session data untuk aplikasi distributed
/// - Message Broker: Publish/Subscribe messaging (advanced feature)
/// 
/// Konfigurasi ini mendukung:
/// - Single Redis instance (development)
/// - Redis Cluster (production)
/// - Redis Sentinel (high availability)
/// - Connection pooling dan timeout settings
/// - Security settings (password, SSL)
/// </summary>
public class CacheSettings
{
    /// <summary>
    /// Configuration section name untuk appsettings.json
    /// Usage: IConfiguration.GetSection("Cache")
    /// </summary>
    public const string SectionName = "Cache";

    /// <summary>
    /// Cache provider type
    /// Supported values: "Redis", "Memory", "Distributed"
    /// 
    /// "Memory": In-process caching (single server apps)
    /// "Redis": Distributed caching (multi-server apps) 
    /// "Distributed": Generic distributed cache interface
    /// </summary>
    public string Provider { get; set; } = "Redis";

    /// <summary>
    /// Redis connection settings
    /// </summary>
    public RedisSettings Redis { get; set; } = new();

    /// <summary>
    /// General cache behavior settings
    /// </summary>
    public CacheBehaviorSettings Behavior { get; set; } = new();

    /// <summary>
    /// Key naming conventions
    /// Consistent key naming untuk better organization
    /// </summary>
    public KeySettings Keys { get; set; } = new();

    /// <summary>
    /// Performance settings
    /// </summary>
    public PerformanceSettings Performance { get; set; } = new();
}

/// <summary>
/// Redis-specific connection dan server settings
/// 
/// Redis connection string format:
/// "localhost:6379" (simple)
/// "localhost:6379,password=mypassword" (with auth)
/// "localhost:6379,ssl=true,password=mypassword" (with SSL)
/// </summary>
public class RedisSettings
{
    /// <summary>
    /// Redis server connection string
    /// 
    /// Examples:
    /// Development: "localhost:6379"
    /// Production: "your-redis-server.com:6379,password=your-password"
    /// Azure Redis: "your-cache.redis.cache.windows.net:6380,password=key,ssl=True"
    /// AWS ElastiCache: "your-cluster.cache.amazonaws.com:6379"
    /// </summary>
    public string ConnectionString { get; set; } = "localhost:6379";

    /// <summary>
    /// Redis database number (0-15)
    /// 
    /// Redis supports multiple databases pada single instance:
    /// 0: Default database (biasanya digunakan)
    /// 1: Development/testing
    /// 2: Session storage
    /// 3: Cache storage
    /// 
    /// Best practice: Use database 0 unless ada specific requirement
    /// </summary>
    public int Database { get; set; } = 0;

    /// <summary>
    /// Key prefix untuk namespace isolation
    /// 
    /// Examples:
    /// "myapp:" → Keys: "myapp:user:123", "myapp:session:456"
    /// "dev:" → Development environment isolation
    /// "prod:" → Production environment isolation
    /// 
    /// Benefits:
    /// - Prevents key collisions between applications
    /// - Environment isolation
    /// - Easier debugging dan monitoring
    /// </summary>
    public string KeyPrefix { get; set; } = "assist:";

    /// <summary>
    /// Connection timeout dalam seconds
    /// 
    /// Timeout types explained:
    /// - Connect Timeout: Time to establish connection
    /// - Command Timeout: Time to execute single command
    /// - Sync Timeout: Time for synchronous operations
    /// 
    /// Recommended values:
    /// Development: 5 seconds
    /// Production: 10-30 seconds (based on network latency)
    /// </summary>
    public int ConnectTimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// Command execution timeout dalam seconds
    /// Jika Redis command lebih lama dari ini, akan timeout
    /// </summary>
    public int CommandTimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// Connection retry count
    /// Jika initial connection gagal, berapa kali retry
    /// </summary>
    public int RetryCount { get; set; } = 3;

    /// <summary>
    /// Enable SSL/TLS encryption
    /// Required untuk cloud Redis services (Azure, AWS)
    /// </summary>
    public bool UseSsl { get; set; } = false;

    /// <summary>
    /// Configuration validation
    /// Memastikan Redis settings valid sebelum application start
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ConnectionString))
            throw new InvalidOperationException("Redis ConnectionString is required");

        if (Database < 0 || Database > 15)
            throw new InvalidOperationException($"Redis Database must be between 0-15, got: {Database}");

        if (ConnectTimeoutSeconds <= 0 || ConnectTimeoutSeconds > 300)
            throw new InvalidOperationException($"ConnectTimeoutSeconds must be between 1-300, got: {ConnectTimeoutSeconds}");

        if (CommandTimeoutSeconds <= 0 || CommandTimeoutSeconds > 300)
            throw new InvalidOperationException($"CommandTimeoutSeconds must be between 1-300, got: {CommandTimeoutSeconds}");

        if (RetryCount < 0 || RetryCount > 10)
            throw new InvalidOperationException($"RetryCount must be between 0-10, got: {RetryCount}");
    }
}

/// <summary>
/// Cache behavior dan expiration settings
/// 
/// Cache expiration strategies:
/// 1. Sliding Expiration: Reset expiration setiap kali accessed
/// 2. Absolute Expiration: Fixed expiration time dari creation
/// 3. Never Expires: Cache until manually removed (hati-hati!)
/// </summary>
public class CacheBehaviorSettings
{
    /// <summary>
    /// Default cache expiration time dalam minutes
    /// 
    /// Guidelines:
    /// - User sessions: 60 minutes (sliding)
    /// - Permission cache: 30 minutes (absolute)  
    /// - Static data: 24 hours (absolute)
    /// - Configuration: 1 hour (absolute)
    /// </summary>
    public int DefaultExpirationMinutes { get; set; } = 30;

    /// <summary>
    /// Session-specific expiration dalam minutes
    /// User session data biasanya longer expiration
    /// </summary>
    public int SessionExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Permission cache expiration dalam minutes
    /// Permission data perlu balance antara performance dan freshness
    /// </summary>
    public int PermissionExpirationMinutes { get; set; } = 30;

    /// <summary>
    /// Enable sliding expiration for sessions
    /// 
    /// True: Session expiration reset setiap kali user active
    /// False: Session expire pada fixed time after creation
    /// 
    /// Recommendation: True untuk better user experience
    /// </summary>
    public bool EnableSlidingExpiration { get; set; } = true;

    /// <summary>
    /// Compress large cache values
    /// 
    /// Benefits:
    /// - Reduced memory usage
    /// - Faster network transfer
    /// - Lower costs pada cloud Redis
    /// 
    /// Drawbacks:
    /// - CPU overhead for compression/decompression
    /// - Slightly increased latency
    /// 
    /// Recommendation: Enable untuk values > 1KB
    /// </summary>
    public bool EnableCompression { get; set; } = true;

    /// <summary>
    /// Minimum size untuk compression dalam bytes
    /// Values smaller than this tidak akan di-compress
    /// </summary>
    public int CompressionThresholdBytes { get; set; } = 1024; // 1KB

    /// <summary>
    /// Enable cache statistics tracking
    /// Useful untuk monitoring cache hit/miss rates
    /// </summary>
    public bool EnableStatistics { get; set; } = true;
}

/// <summary>
/// Cache key naming conventions dan patterns
/// 
/// Consistent key naming benefits:
/// - Easy debugging
/// - Better monitoring
/// - Efficient pattern-based operations
/// - Clear data organization
/// </summary>
public class KeySettings
{
    /// <summary>
    /// Key separator character
    /// 
    /// Common conventions:
    /// ":" → Redis standard (user:123:session)
    /// "." → .NET style (user.123.session)  
    /// "_" → Underscore style (user_123_session)
    /// 
    /// Recommendation: ":" karena Redis tooling support better
    /// </summary>
    public string Separator { get; set; } = ":";

    /// <summary>
    /// User-related key patterns
    /// 
    /// Pattern examples:
    /// "user:{userId}" → User profile data
    /// "user:{userId}:session" → User session data
    /// "user:{userId}:permissions" → User permissions
    /// "user:{userId}:roles" → User roles
    /// </summary>
    public UserKeyPatterns User { get; set; } = new();

    /// <summary>
    /// System-wide key patterns
    /// </summary>
    public SystemKeyPatterns System { get; set; } = new();

    /// <summary>
    /// Temporary key patterns
    /// Untuk data yang short-lived (tokens, OTP, etc.)
    /// </summary>
    public TempKeyPatterns Temp { get; set; } = new();
}

/// <summary>
/// User-specific cache key patterns
/// Semua user-related data akan menggunakan patterns ini
/// </summary>
public class UserKeyPatterns
{
    /// <summary>
    /// User profile cache key pattern
    /// Example: "user:123" atau "user:abc-def-ghi"
    /// </summary>
    public string Profile { get; set; } = "user:{userId}";

    /// <summary>
    /// User session cache key pattern
    /// Example: "user:123:session"
    /// </summary>
    public string Session { get; set; } = "user:{userId}:session";

    /// <summary>
    /// User permissions cache key pattern
    /// Example: "user:123:permissions"
    /// </summary>
    public string Permissions { get; set; } = "user:{userId}:permissions";

    /// <summary>
    /// User roles cache key pattern
    /// Example: "user:123:roles"
    /// </summary>
    public string Roles { get; set; } = "user:{userId}:roles";

    /// <summary>
    /// User statistics cache key pattern
    /// Example: "user:123:stats"
    /// </summary>
    public string Statistics { get; set; } = "user:{userId}:stats";
}

/// <summary>
/// System-wide cache key patterns
/// Untuk application-level data yang tidak user-specific
/// </summary>
public class SystemKeyPatterns
{
    /// <summary>
    /// System configuration cache
    /// Example: "system:config:email"
    /// </summary>
    public string Configuration { get; set; } = "system:config:{configType}";

    /// <summary>
    /// Application statistics
    /// Example: "system:stats:daily"
    /// </summary>
    public string Statistics { get; set; } = "system:stats:{statsType}";

    /// <summary>
    /// Lookup tables dan reference data
    /// Example: "system:lookup:countries"
    /// </summary>
    public string Lookups { get; set; } = "system:lookup:{lookupType}";
}

/// <summary>
/// Temporary cache key patterns
/// Untuk short-lived data seperti tokens, OTP, verification codes
/// </summary>
public class TempKeyPatterns
{
    /// <summary>
    /// Email verification tokens
    /// Example: "temp:email:verification:abc123"
    /// </summary>
    public string EmailVerification { get; set; } = "temp:email:verification:{token}";

    /// <summary>
    /// Password reset tokens
    /// Example: "temp:password:reset:def456"
    /// </summary>
    public string PasswordReset { get; set; } = "temp:password:reset:{token}";

    /// <summary>
    /// One-time passwords
    /// Example: "temp:otp:user:123"
    /// </summary>
    public string OneTimePassword { get; set; } = "temp:otp:user:{userId}";

    /// <summary>
    /// API rate limiting
    /// Example: "temp:ratelimit:api:192.168.1.100"
    /// </summary>
    public string RateLimit { get; set; } = "temp:ratelimit:{limitType}:{identifier}";
}

/// <summary>
/// Performance dan optimization settings
/// 
/// Performance considerations:
/// - Connection pooling untuk better throughput
/// - Batch operations untuk reduced network calls
/// - Pipeline operations untuk improved latency
/// - Memory management untuk large datasets
/// </summary>
public class PerformanceSettings
{
    /// <summary>
    /// Maximum connection pool size
    /// 
    /// Guidelines:
    /// Development: 10-20 connections
    /// Production: 50-100 connections (depends on load)
    /// High traffic: 200+ connections
    /// 
    /// Note: Too many connections dapat overload Redis server
    /// </summary>
    public int MaxConnectionPoolSize { get; set; } = 50;

    /// <summary>
    /// Enable connection multiplexing
    /// 
    /// True: Multiple operations share single connection (recommended)
    /// False: Each operation uses separate connection (resource intensive)
    /// </summary>
    public bool EnableMultiplexing { get; set; } = true;

    /// <summary>
    /// Enable pipeline operations
    /// 
    /// Pipeline benefits:
    /// - Reduced network round trips
    /// - Higher throughput
    /// - Lower latency untuk bulk operations
    /// 
    /// Drawbacks:
    /// - Increased memory usage
    /// - More complex error handling
    /// </summary>
    public bool EnablePipeline { get; set; } = true;

    /// <summary>
    /// Maximum batch size untuk bulk operations
    /// Prevents memory issues dengan very large batches
    /// </summary>
    public int MaxBatchSize { get; set; } = 100;

    /// <summary>
    /// Enable automatic failover
    /// Important untuk production environments
    /// </summary>
    public bool EnableFailover { get; set; } = true;

    /// <summary>
    /// Health check interval dalam seconds
    /// Frequency untuk checking Redis server health
    /// </summary>
    public int HealthCheckIntervalSeconds { get; set; } = 30;
}