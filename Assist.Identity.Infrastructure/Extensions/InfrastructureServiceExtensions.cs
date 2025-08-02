using Assist.Identity.Application.Contracts;
using Assist.Identity.Infrastructure.Configuration;
using Assist.Identity.Infrastructure.Services.Caching;
using Assist.Identity.Infrastructure.Services.Email;
using Assist.Identity.Infrastructure.Services.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Assist.Identity.Infrastructure.Extensions;

/// <summary>
/// Infrastructure Services Extension
/// 
/// Bu extension Infrastructure layer'daki tüm service'lerin dependency injection'ını organize eder.
/// Clean Architecture prensiplerine uygun olarak:
/// 
/// 1. Application layer interface'lerinin Infrastructure implementations'larını register eder
/// 2. Configuration binding'lerini setup eder
/// 3. External service connections'ları kurar (Redis, SMTP)
/// 4. Service lifetime'larını (Singleton, Scoped, Transient) doğru şekilde configure eder
/// 
/// Bu approach'un faydaları:
/// - Startup.cs/Program.cs'te clean kod
/// - Infrastructure concerns'ların encapsulation'ı
/// - Configuration validation'ın centralized yapılması
/// - Service dependencies'lerin organized management'ı
/// - Easy testing ve mocking capabilities
/// </summary>
public static class InfrastructureServicesExtension
{
    /// <summary>
    /// Infrastructure services'leri DI container'a register eder
    /// 
    /// Bu method şu adımları takip eder:
    /// 1. Configuration binding (strongly-typed settings)
    /// 2. External connections setup (Redis, SMTP validation)
    /// 3. Service registrations (Application interfaces → Infrastructure implementations)
    /// 4. Service lifetime configuration (performance optimization)
    /// 5. Health checks setup (monitoring ve diagnostics)
    /// 
    /// Calling code example:
    /// builder.Services.AddInfrastructureServices(builder.Configuration);
    /// </summary>
    /// <param name="services">Service collection untuk DI registration</param>
    /// <param name="configuration">Application configuration</param>
    /// <returns>Service collection fluent interface için</returns>
    public static IServiceCollection AddInfrastructureServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Step 1: Configuration Settings Registration
        AddConfigurationSettings(services, configuration);

        // Step 2: External Service Connections
        AddExternalServiceConnections(services, configuration);

        // Step 3: Application Service Implementations
        AddApplicationServiceImplementations(services);

        // Step 4: Health Checks
        AddHealthChecks(services, configuration);

        return services;
    }

    /// <summary>
    /// Configuration settings'leri strongly-typed olarak register eder
    /// 
    /// IOptions pattern benefits:
    /// - Type safety: Configuration errors caught at startup
    /// - IntelliSense support: Better developer experience  
    /// - Validation: Invalid configurations prevent application startup
    /// - Testing: Easy to mock configurations in unit tests
    /// - Reloading: Configuration changes can be picked up at runtime (with IOptionsMonitor)
    /// 
    /// Each configuration section validation:
    /// - Required fields validation
    /// - Range validations (ports, timeouts, etc.)
    /// - Format validations (email addresses, URLs, etc.)
    /// - Business rule validations (consistent settings)
    /// </summary>
    private static void AddConfigurationSettings(IServiceCollection services, IConfiguration configuration)
    {
        // Cache Settings (Redis configuration)
        services.Configure<CacheSettings>(configuration.GetSection(CacheSettings.SectionName));
        services.AddSingleton(resolver =>
        {
            var cacheSettings = configuration.GetSection(CacheSettings.SectionName).Get<CacheSettings>()
                ?? throw new InvalidOperationException("Cache configuration is missing");

            // Validate configuration at startup (fail-fast principle)
            cacheSettings.Redis.Validate();
            cacheSettings.Behavior.CompressionThresholdBytes = Math.Max(cacheSettings.Behavior.CompressionThresholdBytes, 100);

            return Microsoft.Extensions.Options.Options.Create(cacheSettings);
        });

        // Email Settings (SMTP configuration)
        services.Configure<EmailSettings>(configuration.GetSection(EmailSettings.SectionName));
        services.AddSingleton(resolver =>
        {
            var emailSettings = configuration.GetSection(EmailSettings.SectionName).Get<EmailSettings>()
                ?? throw new InvalidOperationException("Email configuration is missing");

            // Validate SMTP settings
            emailSettings.Smtp.Validate();
            emailSettings.BulkEmail.Validate();

            if (string.IsNullOrWhiteSpace(emailSettings.FromEmail))
                throw new InvalidOperationException("Email:FromEmail configuration is required");

            return Microsoft.Extensions.Options.Options.Create(emailSettings);
        });

        // App Settings (URL configuration)
        services.Configure<AppSettings>(configuration.GetSection(AppSettings.SectionName));
        services.AddSingleton(resolver =>
        {
            var appSettings = configuration.GetSection(AppSettings.SectionName).Get<AppSettings>()
                ?? new AppSettings(); // Default values if section missing

            if (string.IsNullOrWhiteSpace(appSettings.BaseUrl))
                appSettings.BaseUrl = "https://localhost:5000"; // Development default

            return Microsoft.Extensions.Options.Options.Create(appSettings);
        });
    }

    /// <summary>
    /// External service connections'ları kurar
    /// 
    /// Redis Connection Management:
    /// - ConnectionMultiplexer thread-safe ve expensive resource'dur
    /// - Application lifetime boyunca single instance kullanılmalı (Singleton)
    /// - Connection pooling otomatik olarak manage edilir
    /// - Reconnection logic built-in'dir
    /// 
    /// Connection string format examples:
    /// - Development: "localhost:6379"
    /// - Production: "redis-server.com:6379,password=secret"
    /// - Azure Redis: "your-cache.redis.cache.windows.net:6380,password=key,ssl=True"
    /// - AWS ElastiCache: "your-cluster.cache.amazonaws.com:6379"
    /// </summary>
    private static void AddExternalServiceConnections(IServiceCollection services, IConfiguration configuration)
    {
        // Redis Connection - Singleton pattern
        services.AddSingleton<IConnectionMultiplexer>(serviceProvider =>
        {
            var logger = serviceProvider.GetRequiredService<ILogger<IConnectionMultiplexer>>();
            var cacheSettings = configuration.GetSection(CacheSettings.SectionName).Get<CacheSettings>()
                ?? throw new InvalidOperationException("Cache configuration is missing");

            logger.LogInformation("Initializing Redis connection to: {ConnectionString}",
                MaskSensitiveInfo(cacheSettings.Redis.ConnectionString));

            try
            {
                // ConfigurationOptions for advanced Redis configuration
                var configurationOptions = ConfigurationOptions.Parse(cacheSettings.Redis.ConnectionString);

                // Apply additional settings from configuration
                configurationOptions.ConnectTimeout = cacheSettings.Redis.ConnectTimeoutSeconds * 1000;
                configurationOptions.SyncTimeout = cacheSettings.Redis.CommandTimeoutSeconds * 1000;
                configurationOptions.ConnectRetry = cacheSettings.Redis.RetryCount;
                configurationOptions.Ssl = cacheSettings.Redis.UseSsl;
                configurationOptions.AbortOnConnectFail = false; // Keep trying to connect

                // Connection multiplexer with comprehensive error handling
                var connectionMultiplexer = ConnectionMultiplexer.Connect(configurationOptions);

                // Connection event logging for monitoring
                connectionMultiplexer.ConnectionFailed += (sender, args) =>
                {
                    logger.LogError("Redis connection failed: {FailureType} - {Exception}",
                        args.FailureType, args.Exception?.Message);
                };

                connectionMultiplexer.ConnectionRestored += (sender, args) =>
                {
                    logger.LogInformation("Redis connection restored: {FailureType}", args.FailureType);
                };

                connectionMultiplexer.ErrorMessage += (sender, args) =>
                {
                    logger.LogError("Redis error: {Message}", args.Message);
                };

                logger.LogInformation("Redis connection established successfully. Database: {Database}",
                    cacheSettings.Redis.Database);

                return connectionMultiplexer;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to establish Redis connection");
                throw new InvalidOperationException($"Redis connection failed: {ex.Message}", ex);
            }
        });

        // Redis Database - Scoped for better resource management
        services.AddScoped<IDatabase>(serviceProvider =>
        {
            var connectionMultiplexer = serviceProvider.GetRequiredService<IConnectionMultiplexer>();
            var cacheSettings = configuration.GetSection(CacheSettings.SectionName).Get<CacheSettings>()!;

            return connectionMultiplexer.GetDatabase(cacheSettings.Redis.Database);
        });
    }

    /// <summary>
    /// Application service interface'lerini Infrastructure implementations'larına bind eder
    /// 
    /// Service Lifetime Strategies:
    /// 
    /// Singleton Services:
    /// - Expensive to create (database connections, external clients)
    /// - Thread-safe implementations
    /// - No per-request state
    /// - Examples: IConnectionMultiplexer, HttpClient
    /// 
    /// Scoped Services:
    /// - Per-request lifetime (web applications)
    /// - Database contexts, repositories
    /// - Request-specific state
    /// - Examples: DbContext, Repositories, Most business services
    /// 
    /// Transient Services:
    /// - Created every time requested
    /// - Lightweight objects
    /// - No shared state
    /// - Examples: Validators, Mappers, Simple calculators
    /// </summary>
    private static void AddApplicationServiceImplementations(IServiceCollection services)
    {
        // Cache Service - Scoped (request-level caching scenarios)
        // Redis connections are thread-safe, but service may have request-specific context
        services.AddScoped<ICacheService, RedisCacheService>();

        // Email Service - Scoped (request-level email sending)
        // SMTP connections are created per-request, configuration is shared
        services.AddScoped<IEmailService, EmailService>();

        // Password Hashing Service - Scoped (security service with request context)
        // BCrypt operations are CPU-intensive but thread-safe
        services.AddScoped<IPasswordHashingService, PasswordHashingService>();

        // JWT Token Service - Scoped (token generation per request)
        // Token generation includes request-specific claims and expiration
        services.AddScoped<ITokenService, JwtTokenService>();

        // Current User Service - Scoped (per-request user context)
        // Extracts user information from HTTP context or JWT token
        // Will be implemented in next step
        services.AddScoped<ICurrentUserService, CurrentUserService>();

        // Current Tenant Service - Scoped (per-request tenant context)  
        // Extracts tenant information from subdomain, header, or JWT
        // Will be implemented in next step
        // services.AddScoped<ICurrentTenantService, CurrentTenantService>();
    }

    /// <summary>
    /// Health checks for monitoring infrastructure service health
    /// 
    /// Health check benefits:
    /// - Early detection of infrastructure problems
    /// - Kubernetes/Docker health probe support
    /// - Load balancer health endpoint
    /// - Monitoring system integration
    /// - Automated alerting capabilities
    /// 
    /// Health check categories:
    /// - Liveness: Is application running?
    /// - Readiness: Is application ready to serve requests?
    /// - External dependencies: Are external services available?
    /// </summary>
    private static void AddHealthChecks(IServiceCollection services, IConfiguration configuration)
    {
        var healthChecksBuilder = services.AddHealthChecks();

        // Redis health check
        var cacheSettings = configuration.GetSection(CacheSettings.SectionName).Get<CacheSettings>();
        if (cacheSettings?.Provider == "Redis")
        {
            healthChecksBuilder.AddCheck<RedisHealthCheck>(
                name: "redis",
                tags: new[] { "infrastructure", "cache" });
        }

        // SMTP health check (optional - some SMTP servers don't support health checks)
        // healthChecksBuilder.AddCheck<SmtpHealthCheck>(
        //     name: "smtp", 
        //     tags: new[] { "infrastructure", "email" });

        // Custom application health check
        healthChecksBuilder.AddCheck<ApplicationHealthCheck>(
            name: "application",
            tags: new[] { "application", "self" });
    }

    /// <summary>
    /// Security helper - masks sensitive information in logs
    /// 
    /// Security best practices:
    /// - Never log full connection strings (they contain passwords)
    /// - Never log authentication tokens
    /// - Never log personal identifiable information (PII)
    /// - Use structured logging for better security monitoring
    /// 
    /// Example transformations:
    /// "redis:6379,password=secret123" → "redis:6379,password=***"
    /// "user@domain.com" → "u***@domain.com"
    /// </summary>
    private static string MaskSensitiveInfo(string connectionString)
    {
        if (string.IsNullOrEmpty(connectionString)) return connectionString;

        // Mask password in connection string
        if (connectionString.Contains("password=", StringComparison.OrdinalIgnoreCase))
        {
            var parts = connectionString.Split(',');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].TrimStart().StartsWith("password=", StringComparison.OrdinalIgnoreCase))
                {
                    parts[i] = "password=***";
                }
            }
            return string.Join(",", parts);
        }

        return connectionString;
    }
}

/// <summary>
/// Redis Health Check Implementation
/// Monitors Redis server connectivity and performance
/// </summary>
public class RedisHealthCheck : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    private readonly IConnectionMultiplexer _connectionMultiplexer;
    private readonly ILogger<RedisHealthCheck> _logger;

    public RedisHealthCheck(IConnectionMultiplexer connectionMultiplexer, ILogger<RedisHealthCheck> logger)
    {
        _connectionMultiplexer = connectionMultiplexer;
        _logger = logger;
    }

    public async Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var database = _connectionMultiplexer.GetDatabase();

            // Simple ping test
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            await database.PingAsync();
            stopwatch.Stop();

            var data = new Dictionary<string, object>
            {
                ["ping_time_ms"] = stopwatch.ElapsedMilliseconds,
                ["connected_endpoints"] = _connectionMultiplexer.GetEndPoints().Length,
                ["is_connected"] = _connectionMultiplexer.IsConnected
            };

            if (stopwatch.ElapsedMilliseconds < 100)
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy("Redis is responsive", data);
            }
            else if (stopwatch.ElapsedMilliseconds < 1000)
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Degraded("Redis is slow", null, data);
            }
            else
            {
                return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("Redis is too slow", null, data: data);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis health check failed");
            return Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("Redis connection failed", exception: ex);
        }
    }
}

/// <summary>
/// Application Health Check Implementation  
/// Monitors overall application health
/// </summary>
public class ApplicationHealthCheck : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    public Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        // Application-specific health checks
        var data = new Dictionary<string, object>
        {
            ["timestamp"] = DateTime.UtcNow,
            ["environment"] = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
            ["version"] = "1.0.0" // Versioning system kullanıyorsanız buradan alabilirsiniz
        };

        return Task.FromResult(
            Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy("Application is running normally", data));
    }
}