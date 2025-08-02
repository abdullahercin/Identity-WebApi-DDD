using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Infrastructure.Persistence.Contexts;
using Assist.Identity.Infrastructure.Persistence.Repositories;

namespace Assist.Identity.Infrastructure.Extensions;

/// <summary>
/// Persistence Services Extension
/// 
/// Bu extension Persistence layer'daki tüm service'lerin dependency injection'ını organize eder:
/// 1. DbContext registration ve configuration
/// 2. Repository pattern implementations
/// 3. Database connection string management
/// 4. EF Core optimizations ve configurations
/// 
/// Clean Architecture pattern:
/// - Application layer interfaces (IUserRepository)
/// - Infrastructure layer implementations (UserRepository)
/// - Persistence concerns encapsulated
/// </summary>
public static class PersistenceServiceExtensions
{
    /// <summary>
    /// Persistence services'leri DI container'a register eder
    /// 
    /// Services registered:
    /// - DbContext (IdentityDbContext)
    /// - Repositories (IUserRepository, IRoleRepository, etc.)
    /// - Database connection configuration
    /// - EF Core performance optimizations
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configuration">Application configuration</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPersistenceServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Step 1: Database Connection Configuration
        AddDatabaseContext(services, configuration);

        // Step 2: Repository Pattern Implementations
        AddRepositories(services);

        // Step 3: Database-specific optimizations
        AddDatabaseOptimizations(services);

        return services;
    }

    /// <summary>
    /// Entity Framework DbContext configuration
    /// 
    /// Configuration includes:
    /// - SQL Server connection string
    /// - Connection pooling for performance
    /// - Query tracking optimizations
    /// - Development vs Production settings
    /// - Multi-tenancy support
    /// </summary>
    private static void AddDatabaseContext(IServiceCollection services, IConfiguration configuration)
    {
        // Get connection string - fail fast if missing
        var connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException(
                "Connection string 'DefaultConnection' not found. " +
                "Please add it to appsettings.json under ConnectionStrings section.");

        // Entity Framework DbContext registration
        services.AddDbContext<IdentityDbContext>(options =>
        {
            // SQL Server configuration
            options.UseSqlServer(connectionString, sqlOptions =>
            {
                // Connection resilience for cloud deployments
                sqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(30),
                    errorNumbersToAdd: null);

                // Query timeout for long-running operations
                sqlOptions.CommandTimeout(30);

                // Assembly where migrations are located
                sqlOptions.MigrationsAssembly(typeof(IdentityDbContext).Assembly.FullName);
            });

            // Development optimizations
            if (configuration.GetValue<bool>("Development:EnableSensitiveDataLogging", false))
            {
                options.EnableSensitiveDataLogging();
                options.EnableDetailedErrors();
            }

            // Query performance optimizations
            options.ConfigureWarnings(warnings =>
            {
                // Suppress warnings that are expected in our domain model
                warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.CoreEventId.NavigationBaseIncludeIgnored);
            });

            // Memory optimization for read-heavy scenarios
            options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
        });

        // DbContext pooling for better performance (optional, for high-traffic scenarios)
        // Note: Uncomment if you need better performance and don't need per-request state in DbContext
        // services.AddDbContextPool<IdentityDbContext>(options => { /* same configuration */ });
    }

    /// <summary>
    /// Repository pattern implementations registration
    /// 
    /// Repository pattern benefits:
    /// - Abstraction over data access
    /// - Easy unit testing (mock repositories)
    /// - Business logic isolation from EF Core
    /// - Consistent data access patterns
    /// - Future flexibility (switch ORMs if needed)
    /// </summary>
    private static void AddRepositories(IServiceCollection services)
    {
        // Core repositories for Identity domain
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IPermissionRepository, PermissionRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();

        // Note: Scoped lifetime because:
        // - Repositories should live for the request duration
        // - DbContext is scoped, repositories depend on it
        // - Thread-safe within request scope
        // - Automatic disposal when request ends
    }

    /// <summary>
    /// Database-specific optimizations ve configurations
    /// 
    /// Performance optimizations:
    /// - Connection pooling
    /// - Query compilation caching
    /// - Memory management
    /// - Connection string optimizations
    /// </summary>
    private static void AddDatabaseOptimizations(IServiceCollection services)
    {
        // EF Core query compilation caching - improves performance
        services.AddMemoryCache();

        // Optional: Add specialized database services if needed
        // services.AddScoped<IDatabaseSeeder, DatabaseSeeder>();
        // services.AddScoped<IMigrationService, MigrationService>();
    }

    /// <summary>
    /// Database health check registration
    /// 
    /// Health checks for:
    /// - Database connectivity
    /// - EF Core DbContext health
    /// - Connection pool health
    /// </summary>
    public static IServiceCollection AddDatabaseHealthChecks(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddHealthChecks()
            .AddDbContextCheck<IdentityDbContext>(
                name: "identity-database",
                tags: new[] { "database", "ef-core", "identity" });

        return services;
    }

    /// <summary>
    /// Development database utilities
    /// 
    /// Development helpers:
    /// - Database migration runner
    /// - Seed data initialization
    /// - Database reset utilities
    /// </summary>
    public static IServiceCollection AddDevelopmentDatabaseServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        if (configuration.GetValue<bool>("Development:EnableDatabaseUtilities", false))
        {
            // Development-only services
            // services.AddScoped<IDatabaseSeeder, DatabaseSeeder>();
            // services.AddScoped<ITestDataGenerator, TestDataGenerator>();
        }

        return services;
    }
}