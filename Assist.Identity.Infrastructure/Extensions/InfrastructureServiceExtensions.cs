using Assist.Identity.Application.Contracts;
using Assist.Identity.Infrastructure.Persistence.Contexts;
using Assist.Identity.Infrastructure.Persistence.Repositories;
using Assist.Identity.Infrastructure.Services.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Assist.Identity.Infrastructure.Extensions;

public static class InfrastructureServiceExtensions
{
    /// <summary>
    /// Infrastructure Layer services registration
    /// Clean Architecture: Infrastructure implementations
    /// </summary>
    public static IServiceCollection AddInfrastructureServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Database Context
        services.AddDbContext<IdentityDbContext>(options =>
            options.UseSqlServer(
                configuration.GetConnectionString("DefaultConnection"),
                b => b.MigrationsAssembly("Assist.Identity.Infrastructure")));

        // Repositories - Interface Application'da, Implementation Infrastructure'da
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();

        // Infrastructure Services
        services.AddScoped<ITokenService, JwtTokenService>();

        // TODO: Implement these services
        // services.AddScoped<ICacheService, MemoryCacheService>();
        // services.AddScoped<IEmailService, SmtpEmailService>();
        // services.AddScoped<IPasswordHashingService, BCryptPasswordHashingService>();
        // services.AddScoped<ICurrentTenantService, HttpContextTenantService>();
        // services.AddScoped<ICurrentUserService, HttpContextUserService>();

        // JWT Authentication
        services.AddJwtAuthentication(configuration);

        return services;
    }

    /// <summary>
    /// JWT Authentication configuration
    /// </summary>
    private static IServiceCollection AddJwtAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // JWT configuration logic (same as before)
        var jwtSettings = configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"];

        if (string.IsNullOrWhiteSpace(secretKey))
        {
            throw new InvalidOperationException("JWT SecretKey is not configured");
        }

        // JWT Bearer configuration...
        // (Previous JWT configuration code here)

        return services;
    }
}