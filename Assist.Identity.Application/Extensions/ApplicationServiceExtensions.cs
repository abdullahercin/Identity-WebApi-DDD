using Microsoft.Extensions.DependencyInjection;
using Assist.Identity.Application.Abstractions;
using Assist.Identity.Application.Services;
using Assist.Identity.Application.Mappings;

namespace Assist.Identity.Application.Extensions;

public static class ApplicationServiceExtensions
{
    /// <summary>
    /// Application Layer services registration
    /// Clean Architecture: Sadece Application Layer dependencies
    /// </summary>
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        // AutoMapper - Application layer DTO mapping
        services.AddAutoMapper(cfg => {
            cfg.AddProfile<IdentityMappingProfile>();
        }, typeof(IdentityMappingProfile).Assembly);

        // Application Services
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<IRoleService, RoleService>();

        return services;
    }
}
