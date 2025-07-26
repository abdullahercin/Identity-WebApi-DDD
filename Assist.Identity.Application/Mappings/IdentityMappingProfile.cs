// IdentityMappingProfile.cs - AutoMapper configuration for Identity domain
namespace Assist.Identity.Application.Mappings;

using AutoMapper;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Domain.ValueObjects;
using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;
using Assist.Identity.Application.Models;

/// <summary>
/// Identity Mapping Profile
/// Domain entities ↔ DTOs arasındaki mapping configuration'ları
/// AutoMapper convention'larını ve custom mappings'leri tanımlar
/// </summary>
public class IdentityMappingProfile : Profile
{
    public IdentityMappingProfile()
    {
        // User mappings
        ConfigureUserMappings();

        // Role mappings
        ConfigureRoleMappings();

        // Permission mappings (future)
        ConfigurePermissionMappings();

        // Value Object mappings
        ConfigureValueObjectMappings();

        // Collection mappings
        ConfigureCollectionMappings();
    }

    #region User Mappings

    /// <summary>
    /// User entity ↔ DTOs mapping configuration
    /// </summary>
    private void ConfigureUserMappings()
    {
        // User → UserResponse (Main mapping)
        CreateMap<User, UserResponse>()
            .ForMember(dest => dest.Email,
                       opt => opt.MapFrom(src => src.Email.Value))
            .ForMember(dest => dest.PhoneNumber,
                       opt => opt.MapFrom(src => src.PhoneNumber != null ? src.PhoneNumber.Value : null))
            .ForMember(dest => dest.FullName,
                       opt => opt.MapFrom(src => $"{src.FirstName} {src.LastName}"))
            .ForMember(dest => dest.DisplayName,
                       opt => opt.MapFrom(src => !string.IsNullOrEmpty(src.FirstName)
                                                ? $"{src.FirstName} {src.LastName}"
                                                : src.Email.Value))
            .ForMember(dest => dest.Roles,
                       opt => opt.MapFrom(src => src.UserRoles
                           .Where(ur => ur.Role.IsActive)
                           .Select(ur => ur.Role.Name)
                           .ToList()))
            .ForMember(dest => dest.Permissions,
                       opt => opt.MapFrom(src => src.UserRoles
                           .Where(ur => ur.Role.IsActive)
                           .SelectMany(ur => ur.Role.RolePermissions)
                           .Select(rp => rp.Permission.Name)
                           .Distinct()
                           .ToList()))
            .AfterMap((src, dest) =>
            {
                // Additional computed properties
                dest.TenantId = src.TenantId;
            });

        // RegisterRequest → User (Factory method kullanımı için nadiren, ama completeness için)
        CreateMap<RegisterRequest, User>()
            .ConstructUsing(src => User.Create(
                src.Email,
                src.Password,
                src.FirstName,
                src.LastName,
                src.PhoneNumber))
            .ForAllMembers(opt => opt.Ignore()); // Constructor'da handle edildiği için ignore

        // UpdateUserRequest için partial mapping (manual mapping tercih edilir)
        CreateMap<UpdateUserRequest, User>()
            .ForAllMembers(opt => opt.Ignore()); // Manual update logic tercih edilir
    }

    #endregion

    #region Role Mappings

    /// <summary>
    /// Role entity ↔ DTOs mapping configuration
    /// </summary>
    private void ConfigureRoleMappings()
    {
        // Role → RoleResponse
        CreateMap<Role, RoleResponse>()
            .ForMember(dest => dest.Permissions,
                       opt => opt.MapFrom(src => src.RolePermissions
                           .Select(rp => rp.Permission.Name)
                           .ToList()))
            .ForMember(dest => dest.UserCount,
                       opt => opt.MapFrom(src => src.UserRoles.Count(ur => ur.User.IsActive)))
            .AfterMap((src, dest) =>
            {
                // Additional business logic
                dest.CreatedAt = src.CreatedAt;
            });

        // CreateRoleRequest → Role
        CreateMap<CreateRoleRequest, Role>()
            .ConstructUsing(src => Role.Create(src.Name, src.Description))
            .ForAllMembers(opt => opt.Ignore());
    }

    #endregion

    #region Permission Mappings

    /// <summary>
    /// Permission entity ↔ DTOs mapping configuration
    /// Future implementation için placeholder
    /// </summary>
    private void ConfigurePermissionMappings()
    {
        // Permission → PermissionResponse (future)
        CreateMap<Permission, object>()
            .ForAllMembers(opt => opt.Ignore());
    }

    #endregion

    #region Value Object Mappings

    /// <summary>
    /// Value Objects ↔ Primitive types mapping
    /// </summary>
    private void ConfigureValueObjectMappings()
    {
        // Email Value Object → string
        CreateMap<Email, string>()
            .ConstructUsing(src => src.Value);

        // string → Email Value Object
        CreateMap<string, Email>()
            .ConstructUsing(src => Email.Create(src));

        // PhoneNumber Value Object → string
        CreateMap<PhoneNumber, string>()
            .ConstructUsing(src => src != null ? src.Value : null);

        // string → PhoneNumber Value Object
        CreateMap<string, PhoneNumber>()
            .ConstructUsing(src => !string.IsNullOrEmpty(src) ? PhoneNumber.Create(src) : null);

        // Password Value Object → string (sadece hashed value, güvenlik için)
        CreateMap<Password, string>()
            .ConstructUsing(src => "[PROTECTED]"); // Asla expose etme

        // RefreshToken → session info için helper mappings
        CreateMap<RefreshToken, UserSession>()
            .ForMember(dest => dest.SessionId, opt => opt.MapFrom(src => src.Id.ToString()))
            .ForMember(dest => dest.StartedAt, opt => opt.MapFrom(src => src.CreatedAt))
            .ForMember(dest => dest.ExpiresAt, opt => opt.MapFrom(src => src.ExpiresAt))
            .ForMember(dest => dest.IsCurrentSession, opt => opt.Ignore()) // Context'e göre set edilir
            .ForMember(dest => dest.LastActivity, opt => opt.MapFrom(src => src.CreatedAt))
            .ForMember(dest => dest.IpAddress, opt => opt.Ignore()) // Stored separately
            .ForMember(dest => dest.UserAgent, opt => opt.Ignore()) // Stored separately
            .ForMember(dest => dest.DeviceInfo, opt => opt.Ignore()); // Computed from UserAgent
    }

    #endregion

    #region Collection Mappings

    /// <summary>
    /// Collection ve pagination mappings
    /// </summary>
    private void ConfigureCollectionMappings()
    {
        // PagedResult<User> → PagedResult<UserResponse>
        CreateMap<PagedResult<User>, PagedResult<UserResponse>>()
            .ForMember(dest => dest.Items,
                       opt => opt.MapFrom(src => src.Items));

        // PagedResult<Role> → PagedResult<RoleResponse>
        CreateMap<PagedResult<Role>, PagedResult<RoleResponse>>()
            .ForMember(dest => dest.Items,
                       opt => opt.MapFrom(src => src.Items));

        // Generic PagedResult mapping
        CreateMap(typeof(PagedResult<>), typeof(PagedResult<>))
            .ForMember("Items", opt => opt.MapFrom("Items"));
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Custom value resolver for complex scenarios
    /// </summary>
    public class UserPermissionsResolver : IValueResolver<User, UserResponse, List<string>>
    {
        public List<string> Resolve(User source, UserResponse destination, List<string> destMember, ResolutionContext context)
        {
            return source.UserRoles
                .Where(ur => ur.Role.IsActive)
                .SelectMany(ur => ur.Role.RolePermissions)
                .Select(rp => rp.Permission.Name)
                .Distinct()
                .OrderBy(p => p)
                .ToList();
        }
    }

    /// <summary>
    /// Custom value resolver for role names
    /// </summary>
    public class UserRolesResolver : IValueResolver<User, UserResponse, List<string>>
    {
        public List<string> Resolve(User source, UserResponse destination, List<string> destMember, ResolutionContext context)
        {
            return source.UserRoles
                .Where(ur => ur.Role.IsActive)
                .Select(ur => ur.Role.Name)
                .OrderBy(r => r)
                .ToList();
        }
    }

    /// <summary>
    /// Custom type converter for safe Email mapping
    /// </summary>
    public class SafeEmailConverter : ITypeConverter<Email, string>
    {
        public string Convert(Email source, string destination, ResolutionContext context)
        {
            return source?.Value ?? string.Empty;
        }
    }

    /// <summary>
    /// Custom type converter for safe PhoneNumber mapping
    /// </summary>
    public class SafePhoneNumberConverter : ITypeConverter<PhoneNumber, string>
    {
        public string Convert(PhoneNumber source, string destination, ResolutionContext context)
        {
            return source?.Value ?? string.Empty;
        }
    }

    #endregion

    #region Advanced Mappings

    /// <summary>
    /// Advanced mapping scenarios
    /// </summary>
    private void ConfigureAdvancedMappings()
    {
        // UserStatistics için custom mapping
        CreateMap<User, UserStatistics>()
            .ForAllMembers(opt => opt.Ignore()); // Statistics computed separately

        // Session info mapping with context
        CreateMap<User, UserSession>()
            .ForMember(dest => dest.SessionId, opt => opt.Ignore()) // Generated separately
            .ForMember(dest => dest.StartedAt, opt => opt.MapFrom(src => src.LastLoginAt ?? src.CreatedAt))
            .ForMember(dest => dest.ExpiresAt, opt => opt.Ignore()) // Computed from token
            .ForMember(dest => dest.IsCurrentSession, opt => opt.Ignore()) // Context-dependent
            .ForMember(dest => dest.LastActivity, opt => opt.MapFrom(src => src.LastLoginAt ?? src.CreatedAt));

        // Conditional mappings
        CreateMap<User, UserResponse>()
            .ForMember(dest => dest.PhoneNumber, opt => opt.Condition(src => src.PhoneNumber != null))
            .ForMember(dest => dest.LastLoginAt, opt => opt.Condition(src => src.LastLoginAt.HasValue));
    }

    #endregion

    #region Validation and Error Handling

    /// <summary>
    /// Mapping validation ve error handling
    /// </summary>
    private void ConfigureMappingValidation()
    {
        // Value object creation error handling
        CreateMap<string, Email>()
            .ConstructUsing((src, context) =>
            {
                try
                {
                    return Email.Create(src);
                }
                catch
                {
                    // Log error, return null or default
                    return null;
                }
            });

        CreateMap<string, PhoneNumber>()
            .ConstructUsing((src, context) =>
            {
                try
                {
                    return !string.IsNullOrEmpty(src) ? PhoneNumber.Create(src) : null;
                }
                catch
                {
                    // Log error, return null
                    return null;
                }
            });
    }

    #endregion

    #region Performance Optimizations

    /// <summary>
    /// Performance optimization için mapping configuration'ları
    /// </summary>
    private void ConfigurePerformanceOptimizations()
    {
        // Lazy loading prevention
        CreateMap<User, UserResponse>()
            .ForMember(dest => dest.Roles, opt => opt.ExplicitExpansion())
            .ForMember(dest => dest.Permissions, opt => opt.ExplicitExpansion());

        // Projection için optimize edilmiş mapping
        CreateMap<User, UserResponse>()
            .ForMember(dest => dest.FullName, opt => opt.MapFrom(src => src.FirstName + " " + src.LastName))
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email.Value));
    }

    #endregion
}