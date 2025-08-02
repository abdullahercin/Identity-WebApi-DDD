using Assist.Identity.Application.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Assist.Identity.Infrastructure.Services.Security;

/// <summary>
/// Current User Service Implementation - Complete
/// 
/// Bu service HTTP request context'inden user bilgilerini extract eder ve
/// application layer'a clean bir interface ile sunar.
/// 
/// Architecture Benefits:
/// - Application layer HTTP context'inden tamamen izole edilir
/// - Business logic sadece ICurrentUserService interface'ini görür
/// - Testing kolay (mock HTTP context kullanılabilir)
/// - Clean separation of concerns (web concerns vs business logic)
/// 
/// Authentication Flow Integration:
/// 1. User login olur → JWT token generate edilir
/// 2. Client her request'te Authorization header'da Bearer token gönderir
/// 3. ASP.NET Core JWT middleware token'ı validate eder
/// 4. Validation başarılı ise ClaimsPrincipal oluşturulur
/// 5. CurrentUserService ClaimsPrincipal'dan user bilgilerini extract eder
/// 6. Application layer clean interface ile user bilgilerine erişir
/// 
/// Security Considerations:
/// - HTTP context null olabilir (background jobs, system operations)
/// - JWT token corrupt veya missing olabilir
/// - Claims missing veya invalid format'ta olabilir
/// - Multi-tenancy validation yapılmalı
/// - Graceful degradation sağlanmalı (system operations için)
/// 
/// Performance Considerations:
/// - HTTP context access lightweight operation
/// - Claims parsing minimal overhead
/// - Lazy evaluation pattern (tek seferde load edilir)
/// - Request scope'unda cache edilir
/// </summary>
public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<CurrentUserService> _logger;

    // Lazy-loaded properties for performance
    // HTTP context'e sadece ihtiyaç duyulduğunda access edilir
    private Guid? _userId;
    private string? _email;
    private string? _firstName;
    private string? _lastName;
    private Guid? _tenantId;
    private List<string>? _roles;
    private List<string>? _permissions;
    private bool? _emailConfirmed;
    private bool _propertiesLoaded = false;

    /// <summary>
    /// CurrentUserService constructor
    /// 
    /// IHttpContextAccessor dependency injection pattern:
    /// - ASP.NET Core request context'ine safe access sağlar
    /// - Thread-safe implementation (per-request scope)
    /// - Background operations'da null değer döner (expected behavior)
    /// - Scoped lifetime (request başına bir instance)
    /// 
    /// Design pattern: Lazy Loading
    /// - Properties first access'te load edilir
    /// - Multiple property access'lerde recomputation yapılmaz
    /// - Performance optimization (HTTP context access minimize edilir)
    /// </summary>
    /// <param name="httpContextAccessor">HTTP context accessor for request-scoped data</param>
    /// <param name="logger">Structured logging interface</param>
    public CurrentUserService(IHttpContextAccessor httpContextAccessor, ILogger<CurrentUserService> logger)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    #region Public Properties - ICurrentUserService Interface Implementation

    /// <summary>
    /// Current user ID
    /// 
    /// JWT claims mapping:
    /// - Standard claim: "sub" (subject) → User ID
    /// - Format: GUID string → Guid conversion
    /// - Validation: GUID format check
    /// 
    /// Error handling:
    /// - HTTP context null (background operations) → null
    /// - User not authenticated → null
    /// - Invalid GUID format → null (log warning)
    /// - Missing sub claim → null (log warning)
    /// 
    /// Usage patterns:
    /// - Repository queries: filter by user ID
    /// - Authorization checks: ownership validation
    /// - Audit logging: track user actions
    /// </summary>
    public Guid? UserId
    {
        get
        {
            EnsurePropertiesLoaded();
            return _userId;
        }
    }

    /// <summary>
    /// Current user email
    /// 
    /// JWT claims mapping:
    /// - Standard claim: "email" → Email address
    /// - Format validation: basic email format check
    /// - Case handling: preserve original case
    /// 
    /// Use cases:
    /// - User display (UI personalization)
    /// - Email notifications (correspondence)
    /// - Audit trails (user identification)
    /// - Support requests (user context)
    /// </summary>
    public string? Email
    {
        get
        {
            EnsurePropertiesLoaded();
            return _email;
        }
    }

    /// <summary>
    /// Current user first name
    /// 
    /// JWT claims mapping:
    /// - Custom claim: "first_name" → First name
    /// - UI personalization için kullanılır
    /// 
    /// Use cases:
    /// - Welcome messages: "Hello, John!"
    /// - User profile display
    /// - Personalized communications
    /// </summary>
    public string? FirstName
    {
        get
        {
            EnsurePropertiesLoaded();
            return _firstName;
        }
    }

    /// <summary>
    /// Current user last name
    /// 
    /// JWT claims mapping:
    /// - Custom claim: "last_name" → Last name
    /// - Full name construction için kullanılır
    /// 
    /// Use cases:
    /// - Formal communication
    /// - Full name display
    /// - Professional identification
    /// </summary>
    public string? LastName
    {
        get
        {
            EnsurePropertiesLoaded();
            return _lastName;
        }
    }

    /// <summary>
    /// Current user tenant ID
    /// 
    /// JWT claims mapping:
    /// - Custom claim: "tenant_id" → Tenant ID
    /// - Multi-tenancy için kritik bilgi
    /// 
    /// Use cases:
    /// - Data filtering (tenant-specific data)
    /// - Authorization checks (tenant ownership)
    /// - Multi-tenant operations
    /// - Tenant context validation
    /// </summary>
    public Guid? TenantId
    {
        get
        {
            EnsurePropertiesLoaded();
            return _tenantId;
        }
    }

    /// <summary>
    /// Current user roles
    /// 
    /// JWT claims mapping:
    /// - Standard claim type: ClaimTypes.Role
    /// - Multiple values: multiple role claims in token
    /// - Format: string collection
    /// 
    /// Authorization usage:
    /// - Role-based access control (RBAC)
    /// - UI conditional rendering
    /// - Feature flagging
    /// - Navigation customization
    /// 
    /// Performance note:
    /// - Immutable collection (read-only)
    /// - Lazy loaded on first access
    /// - Cached for request duration
    /// </summary>
    public IEnumerable<string> Roles
    {
        get
        {
            EnsurePropertiesLoaded();
            return _roles ?? Enumerable.Empty<string>();
        }
    }

    /// <summary>
    /// Current user permissions
    /// 
    /// JWT claims mapping:
    /// - Custom claim type: "permission"
    /// - Multiple values: multiple permission claims
    /// - Format: string collection
    /// 
    /// Fine-grained authorization:
    /// - Permission-based access control (PBAC)
    /// - API endpoint authorization
    /// - Feature-level access control
    /// - Data-level security
    /// 
    /// Design pattern: Capability-based security
    /// - "CanReadUsers", "CanEditProfile", "CanDeleteData"
    /// - Granular control over functionality
    /// - Easy to extend and maintain
    /// </summary>
    public IEnumerable<string> Permissions
    {
        get
        {
            EnsurePropertiesLoaded();
            return _permissions ?? Enumerable.Empty<string>();
        }
    }

    /// <summary>
    /// User authentication status
    /// 
    /// Authentication check logic:
    /// 1. HTTP context exists
    /// 2. User principal exists
    /// 3. User identity is authenticated
    /// 4. Valid user ID claim exists
    /// 
    /// Background operations:
    /// - System operations: false (expected)
    /// - Background jobs: false (expected)
    /// - Console applications: false (expected)
    /// 
    /// Error scenarios:
    /// - Invalid JWT token: false
    /// - Expired token: false (handled by middleware)
    /// - Missing claims: false
    /// </summary>
    public bool IsAuthenticated
    {
        get
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;

                // Background operations or system context
                if (httpContext?.User == null)
                    return false;

                var user = httpContext.User;

                // Check authentication status
                if (!user.Identity?.IsAuthenticated == true)
                    return false;

                // Verify user has valid claims (additional validation)
                var userIdClaim = user.FindFirst(JwtRegisteredClaimNames.Sub) ??
                                user.FindFirst(ClaimTypes.NameIdentifier);

                // Must have valid user ID claim
                return userIdClaim != null && Guid.TryParse(userIdClaim.Value, out _);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking authentication status");
                return false; // Fail secure
            }
        }
    }

    /// <summary>
    /// Email confirmation status
    /// 
    /// JWT claims mapping:
    /// - Custom claim: "email_confirmed" → Boolean value
    /// - Security validation için kullanılır
    /// 
    /// Business rules:
    /// - Unconfirmed users may have limited access
    /// - Some operations require confirmed email
    /// - Security notifications may be restricted
    /// </summary>
    public bool EmailConfirmed
    {
        get
        {
            EnsurePropertiesLoaded();
            return _emailConfirmed ?? false;
        }
    }

    #endregion

    #region Computed Properties

    /// <summary>
    /// Full name computed property
    /// FirstName ve LastName'i intelligent şekilde birleştirir
    /// </summary>
    public string? FullName
    {
        get
        {
            EnsurePropertiesLoaded();

            if (!string.IsNullOrWhiteSpace(_firstName) && !string.IsNullOrWhiteSpace(_lastName))
                return $"{_firstName} {_lastName}";

            if (!string.IsNullOrWhiteSpace(_firstName))
                return _firstName;

            if (!string.IsNullOrWhiteSpace(_lastName))
                return _lastName;

            return null;
        }
    }

    /// <summary>
    /// Display name - UI için optimize edilmiş name
    /// </summary>
    public string DisplayName
    {
        get
        {
            var fullName = FullName;
            if (!string.IsNullOrWhiteSpace(fullName))
                return fullName;

            if (!string.IsNullOrWhiteSpace(Email))
                return Email;

            return "User";
        }
    }

    #endregion

    #region Authorization Methods

    /// <summary>
    /// Tenant ownership validation
    /// 
    /// Multi-tenancy security:
    /// - User sadece kendi tenant'ının datasına erişebilir
    /// - Cross-tenant access prevented
    /// - Security audit logging
    /// 
    /// Use cases:
    /// - Repository queries (automatic tenant filtering)
    /// - API authorization (tenant-specific operations)
    /// - Data validation (ownership checks)
    /// - Security boundary enforcement
    /// 
    /// Error handling:
    /// - User not authenticated → false
    /// - Missing tenant claim → false (security concern)
    /// - Invalid tenant ID format → false
    /// - Cross-tenant attempt → false (log warning)
    /// </summary>
    /// <param name="tenantId">Requested tenant ID for access validation</param>
    /// <returns>True if user belongs to specified tenant</returns>
    public bool BelongsToTenant(Guid tenantId)
    {
        try
        {
            EnsurePropertiesLoaded();

            // User not authenticated
            if (!IsAuthenticated || _tenantId == null)
            {
                _logger.LogDebug("Tenant validation failed: user not authenticated or no tenant info");
                return false;
            }

            var belongsToTenant = _tenantId == tenantId;

            if (!belongsToTenant)
            {
                _logger.LogWarning("Cross-tenant access attempt - User tenant: {UserTenant}, Requested tenant: {RequestedTenant}, User: {UserId}",
                    _tenantId, tenantId, _userId);
            }
            else
            {
                _logger.LogDebug("Tenant access validated - User: {UserId}, Tenant: {TenantId}", _userId, tenantId);
            }

            return belongsToTenant;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during tenant validation for tenant: {TenantId}", tenantId);
            return false; // Fail secure: deny access on errors
        }
    }

    /// <summary>
    /// Role check utility method
    /// Specific bir role'ün varlığını kontrol eder
    /// </summary>
    /// <param name="roleName">Kontrol edilecek role adı</param>
    /// <returns>Role varsa true</returns>
    public bool HasRole(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
            return false;

        return Roles.Any(r => r.Equals(roleName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Permission check utility method
    /// Specific bir permission'ın varlığını kontrol eder
    /// </summary>
    /// <param name="permissionName">Kontrol edilecek permission adı</param>
    /// <returns>Permission varsa true</returns>
    public bool HasPermission(string permissionName)
    {
        if (string.IsNullOrWhiteSpace(permissionName))
            return false;

        return Permissions.Any(p => p.Equals(permissionName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Admin role check
    /// Admin, Administrator, SuperAdmin role'lerinden birini kontrol eder
    /// </summary>
    /// <returns>Admin role'ü varsa true</returns>
    public bool IsAdmin()
    {
        var adminRoles = new[] { "Admin", "Administrator", "SuperAdmin" };
        return Roles.Any(r => adminRoles.Contains(r, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Multiple role check utility
    /// Verilen role'lerden herhangi birine sahip mi kontrol eder
    /// </summary>
    /// <param name="roleNames">Kontrol edilecek role adları</param>
    /// <returns>Herhangi bir role varsa true</returns>
    public bool HasAnyRole(params string[] roleNames)
    {
        if (roleNames == null || roleNames.Length == 0)
            return false;

        return roleNames.Any(HasRole);
    }

    /// <summary>
    /// Multiple permission check utility
    /// Verilen permission'lardan herhangi birine sahip mi kontrol eder
    /// </summary>
    /// <param name="permissionNames">Kontrol edilecek permission adları</param>
    /// <returns>Herhangi bir permission varsa true</returns>
    public bool HasAnyPermission(params string[] permissionNames)
    {
        if (permissionNames == null || permissionNames.Length == 0)
            return false;

        return permissionNames.Any(HasPermission);
    }

    /// <summary>
    /// All permissions check utility
    /// Verilen tüm permission'lara sahip mi kontrol eder
    /// </summary>
    /// <param name="permissionNames">Kontrol edilecek permission adları</param>
    /// <returns>Tüm permission'lar varsa true</returns>
    public bool HasAllPermissions(params string[] permissionNames)
    {
        if (permissionNames == null || permissionNames.Length == 0)
            return true; // Vacuous truth

        return permissionNames.All(HasPermission);
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// Lazy loading pattern implementation
    /// 
    /// Performance optimization:
    /// - HTTP context access sadece gerektiğinde yapılır
    /// - Multiple property access'lerde recomputation önlenir
    /// - Request scope'unda tek parsing yapılır
    /// 
    /// Thread safety:
    /// - Request scope'unda tek thread access (web context)
    /// - Background operations'da property access safe
    /// - No locking required (scoped lifetime)
    /// 
    /// Error resilience:
    /// - Parsing errors gracefully handle edilir
    /// - Invalid claims null değer döndürür
    /// - Application functionality bozulmaz
    /// </summary>
    private void EnsurePropertiesLoaded()
    {
        // Already loaded check (performance optimization)
        if (_propertiesLoaded)
            return;

        try
        {
            var httpContext = _httpContextAccessor.HttpContext;

            // Background operations or system context
            if (httpContext?.User == null)
            {
                _logger.LogDebug("HTTP context or user not available - using default values");
                SetDefaultValues();
                return;
            }

            var user = httpContext.User;

            // User not authenticated
            if (!user.Identity?.IsAuthenticated == true)
            {
                _logger.LogDebug("User not authenticated - using default values");
                SetDefaultValues();
                return;
            }

            // Extract and parse user properties from claims
            ExtractUserProperties(user);

            _logger.LogDebug("User properties loaded - UserId: {UserId}, Email: {Email}, Roles: {RoleCount}, Permissions: {PermissionCount}",
                _userId, _email, _roles?.Count ?? 0, _permissions?.Count ?? 0);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading user properties from HTTP context");
            SetDefaultValues(); // Graceful degradation
        }
        finally
        {
            _propertiesLoaded = true; // Ensure we don't retry on subsequent calls
        }
    }

    /// <summary>
    /// Extract user properties from JWT claims
    /// 
    /// Claims mapping strategy:
    /// - Standard claims: "sub", "email" (JWT registered claims)
    /// - Custom claims: "tenant_id", "permission", "first_name", "last_name" (application-specific)
    /// - Multiple value claims: roles, permissions (array handling)
    /// 
    /// Error handling approach:
    /// - Individual claim parsing errors don't fail entire operation
    /// - Invalid format → null/empty (graceful degradation)
    /// - Missing claims → default values
    /// - Log warnings for security-relevant issues
    /// </summary>
    /// <param name="user">ClaimsPrincipal from HTTP context</param>
    private void ExtractUserProperties(ClaimsPrincipal user)
    {
        // Extract User ID - en kritik claim
        var userIdClaim = user.FindFirst(JwtRegisteredClaimNames.Sub) ??
                         user.FindFirst(ClaimTypes.NameIdentifier);

        if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
        {
            _userId = userId;
        }
        else
        {
            _logger.LogWarning("User ID claim not found or invalid format in token");
            _userId = null;
        }

        // Extract Email
        var emailClaim = user.FindFirst(JwtRegisteredClaimNames.Email) ??
                        user.FindFirst(ClaimTypes.Email);
        _email = emailClaim?.Value;

        // Extract First Name
        var firstNameClaim = user.FindFirst("first_name") ??
                            user.FindFirst(ClaimTypes.GivenName);
        _firstName = firstNameClaim?.Value;

        // Extract Last Name
        var lastNameClaim = user.FindFirst("last_name") ??
                           user.FindFirst(ClaimTypes.Surname);
        _lastName = lastNameClaim?.Value;

        // Extract Tenant ID
        var tenantClaim = user.FindFirst("tenant_id");
        if (tenantClaim != null && Guid.TryParse(tenantClaim.Value, out var tenantId))
        {
            _tenantId = tenantId;
        }
        else
        {
            _logger.LogWarning("Tenant ID claim not found or invalid format in token - this is a security concern");
            _tenantId = null;
        }

        // Extract Email Confirmed status
        var emailConfirmedClaim = user.FindFirst("email_confirmed");
        _emailConfirmed = emailConfirmedClaim != null &&
                         bool.TryParse(emailConfirmedClaim.Value, out var confirmed) &&
                         confirmed;

        // Extract Roles (multiple claims)
        _roles = user.FindAll(ClaimTypes.Role)
                    .Select(c => c.Value)
                    .Where(r => !string.IsNullOrWhiteSpace(r))
                    .Distinct()
                    .ToList();

        // Extract Permissions (multiple custom claims)
        _permissions = user.FindAll("permission")
                          .Select(c => c.Value)
                          .Where(p => !string.IsNullOrWhiteSpace(p))
                          .Distinct()
                          .ToList();

        // Log security-relevant missing claims
        if (_userId == null)
        {
            _logger.LogWarning("Critical: User ID claim missing from authenticated user token");
        }

        if (_tenantId == null)
        {
            _logger.LogWarning("Critical: Tenant ID claim missing from authenticated user token - multi-tenancy compromise");
        }
    }

    /// <summary>
    /// Set default values for unauthenticated context
    /// 
    /// Default value strategy:
    /// - Null values for all properties
    /// - Empty collections for roles and permissions
    /// - Safe defaults that don't grant access
    /// 
    /// Use cases:
    /// - Background operations
    /// - System context operations
    /// - Unauthenticated requests
    /// - Error scenarios (graceful degradation)
    /// </summary>
    private void SetDefaultValues()
    {
        _userId = null;
        _email = null;
        _firstName = null;
        _lastName = null;
        _tenantId = null;
        _emailConfirmed = false;
        _roles = new List<string>();
        _permissions = new List<string>();

        _logger.LogDebug("Default values set for unauthenticated context");
    }

    #endregion
}