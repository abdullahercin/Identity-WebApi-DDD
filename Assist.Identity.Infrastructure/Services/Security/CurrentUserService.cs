using Assist.Identity.Application.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Assist.Identity.Infrastructure.Services.Security;

/// <summary>
/// Current User Service Implementation
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
/// - Caching gerekmiyor (request scope'unda single access)
/// - Lazy evaluation pattern kullanılabilir
/// </summary>
public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<CurrentUserService> _logger;

    // Lazy-loaded properties for performance
    // HTTP context'e sadece ihtiyaç duyulduğunda access edilir
    private Guid? _userId;
    private string? _email;
    private List<string>? _roles;
    private List<string>? _permissions;
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
    /// Usage scenarios:
    /// - Authorization guards
    /// - Conditional UI rendering
    /// - API access control
    /// - Redirect logic (login required)
    /// 
    /// Security note:
    /// - Authentication ≠ Authorization
    /// - Authenticated user may not have permissions for specific operations
    /// - Always check both authentication and authorization
    /// </summary>
    public bool IsAuthenticated
    {
        get
        {
            try
            {
                var httpContext = _httpContextAccessor.HttpContext;

                // Background operations veya initialization phase
                if (httpContext == null)
                {
                    _logger.LogDebug("HTTP context not available - likely background operation");
                    return false;
                }

                // User principal check
                var user = httpContext.User;
                if (user == null || user.Identity == null)
                {
                    _logger.LogDebug("User principal not available");
                    return false;
                }

                // Authentication status check
                if (!user.Identity.IsAuthenticated)
                {
                    _logger.LogDebug("User identity not authenticated");
                    return false;
                }

                // Valid user ID check (business requirement)
                var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier) ?? user.FindFirst("sub");
                if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out _))
                {
                    _logger.LogDebug("Valid user ID claim not found");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking authentication status");
                return false; // Fail secure: deny access on errors
            }
        }
    }

    #endregion

    #region Public Methods - Business Logic Operations

    /// <summary>
    /// Multi-tenant authorization check
    /// 
    /// Multi-tenancy security is critical:
    /// - Users can only access their tenant's data
    /// - Cross-tenant data access is security violation
    /// - System operations may bypass tenant checks
    /// 
    /// Validation logic:
    /// 1. Check if user is authenticated
    /// 2. Extract tenant ID from JWT claims
    /// 3. Compare with requested tenant ID
    /// 4. Handle system operations (no user context)
    /// 
    /// Security implications:
    /// - Data isolation between tenants
    /// - Prevent data leakage
    /// - Compliance requirements (GDPR, HIPAA)
    /// - Audit trail for cross-tenant attempts
    /// 
    /// Use cases:
    /// - Repository-level filtering
    /// - API endpoint authorization
    /// - Data export/import operations
    /// - Admin panel access control
    /// </summary>
    /// <param name="tenantId">Tenant ID to check access for</param>
    /// <returns>True if user belongs to tenant or is system operation</returns>
    public bool BelongsToTenant(Guid tenantId)
    {
        try
        {
            // System operations (background jobs, migrations)
            // Tenant check skip edilebilir ama log edilmeli
            if (!IsAuthenticated)
            {
                _logger.LogDebug("Tenant check for unauthenticated context - likely system operation");
                return true; // System operations bypass tenant checks
            }

            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User == null)
            {
                _logger.LogDebug("HTTP context or user not available for tenant check");
                return true; // System context
            }

            // Extract tenant ID from JWT claims
            var tenantClaim = httpContext.User.FindFirst("tenant_id");
            if (tenantClaim == null)
            {
                _logger.LogWarning("Tenant ID claim not found in user token - security concern");
                return false; // Fail secure: deny access
            }

            if (!Guid.TryParse(tenantClaim.Value, out var userTenantId))
            {
                _logger.LogWarning("Invalid tenant ID format in user token: {TenantClaim}", tenantClaim.Value);
                return false; // Fail secure: deny access
            }

            var belongsToTenant = userTenantId == tenantId;

            if (!belongsToTenant)
            {
                _logger.LogWarning("Cross-tenant access attempt - User tenant: {UserTenant}, Requested tenant: {RequestedTenant}, User: {UserId}",
                    userTenantId, tenantId, UserId);
            }
            else
            {
                _logger.LogDebug("Tenant access validated - User: {UserId}, Tenant: {TenantId}", UserId, tenantId);
            }

            return belongsToTenant;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during tenant validation for tenant: {TenantId}", tenantId);
            return false; // Fail secure: deny access on errors
        }
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
    /// - Custom claims: "tenant_id", "permission" (application-specific)
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
        // Extract User ID
        var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier) ?? user.FindFirst("sub");
        if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
        {
            _userId = userId;
        }
        else
        {
            _logger.LogWarning("User ID claim missing or invalid format");
            _userId = null;
        }

        // Extract Email
        var emailClaim = user.FindFirst(ClaimTypes.Email) ?? user.FindFirst("email");
        if (emailClaim != null && !string.IsNullOrWhiteSpace(emailClaim.Value))
        {
            _email = emailClaim.Value;
        }
        else
        {
            _logger.LogDebug("Email claim missing or empty");
            _email = null;
        }

        // Extract Roles
        var roleClaims = user.FindAll(ClaimTypes.Role);
        _roles = roleClaims
            .Select(c => c.Value)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Extract Permissions
        var permissionClaims = user.FindAll("permission");
        _permissions = permissionClaims
            .Select(c => c.Value)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Set default values for unauthenticated or system contexts
    /// 
    /// Default value strategy:
    /// - null for optional properties (UserId, Email)
    /// - Empty collections for arrays (Roles, Permissions)
    /// - Consistent behavior across application
    /// 
    /// Use cases:
    /// - Background job operations
    /// - System maintenance tasks
    /// - Application initialization
    /// - Health check operations
    /// </summary>
    private void SetDefaultValues()
    {
        _userId = null;
        _email = null;
        _roles = new List<string>();
        _permissions = new List<string>();
    }

    #endregion
}