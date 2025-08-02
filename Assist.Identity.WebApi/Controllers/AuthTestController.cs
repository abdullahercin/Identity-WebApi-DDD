using Assist.Identity.Application.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Assist.Identity.WebApi.Controllers;

/// <summary>
/// Authentication Test Controller
/// 
/// Bu controller authentication system'imizin doğru çalışıp çalışmadığını test etmek için
/// basit endpoint'ler sağlar. Production'da kaldırılabilir veya development-only yapılabilir.
/// 
/// Test Scenarios:
/// 1. Public endpoint (authentication gerekmez)
/// 2. Protected endpoint (valid JWT token gerekir)
/// 3. Role-based endpoint (specific role gerekir)
/// 4. Permission-based endpoint (specific permission gerekir)
/// 5. User context extraction (CurrentUserService test)
/// 
/// Usage:
/// 1. Public endpoint'i test et → 200 OK beklenir
/// 2. Protected endpoint'e token'sız request → 401 Unauthorized beklenir
/// 3. Valid token ile protected endpoint → 200 OK + user info beklenir
/// 4. Role/permission endpoint'leri authorized user ile test et
/// </summary>
[ApiController]
[Route("api/test")]
public class AuthTestController : ControllerBase
{
    private readonly ICurrentUserService _currentUserService;
    private readonly ILogger<AuthTestController> _logger;

    public AuthTestController(ICurrentUserService currentUserService, ILogger<AuthTestController> logger)
    {
        _currentUserService = currentUserService;
        _logger = logger;
    }

    /// <summary>
    /// Public endpoint - authentication gerekmez
    /// 
    /// Test purpose: Basic API functionality
    /// Expected: 200 OK, herkes erişebilir
    /// 
    /// Usage:
    /// GET /api/test/public
    /// </summary>
    [HttpGet("public")]
    public IActionResult PublicEndpoint()
    {
        var response = new
        {
            Message = "This is a public endpoint",
            Timestamp = DateTime.UtcNow,
            Server = Environment.MachineName,
            Status = "Authentication system is running"
        };

        _logger.LogInformation("Public endpoint accessed");
        return Ok(response);
    }

    /// <summary>
    /// Protected endpoint - valid JWT token gerekir
    /// 
    /// Test purpose: Basic authentication check
    /// Expected: 401 Unauthorized (token yok), 200 OK (valid token)
    /// 
    /// Usage:
    /// GET /api/test/protected
    /// Headers: Authorization: Bearer <jwt-token>
    /// </summary>
    [HttpGet("protected")]
    [Authorize]
    public IActionResult ProtectedEndpoint()
    {
        var response = new
        {
            Message = "This is a protected endpoint",
            IsAuthenticated = _currentUserService.IsAuthenticated,
            UserId = _currentUserService.UserId,
            Email = _currentUserService.Email,
            Roles = _currentUserService.Roles.ToList(),
            Permissions = _currentUserService.Permissions.ToList(),
            Timestamp = DateTime.UtcNow
        };

        _logger.LogInformation("Protected endpoint accessed by user: {UserId}", _currentUserService.UserId);
        return Ok(response);
    }

    /// <summary>
    /// Admin only endpoint - Admin role gerekir
    /// 
    /// Test purpose: Role-based authorization
    /// Expected: 403 Forbidden (wrong role), 200 OK (Admin role)
    /// 
    /// Usage:
    /// GET /api/test/admin-only
    /// Headers: Authorization: Bearer <admin-jwt-token>
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnlyEndpoint()
    {
        var response = new
        {
            Message = "This endpoint is only for Admins",
            UserId = _currentUserService.UserId,
            Email = _currentUserService.Email,
            Roles = _currentUserService.Roles.ToList(),
            AdminPrivileges = new[]
            {
                "Can access all data",
                "Can manage users",
                "Can view system logs",
                "Can modify settings"
            },
            Timestamp = DateTime.UtcNow
        };

        _logger.LogInformation("Admin endpoint accessed by user: {UserId}", _currentUserService.UserId);
        return Ok(response);
    }

    /// <summary>
    /// Permission-based endpoint - specific permission gerekir
    /// 
    /// Test purpose: Permission-based authorization
    /// Expected: 403 Forbidden (permission yok), 200 OK (permission var)
    /// 
    /// Usage:
    /// GET /api/test/can-read-users
    /// Headers: Authorization: Bearer <jwt-token-with-permission>
    /// </summary>
    [HttpGet("can-read-users")]
    [Authorize(Policy = "CanReadUsers")]
    public IActionResult CanReadUsersEndpoint()
    {
        var response = new
        {
            Message = "This endpoint requires CanReadUsers permission",
            UserId = _currentUserService.UserId,
            Email = _currentUserService.Email,
            Permissions = _currentUserService.Permissions.ToList(),
            GrantedAccess = "CanReadUsers",
            Timestamp = DateTime.UtcNow
        };

        _logger.LogInformation("CanReadUsers endpoint accessed by user: {UserId}", _currentUserService.UserId);
        return Ok(response);
    }

    /// <summary>
    /// Multi-tenancy test endpoint
    /// 
    /// Test purpose: Tenant isolation validation
    /// Expected: Tenant bilgisi görüntülenir, cross-tenant access kontrol edilir
    /// 
    /// Usage:
    /// GET /api/test/tenant-info
    /// Headers: Authorization: Bearer <jwt-token>
    /// </summary>
    [HttpGet("tenant-info")]
    [Authorize]
    public IActionResult TenantInfoEndpoint()
    {
        // Simulate tenant check
        var mockTenantId = Guid.NewGuid(); // Gerçek tenant ID
        var belongsToTenant = _currentUserService.BelongsToTenant(mockTenantId);

        var response = new
        {
            Message = "Tenant information and access validation",
            UserId = _currentUserService.UserId,
            Email = _currentUserService.Email,
            TenantAccess = new
            {
                MockTenantId = mockTenantId,
                BelongsToTenant = belongsToTenant,
                AccessDeniedReason = belongsToTenant ? null : "User does not belong to this tenant"
            },
            SecurityNote = "In production, this would filter data by user's actual tenant",
            Timestamp = DateTime.UtcNow
        };

        _logger.LogInformation("Tenant info endpoint accessed by user: {UserId}, belongs to mock tenant: {BelongsToTenant}",
            _currentUserService.UserId, belongsToTenant);

        return Ok(response);
    }

    /// <summary>
    /// User context comprehensive test
    /// 
    /// Test purpose: Full CurrentUserService functionality test
    /// Expected: Complete user context bilgileri display edilir
    /// 
    /// Usage:
    /// GET /api/test/user-context
    /// Headers: Authorization: Bearer <jwt-token>
    /// </summary>
    [HttpGet("user-context")]
    [Authorize]
    public IActionResult UserContextEndpoint()
    {
        var response = new
        {
            Message = "Complete user context information",
            Authentication = new
            {
                IsAuthenticated = _currentUserService.IsAuthenticated,
                UserId = _currentUserService.UserId,
                Email = _currentUserService.Email
            },
            Authorization = new
            {
                Roles = _currentUserService.Roles.ToList(),
                RoleCount = _currentUserService.Roles.Count(),
                Permissions = _currentUserService.Permissions.ToList(),
                PermissionCount = _currentUserService.Permissions.Count()
            },
            CapabilityChecks = new
            {
                CanReadUsers = _currentUserService.Permissions.Contains("CanReadUsers"),
                CanEditUsers = _currentUserService.Permissions.Contains("CanEditUsers"),
                CanDeleteUsers = _currentUserService.Permissions.Contains("CanDeleteUsers"),
                IsAdmin = _currentUserService.Roles.Contains("Admin"),
                IsManager = _currentUserService.Roles.Contains("Manager")
            },
            SystemInfo = new
            {
                RequestId = HttpContext.TraceIdentifier,
                Timestamp = DateTime.UtcNow,
                RequestPath = HttpContext.Request.Path,
                UserAgent = HttpContext.Request.Headers.UserAgent.ToString()
            }
        };

        _logger.LogInformation("User context endpoint accessed - comprehensive test for user: {UserId}",
            _currentUserService.UserId);

        return Ok(response);
    }

    /// <summary>
    /// Authentication system health check
    /// 
    /// Test purpose: System component'lerinin health status'u
    /// Expected: Authentication system component'lerinin durumu
    /// 
    /// Usage:
    /// GET /api/test/auth-health
    /// </summary>
    [HttpGet("auth-health")]
    public IActionResult AuthHealthEndpoint()
    {
        var response = new
        {
            Message = "Authentication system health check",
            Components = new
            {
                JwtMiddleware = "Configured",
                CurrentUserService = _currentUserService != null ? "Available" : "Not Available",
                HttpContext = HttpContext != null ? "Available" : "Not Available",
                AuthenticationScheme = HttpContext?.User?.Identity?.AuthenticationType ?? "None"
            },
            TestInstructions = new
            {
                Step1 = "Test /api/test/public (should work without token)",
                Step2 = "Test /api/test/protected without token (should return 401)",
                Step3 = "Get JWT token from /api/auth/login",
                Step4 = "Test /api/test/protected with token (should return user info)",
                Step5 = "Test role/permission endpoints based on your token"
            },
            Timestamp = DateTime.UtcNow
        };

        return Ok(response);
    }
}