using Assist.Identity.Application.Contracts;
using Assist.Identity.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Assist.Identity.WebApi.Controllers;

/// <summary>
/// Authentication Test Controller - Updated with Test User Creation
/// 
/// Bu controller authentication system'imizin doğru çalışıp çalışmadığını test etmek için
/// endpoint'ler sağlar + development ortamında test user oluşturur.
/// </summary>
[ApiController]
[Route("api/test")]
public class AuthTestController : ControllerBase
{
    private readonly ICurrentUserService _currentUserService;
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IPermissionRepository _permissionRepository;
    private readonly IWebHostEnvironment _hostEnvironment;
    private readonly ILogger<AuthTestController> _logger;

    public AuthTestController(
        ICurrentUserService currentUserService,
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        IPermissionRepository permissionRepository,
        IWebHostEnvironment hostEnvironment,
        ILogger<AuthTestController> logger)
    {
        _currentUserService = currentUserService;
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _permissionRepository = permissionRepository;
        _hostEnvironment = hostEnvironment;
        _logger = logger;
    }

    #region Basic Test Endpoints

    /// <summary>
    /// Public endpoint - authentication gerekmez
    /// </summary>
    [HttpGet("public")]
    public IActionResult PublicEndpoint()
    {
        var response = new
        {
            Message = "This is a public endpoint",
            Timestamp = DateTime.UtcNow,
            Server = Environment.MachineName,
            Status = "Authentication system is running",
            Environment = _hostEnvironment.EnvironmentName,
            TestUserEndpoint = _hostEnvironment.IsDevelopment() ? "/api/test/create-test-user" : "Not available in production"
        };

        _logger.LogInformation("Public endpoint accessed");
        return Ok(response);
    }

    /// <summary>
    /// Protected endpoint - valid JWT token gerekir
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
            FirstName = _currentUserService.FirstName,
            LastName = _currentUserService.LastName,
            FullName = _currentUserService.FullName,
            Roles = _currentUserService.Roles.ToList(),
            Permissions = _currentUserService.Permissions.ToList(),
            Timestamp = DateTime.UtcNow
        };

        _logger.LogInformation("Protected endpoint accessed by user: {UserId}", _currentUserService.UserId);
        return Ok(response);
    }

    /// <summary>
    /// Authentication system health check
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
                AuthenticationScheme = HttpContext?.User?.Identity?.AuthenticationType ?? "None",
                Environment = _hostEnvironment.EnvironmentName,
                Database = "Connected" // TODO: Add actual DB health check
            },
            TestInstructions = new
            {
                Step1 = "Test /api/test/public (should work without token)",
                Step2 = "Test /api/test/protected without token (should return 401)",
                Step3 = "Create test user: POST /api/test/create-test-user (development only)",
                Step4 = "Get JWT token from /api/auth/login",
                Step5 = "Test /api/test/protected with token (should return user info)",
                Step6 = "Test role/permission endpoints based on your token"
            },
            Timestamp = DateTime.UtcNow
        };

        return Ok(response);
    }

    #endregion

    #region Development Test User Creation

    /// <summary>
    /// Test user oluşturma endpoint - Development only
    /// 
    /// Bu endpoint sadece development ortamında test için kullanılır.
    /// Production'da disable edilir.
    /// 
    /// Oluşturduğu test user:
    /// - Email: test@example.com
    /// - Password: Test123!
    /// - Roles: Admin, User
    /// - Permissions: Full access
    /// 
    /// Usage:
    /// POST /api/test/create-test-user
    /// </summary>
    [HttpPost("create-test-user")]
    public async Task<IActionResult> CreateTestUser()
    {
        try
        {
            // Development environment check
            if (!_hostEnvironment.IsDevelopment())
            {
                return BadRequest(new { message = "This endpoint is only available in development environment" });
            }

            // Test user data
            var testEmail = "test@example.com";
            var testPassword = "Test123!";

            _logger.LogInformation("Creating test user: {Email}", testEmail);

            // Check if test user already exists
            var emailVO = Email.Create(testEmail);
            var existingUser = await _userRepository.GetByEmailAsync(emailVO);

            if (existingUser != null)
            {
                var roles = existingUser.GetRoleNames().ToList();
                var permissions = existingUser.GetPermissions().ToList();

                return Ok(new
                {
                    message = "Test user already exists",
                    user = new
                    {
                        id = existingUser.Id,
                        email = existingUser.Email?.Value,
                        firstName = existingUser.FirstName,
                        lastName = existingUser.LastName,
                        roles = roles,
                        permissions = permissions,
                        isActive = existingUser.IsActive,
                        emailConfirmed = existingUser.EmailConfirmed
                    },
                    loginInfo = new
                    {
                        email = testEmail,
                        password = testPassword,
                        loginEndpoint = "/api/auth/login",
                        instructions = "Use this email/password to login and get JWT token"
                    }
                });
            }

            // Create default roles and permissions first
            await CreateDefaultRolesAndPermissions();

            // Create test user
            var user = Assist.Identity.Domain.Entities.User.Create(
                email: testEmail,
                password: testPassword,
                firstName: "Test",
                lastName: "User",
                phoneNumber: "+1234567890"
            );

            // Confirm email for test user
            user.ConfirmEmail();

            // Save user first
            var createdUser = await _userRepository.AddAsync(user);

            // Assign roles to test user
            var adminRole = await _roleRepository.GetByNameAsync("Admin");
            var userRole = await _roleRepository.GetByNameAsync("User");

            if (adminRole != null)
            {
                createdUser.AssignRole(adminRole);
                _logger.LogInformation("Assigned Admin role to test user");
            }

            if (userRole != null)
            {
                createdUser.AssignRole(userRole);
                _logger.LogInformation("Assigned User role to test user");
            }

            // Update user with roles
            await _userRepository.UpdateAsync(createdUser);

            // Get final user data with roles/permissions
            var finalUser = await _userRepository.GetByIdAsync(createdUser.Id);
            var finalRoles = finalUser?.GetRoleNames().ToList() ?? new List<string>();
            var finalPermissions = finalUser?.GetPermissions().ToList() ?? new List<string>();

            var response = new
            {
                message = "Test user created successfully! 🎉",
                user = new
                {
                    id = finalUser?.Id,
                    email = finalUser?.Email?.Value,
                    firstName = finalUser?.FirstName,
                    lastName = finalUser?.LastName,
                    roles = finalRoles,
                    permissions = finalPermissions,
                    isActive = finalUser?.IsActive,
                    emailConfirmed = finalUser?.EmailConfirmed
                },
                loginInfo = new
                {
                    email = testEmail,
                    password = testPassword,
                    loginEndpoint = "/api/auth/login"
                },
                nextSteps = new[]
                {
                    "1. Use POST /api/auth/login with the above credentials",
                    "2. Copy the 'accessToken' from the response",
                    "3. Add 'Authorization: Bearer <accessToken>' header to requests",
                    "4. Test protected endpoints like /api/test/protected",
                    "5. Try admin endpoints with your admin role"
                }
            };

            _logger.LogInformation("Test user created successfully: {Email}", testEmail);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating test user");
            return StatusCode(500, new
            {
                message = "Error creating test user",
                error = ex.Message,
                details = "Check server logs for more details"
            });
        }
    }

    #endregion

    #region Admin Test Endpoints

    /// <summary>
    /// Admin only endpoint - Admin role gerekir
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnlyEndpoint()
    {
        var response = new
        {
            Message = "🔑 Admin access granted!",
            UserId = _currentUserService.UserId,
            Email = _currentUserService.Email,
            FullName = _currentUserService.FullName,
            Roles = _currentUserService.Roles.ToList(),
            AdminPrivileges = new[]
            {
                "Can access all data",
                "Can manage users",
                "Can view system logs",
                "Can modify settings",
                "Can create/delete roles"
            },
            Timestamp = DateTime.UtcNow
        };

        _logger.LogInformation("Admin endpoint accessed by user: {UserId}", _currentUserService.UserId);
        return Ok(response);
    }

    /// <summary>
    /// User context comprehensive test
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
                Email = _currentUserService.Email,
                FirstName = _currentUserService.FirstName,
                LastName = _currentUserService.LastName,
                FullName = _currentUserService.FullName,
                DisplayName = _currentUserService.DisplayName,
                EmailConfirmed = _currentUserService.EmailConfirmed
            },
            Authorization = new
            {
                Roles = _currentUserService.Roles.ToList(),
                RoleCount = _currentUserService.Roles.Count(),
                Permissions = _currentUserService.Permissions.ToList(),
                PermissionCount = _currentUserService.Permissions.Count(),
                IsAdmin = _currentUserService.IsAdmin()
            },
            CapabilityChecks = new
            {
                CanReadUsers = _currentUserService.HasPermission("CanReadUsers"),
                CanEditUsers = _currentUserService.HasPermission("CanEditUsers"),
                CanDeleteUsers = _currentUserService.HasPermission("CanDeleteUsers"),
                CanManageRoles = _currentUserService.HasPermission("CanManageRoles"),
                CanViewReports = _currentUserService.HasPermission("CanViewReports"),
                CanManageSystem = _currentUserService.HasPermission("CanManageSystem")
            },
            SystemInfo = new
            {
                RequestId = HttpContext.TraceIdentifier,
                Timestamp = DateTime.UtcNow,
                RequestPath = HttpContext.Request.Path,
                UserAgent = HttpContext.Request.Headers.UserAgent.ToString(),
                Environment = _hostEnvironment.EnvironmentName
            }
        };

        _logger.LogInformation("User context endpoint accessed - comprehensive test for user: {UserId}",
            _currentUserService.UserId);

        return Ok(response);
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// Default role ve permission'ları oluşturma helper method
    /// </summary>
    private async Task CreateDefaultRolesAndPermissions()
    {
        _logger.LogInformation("Creating default roles and permissions");

        try
        {
            // Create permissions
            var permissionsToCreate = new[]
            {
                ("CanReadUsers", "Can view user list", "User Management"),
                ("CanEditUsers", "Can edit user information", "User Management"),
                ("CanDeleteUsers", "Can delete users", "User Management"),
                ("CanManageRoles", "Can manage user roles", "Role Management"),
                ("CanViewReports", "Can view system reports", "Reporting"),
                ("CanManageSystem", "Can manage system settings", "System")
            };

            var createdPermissions = new List<Permission>();

            foreach (var (name, description, category) in permissionsToCreate)
            {
                var existingPermission = await _permissionRepository.GetByNameAsync(name);
                if (existingPermission == null)
                {
                    var permission = Permission.Create(name, description, category);
                    var created = await _permissionRepository.AddAsync(permission);
                    createdPermissions.Add(created);
                    _logger.LogInformation("Created permission: {PermissionName}", name);
                }
                else
                {
                    createdPermissions.Add(existingPermission);
                }
            }

            // Create Admin role
            var adminRole = await _roleRepository.GetByNameAsync("Admin");
            if (adminRole == null)
            {
                adminRole = Role.Create("Admin", "System Administrator - Full Access");
                adminRole = await _roleRepository.AddAsync(adminRole);
                _logger.LogInformation("Created Admin role");

                // Add all permissions to Admin role
                foreach (var permission in createdPermissions)
                {
                    adminRole.AddPermission(permission);
                }

                await _roleRepository.UpdateAsync(adminRole);
                _logger.LogInformation("Added all permissions to Admin role");
            }

            // Create User role
            var userRole = await _roleRepository.GetByNameAsync("User");
            if (userRole == null)
            {
                userRole = Role.Create("User", "Standard User - Limited Access");
                userRole = await _roleRepository.AddAsync(userRole);
                _logger.LogInformation("Created User role");

                // Add basic permissions to User role
                var basicPermissions = new[] { "CanReadUsers", "CanViewReports" };
                foreach (var permissionName in basicPermissions)
                {
                    var permission = createdPermissions.FirstOrDefault(p => p.Name == permissionName);
                    if (permission != null)
                    {
                        userRole.AddPermission(permission);
                    }
                }

                await _roleRepository.UpdateAsync(userRole);
                _logger.LogInformation("Added basic permissions to User role");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating default roles and permissions");
            throw;
        }
    }

    #endregion
}