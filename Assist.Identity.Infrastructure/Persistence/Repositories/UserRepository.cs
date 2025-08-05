using Microsoft.EntityFrameworkCore;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Domain.ValueObjects;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.Models;
using Assist.Identity.Infrastructure.Persistence.Contexts;

namespace Assist.Identity.Infrastructure.Persistence.Repositories;

/// <summary>
/// User Repository Implementation
/// 
/// This class implements IUserRepository interface from Application layer.
/// It provides data access for User entity using Entity Framework Core.
/// 
/// Key Learning Points:
/// 1. How to implement Clean Architecture repository pattern
/// 2. Multi-tenant filtering (automatic through global filters)
/// 3. LINQ queries with async/await
/// 4. Complex joins and business queries
/// 5. Pagination and search functionality
/// 6. Proper error handling in data layer
/// </summary>
public class UserRepository : IUserRepository
{
    private readonly IdentityDbContext _context;

    /// <summary>
    /// Constructor - Dependency injection of DbContext
    /// This is how Infrastructure layer gets access to database
    /// </summary>
    public UserRepository(IdentityDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    #region Basic CRUD Operations

    /// <summary>
    /// Get user by ID with related data (roles, refresh tokens)
    /// 
    /// Uses Include() to load related entities in single query.
    /// Multi-tenant filtering happens automatically through global filters.
    /// </summary>
    public async Task<User?> GetByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)                // Load roles through UserRole join
                    .ThenInclude(r => r.RolePermissions)   // Load permissions through RolePermission join
                        .ThenInclude(rp => rp.Permission)  // Load actual Permission entities
            .Include(u => u.RefreshTokens)                 // Load user's refresh tokens
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

        // Note: No need to filter by TenantId manually - global filters handle this automatically!
        // This is the power of our IdentityDbContext configuration
    }

    /// <summary>
    /// Get user by email address
    /// 
    /// Email is a value object, so we access its Value property.
    /// This is commonly used for login functionality.
    /// </summary>
    public async Task<User?> GetByEmailAsync(Email email, CancellationToken cancellationToken = default)
    {
        if (email == null)
            throw new ArgumentNullException(nameof(email));

        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .ThenInclude(r => r.RolePermissions)
            .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(u => u.Email == email, cancellationToken);

        // Again, tenant filtering is automatic - very clean and safe!
    }

    /// <summary>
    /// Add new user to database
    /// 
    /// EF Core will automatically set audit fields (CreatedAt, CreatedBy, TenantId)
    /// through our IdentityDbContext SaveChanges override.
    /// </summary>
    public async Task<User> AddAsync(User user, CancellationToken cancellationToken = default)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        _context.Users.Add(user);
        await _context.SaveChangesAsync(cancellationToken);
        return user;
    }

    /// <summary>
    /// Update existing user
    /// 
    /// EF Core tracks changes automatically, so we just need to call SaveChanges.
    /// Audit fields (UpdatedAt, UpdatedBy) will be set automatically.
    /// </summary>
    public async Task UpdateAsync(User user, CancellationToken cancellationToken = default)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        _context.Users.Update(user);
        await _context.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Delete user (typically soft delete through IsActive = false)
    /// 
    /// In most business applications, we don't physically delete users
    /// for audit trail and data integrity reasons.
    /// </summary>
    public async Task DeleteAsync(User user, CancellationToken cancellationToken = default)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        // Instead of physical delete, we typically deactivate the user
        user.Deactivate(); // This is domain method that sets IsActive = false
        await _context.SaveChangesAsync(cancellationToken);
    }

    #endregion

    #region Existence Checks

    /// <summary>
    /// Check if user exists by ID
    /// 
    /// More efficient than GetByIdAsync when you only need existence check.
    /// Uses Any() which stops at first match.
    /// </summary>
    public async Task<bool> ExistsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.Users
            .AnyAsync(u => u.Id == userId, cancellationToken);
    }

    /// <summary>
    /// Check if email already exists (for duplicate prevention)
    /// 
    /// excludeUserId parameter allows checking during user updates
    /// (user can keep their own email, but can't use someone else's email)
    /// </summary>
    public async Task<bool> EmailExistsAsync(Email email, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
    {
        if (email == null)
            throw new ArgumentNullException(nameof(email));

        var query = _context.Users.Where(u => u.Email == email);

        if (excludeUserId.HasValue)
        {
            query = query.Where(u => u.Id != excludeUserId.Value);
        }

        return await query.AnyAsync(cancellationToken);
    }

    #endregion

    #region Business Queries

    /// <summary>
    /// Get all active users
    /// 
    /// Business query: commonly used in admin interfaces
    /// to show users who can currently access the system.
    /// </summary>
    public async Task<IEnumerable<User>> GetActiveUsersAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Users
            .Where(u => u.IsActive)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Get users by role name
    /// 
    /// Complex query: joins through UserRole to find users with specific role.
    /// Example: "Get all users with 'Admin' role"
    /// </summary>
    public async Task<IEnumerable<User>> GetUsersByRoleAsync(string roleName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(roleName))
            throw new ArgumentException("Role name cannot be empty", nameof(roleName));

        return await _context.Users
            .Where(u => u.UserRoles.Any(ur => ur.Role.Name == roleName && ur.Role.IsActive))
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Get users by permission name
    /// 
    /// Very complex query: joins through UserRole → Role → RolePermission → Permission
    /// Example: "Get all users who can 'DeleteUser'"
    /// </summary>
    public async Task<IEnumerable<User>> GetUsersByPermissionAsync(string permissionName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(permissionName))
            throw new ArgumentException("Permission name cannot be empty", nameof(permissionName));

        return await _context.Users
            .Where(u => u.UserRoles
                .Any(ur => ur.Role.IsActive &&
                          ur.Role.RolePermissions
                            .Any(rp => rp.Permission.Name == permissionName)))
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                    .ThenInclude(r => r.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
            .ToListAsync(cancellationToken);
    }

    #endregion

    #region Pagination & Search

    /// <summary>
    /// Get paginated users with search functionality
    /// 
    /// This is essential for admin interfaces with large user bases.
    /// Combines filtering, searching, and pagination in efficient query.
    /// </summary>
    public async Task<PagedResult<User>> GetPagedAsync(int pageNumber, int pageSize, string? searchTerm = null, CancellationToken cancellationToken = default)
    {
        if (pageNumber < 1)
            throw new ArgumentException("Page number must be greater than 0", nameof(pageNumber));

        if (pageSize < 1 || pageSize > 100)
            throw new ArgumentException("Page size must be between 1 and 100", nameof(pageSize));

        var query = _context.Users.AsQueryable();

        // Apply search filter if provided
        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            var searchLower = searchTerm.ToLower();
            query = query.Where(u =>
                u.Email.Value.ToLower().Contains(searchLower) ||
                u.FirstName.ToLower().Contains(searchLower) ||
                u.LastName.ToLower().Contains(searchLower));
        }

        // Get total count for pagination info
        var totalCount = await query.CountAsync(cancellationToken);

        // Apply pagination
        var users = await query
            .OrderBy(u => u.Email.Value)              // Consistent ordering
            .Skip((pageNumber - 1) * pageSize)       // Skip previous pages
            .Take(pageSize)                          // Take only current page
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .ToListAsync(cancellationToken);

        return new PagedResult<User>
        {
            Items = users,
            TotalCount = totalCount,
            PageNumber = pageNumber,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling((double)totalCount / pageSize)
        };
    }

    /// <summary>
    /// Get total user count
    /// 
    /// Simple but useful for dashboard statistics.
    /// Much more efficient than loading all users just to count them.
    /// </summary>
    public async Task<int> GetTotalUserCountAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Users.CountAsync(cancellationToken);
    }

    #endregion

    #region Multi-Tenant Operations

    /// <summary>
    /// Get users by specific tenant
    /// 
    /// Special method that might be used by system administrators
    /// who can see across tenants. Normal users won't need this
    /// because global filters handle tenant isolation automatically.
    /// </summary>
    public async Task<IEnumerable<User>> GetUsersByTenantAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        if (tenantId == Guid.Empty)
            throw new ArgumentException("Tenant ID cannot be empty", nameof(tenantId));

        // This query explicitly filters by tenant
        // Might be used in system admin scenarios where global filters are bypassed
        return await _context.Users
            .Where(u => u.TenantId == tenantId)
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .ToListAsync(cancellationToken);
    }

    #endregion
}