using Microsoft.EntityFrameworkCore;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Infrastructure.Persistence.Contexts;

namespace Assist.Identity.Infrastructure.Persistence.Repositories;

/// <summary>
/// Role Repository Implementation
/// 
/// This class implements IRoleRepository interface from Application layer.
/// It provides data access for Role entity using Entity Framework Core.
/// 
/// Key Learning Points:
/// 1. How repository patterns are consistent across different entities
/// 2. Role-specific business queries (simpler than User queries)
/// 3. Loading related data (permissions through role-permission relationships)
/// 4. Role name uniqueness validation within tenant
/// 5. Same multi-tenant filtering as UserRepository (automatic)
/// 
/// Compared to UserRepository:
/// - Simpler because Role has no value objects
/// - Fewer methods (6 vs 11)
/// - Less complex relationships
/// - Same architectural patterns
/// </summary>
public class RoleRepository : IRoleRepository
{
    private readonly IdentityDbContext _context;

    /// <summary>
    /// Constructor - Same dependency injection pattern as UserRepository
    /// </summary>
    public RoleRepository(IdentityDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    #region Basic CRUD Operations

    /// <summary>
    /// Get role by ID with related data
    /// 
    /// Loads role with its permissions and users.
    /// Pattern is identical to UserRepository.GetByIdAsync but for Role entity.
    /// Multi-tenant filtering happens automatically.
    /// </summary>
    public async Task<Role?> GetByIdAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.Roles
            .Include(r => r.RolePermissions)              // Load role's permissions
                .ThenInclude(rp => rp.Permission)         // Load actual Permission entities
            .Include(r => r.UserRoles)                    // Load users who have this role
                .ThenInclude(ur => ur.User)               // Load actual User entities
            .FirstOrDefaultAsync(r => r.Id == roleId, cancellationToken);

        // Note: Same as UserRepository - no manual tenant filtering needed!
        // Global filters in IdentityDbContext handle this automatically.
    }

    /// <summary>
    /// Get role by name
    /// 
    /// This is commonly used for role-based authorization checks.
    /// Example: checking if user has "Admin" role.
    /// Much simpler than UserRepository.GetByEmailAsync because Role.Name is a simple string.
    /// </summary>
    public async Task<Role?> GetByNameAsync(string roleName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(roleName))
            throw new ArgumentException("Role name cannot be empty", nameof(roleName));

        return await _context.Roles
            .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
            .Include(r => r.UserRoles)
                .ThenInclude(ur => ur.User)
            .FirstOrDefaultAsync(r => r.Name == roleName, cancellationToken);

        // Automatic tenant filtering ensures we only get roles from current tenant
    }

    /// <summary>
    /// Add new role to database
    /// 
    /// Identical pattern to UserRepository.AddAsync.
    /// EF Core automatically handles audit fields through IdentityDbContext.
    /// </summary>
    public async Task<Role> AddAsync(Role role, CancellationToken cancellationToken = default)
    {
        if (role == null)
            throw new ArgumentNullException(nameof(role));

        _context.Roles.Add(role);
        await _context.SaveChangesAsync(cancellationToken);
        return role;
    }

    /// <summary>
    /// Update existing role
    /// 
    /// Same pattern as UserRepository - EF Core change tracking handles the rest.
    /// UpdatedAt and UpdatedBy audit fields set automatically.
    /// </summary>
    public async Task UpdateAsync(Role role, CancellationToken cancellationToken = default)
    {
        if (role == null)
            throw new ArgumentNullException(nameof(role));

        _context.Roles.Update(role);
        await _context.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Delete role
    /// 
    /// Similar to UserRepository, we typically use soft delete (Deactivate).
    /// However, roles might be physically deleted in some scenarios
    /// since they're less critical for audit trails than users.
    /// </summary>
    public async Task DeleteAsync(Role role, CancellationToken cancellationToken = default)
    {
        if (role == null)
            throw new ArgumentNullException(nameof(role));

        // Soft delete approach - deactivate the role
        role.Deactivate(); // Domain method that sets IsActive = false
        await _context.SaveChangesAsync(cancellationToken);

        // Alternative: Physical delete (uncomment if business rules allow)
        // _context.Roles.Remove(role);
        // await _context.SaveChangesAsync(cancellationToken);
    }

    #endregion

    #region Business Queries

    /// <summary>
    /// Get all active roles
    /// 
    /// Business query: commonly used in role assignment interfaces.
    /// You typically only want to show active roles when assigning roles to users.
    /// Much simpler than UserRepository business queries.
    /// </summary>
    public async Task<IEnumerable<Role>> GetActiveRolesAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Roles
            .Where(r => r.IsActive)                      // Only active roles
            .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
            .OrderBy(r => r.Name)                        // Alphabetical order for UI
            .ToListAsync(cancellationToken);

        // Tenant filtering automatic - only current tenant's roles returned
    }

    /// <summary>
    /// Get roles assigned to specific user
    /// 
    /// Complex query but simpler than UserRepository.GetUsersByPermissionAsync.
    /// Joins through UserRole table to find roles for specific user.
    /// Example: "What roles does John Doe have?"
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException("User ID cannot be empty", nameof(userId));

        return await _context.Roles
            .Where(r => r.UserRoles.Any(ur => ur.UserId == userId))  // Join through UserRole
            .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);

        // Multi-tenant filtering ensures we only see roles from current tenant
        // even if somehow userId from different tenant was passed
    }

    /// <summary>
    /// Check if role name already exists
    /// 
    /// Similar to UserRepository.EmailExistsAsync but for role names.
    /// Used to prevent duplicate role names within same tenant.
    /// excludeRoleId parameter allows checking during role updates.
    /// </summary>
    public async Task<bool> RoleExistsAsync(string roleName, Guid? excludeRoleId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(roleName))
            throw new ArgumentException("Role name cannot be empty", nameof(roleName));

        var query = _context.Roles.Where(r => r.Name == roleName);

        // If excluding a specific role (during update operations)
        // This allows role to keep its own name but prevents using another role's name
        if (excludeRoleId.HasValue)
        {
            query = query.Where(r => r.Id != excludeRoleId.Value);
        }

        return await query.AnyAsync(cancellationToken);

        // Tenant filtering automatic - checks uniqueness only within current tenant
        // This means different tenants can have roles with same names (which is correct business logic)
    }

    #endregion

    #region Additional Helper Methods

    /// <summary>
    /// Get total role count for current tenant
    /// 
    /// Simple utility method similar to UserRepository.GetTotalUserCountAsync.
    /// Useful for dashboard statistics or pagination calculations.
    /// </summary>
    public async Task<int> GetTotalRoleCountAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Roles.CountAsync(cancellationToken);

        // Count automatically filtered by tenant through global filters
    }

    /// <summary>
    /// Get roles with specific permission
    /// 
    /// Business query: "Which roles have 'DeleteUser' permission?"
    /// Reverse of UserRepository.GetUsersByPermissionAsync - shows the power
    /// of relationship navigation in both directions.
    /// </summary>
    public async Task<IEnumerable<Role>> GetRolesWithPermissionAsync(string permissionName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(permissionName))
            throw new ArgumentException("Permission name cannot be empty", nameof(permissionName));

        return await _context.Roles
            .Where(r => r.IsActive &&
                       r.RolePermissions.Any(rp => rp.Permission.Name == permissionName))
            .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);
    }

    #endregion
}