using Microsoft.EntityFrameworkCore;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.Models;
using Assist.Identity.Infrastructure.Persistence.Contexts;

namespace Assist.Identity.Infrastructure.Persistence.Repositories;

/// <summary>
/// Permission Repository Implementation
/// </summary>
public class PermissionRepository : IPermissionRepository
{
    private readonly IdentityDbContext _context;

    public PermissionRepository(IdentityDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    #region Basic CRUD Operations

    public async Task<Permission?> GetByIdAsync(Guid permissionId, CancellationToken cancellationToken = default)
    {
        return await _context.Permissions
            .Include(p => p.RolePermissions)
                .ThenInclude(rp => rp.Role)
            .FirstOrDefaultAsync(p => p.Id == permissionId, cancellationToken);
    }

    public async Task<Permission?> GetByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Permission name cannot be empty", nameof(name));

        return await _context.Permissions
            .Include(p => p.RolePermissions)
                .ThenInclude(rp => rp.Role)
            .FirstOrDefaultAsync(p => p.Name == name, cancellationToken);
    }

    public async Task<IEnumerable<Permission>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Permissions
            .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
            .ToListAsync(cancellationToken);
    }

    public async Task<Permission> AddAsync(Permission permission, CancellationToken cancellationToken = default)
    {
        if (permission == null)
            throw new ArgumentNullException(nameof(permission));

        _context.Permissions.Add(permission);
        await _context.SaveChangesAsync(cancellationToken);
        return permission;
    }

    public async Task<Permission> UpdateAsync(Permission permission, CancellationToken cancellationToken = default)
    {
        if (permission == null)
            throw new ArgumentNullException(nameof(permission));

        _context.Permissions.Update(permission);
        await _context.SaveChangesAsync(cancellationToken);
        return permission;
    }

    public async Task DeleteAsync(Permission permission, CancellationToken cancellationToken = default)
    {
        if (permission == null)
            throw new ArgumentNullException(nameof(permission));

        _context.Permissions.Remove(permission);
        await _context.SaveChangesAsync(cancellationToken);
    }

    #endregion

    #region Business Queries

    public async Task<IEnumerable<Permission>> GetByCategoryAsync(string category, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(category))
            throw new ArgumentException("Category cannot be empty", nameof(category));

        return await _context.Permissions
            .Where(p => p.Category == category)
            .OrderBy(p => p.Name)
            .ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<Permission>> GetByRoleIdAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        return await _context.Permissions
            .Where(p => p.RolePermissions.Any(rp => rp.RoleId == roleId))
            .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
            .ToListAsync(cancellationToken);
    }

    public async Task<bool> ExistsAsync(string name, Guid? excludeId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        var query = _context.Permissions.Where(p => p.Name == name);

        if (excludeId.HasValue)
            query = query.Where(p => p.Id != excludeId.Value);

        return await query.AnyAsync(cancellationToken);
    }

    #endregion

    #region Pagination & Search

    public async Task<PagedResult<Permission>> GetPagedAsync(
        int pageNumber,
        int pageSize,
        string? searchTerm = null,
        string? category = null,
        CancellationToken cancellationToken = default)
    {
        var query = _context.Permissions.AsQueryable();

        // Search filter
        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            query = query.Where(p =>
                p.Name.Contains(searchTerm) ||
                (p.Description != null && p.Description.Contains(searchTerm)));
        }

        // Category filter
        if (!string.IsNullOrWhiteSpace(category))
        {
            query = query.Where(p => p.Category == category);
        }

        // Total count
        var totalCount = await query.CountAsync(cancellationToken);

        // Paged results
        var items = await query
            .OrderBy(p => p.Category)
                .ThenBy(p => p.Name)
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        return new PagedResult<Permission>
        {
            Items = items,
            TotalCount = totalCount,
            PageNumber = pageNumber,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };
    }

    #endregion
}