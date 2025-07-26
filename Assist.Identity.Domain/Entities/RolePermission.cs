namespace Assist.Identity.Domain.Entities;

/// <summary>
/// Role-Permission Many-to-Many Join Entity
/// </summary>
public class RolePermission
{
    // Parameterless constructor - EF için
    public RolePermission() { }

    /// <summary>
    /// RolePermission oluşturma constructor
    /// </summary>
    /// <param name="roleId">Role ID</param>
    /// <param name="permissionId">Permission ID</param>
    public RolePermission(Guid roleId, Guid permissionId)
    {
        RoleId = roleId;
        PermissionId = permissionId;
    }

    #region Properties

    /// <summary>
    /// Role ID - Composite key part 1
    /// </summary>
    public Guid RoleId { get; set; }

    /// <summary>
    /// Permission ID - Composite key part 2
    /// </summary>
    public Guid PermissionId { get; set; }

    #endregion

    #region Navigation Properties

    /// <summary>
    /// Role navigation property
    /// </summary>
    public virtual Role? Role { get; set; }

    /// <summary>
    /// Permission navigation property
    /// </summary>
    public virtual Permission? Permission { get; set; }

    #endregion
}