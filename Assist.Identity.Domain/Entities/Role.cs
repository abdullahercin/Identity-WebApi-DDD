using Assist.Identity.Domain.Common;

namespace Assist.Identity.Domain.Entities;

/// <summary>
/// Role Entity
/// RBAC (Role-Based Access Control) sistem için role tanımı
/// </summary>
public class Role : BaseEntity
{
    // Private constructor - EF için
    private Role() { }

    /// <summary>
    /// Role oluşturma constructor
    /// </summary>
    private Role(string name, string description = null)
    {
        Name = name?.Trim() ?? throw new ArgumentNullException(nameof(name));
        Description = description?.Trim();
        IsActive = true;
        
        // Navigation properties
        UserRoles = new HashSet<UserRole>();
        RolePermissions = new HashSet<RolePermission>();
    }

    #region Properties

    /// <summary>
    /// Role adı - Unique olmalı
    /// </summary>
    public string Name { get; private set; }

    /// <summary>
    /// Role açıklaması
    /// </summary>
    public string Description { get; private set; }

    /// <summary>
    /// Role aktif mi
    /// </summary>
    public bool IsActive { get; private set; }

    #endregion

    #region Navigation Properties

    /// <summary>
    /// Bu role'e sahip user'lar
    /// </summary>
    public virtual ICollection<UserRole> UserRoles { get; private set; }

    /// <summary>
    /// Role'ün sahip olduğu permission'lar
    /// </summary>
    public virtual ICollection<RolePermission> RolePermissions { get; private set; }

    #endregion

    #region Factory Methods

    /// <summary>
    /// Role oluşturma factory method
    /// </summary>
    /// <param name="name">Role adı</param>
    /// <param name="description">Role açıklaması</param>
    /// <returns>Yeni Role entity</returns>
    public static Role Create(string name, string description = null)
    {
        ValidateRoleName(name);
        return new Role(name, description);
    }

    #endregion

    #region Business Methods

    /// <summary>
    /// Permission ekleme
    /// </summary>
    /// <param name="permission">Eklenecek permission</param>
    public void AddPermission(Permission permission)
    {
        if (permission == null)
            throw new ArgumentNullException(nameof(permission));

        // Duplicate check
        if (RolePermissions.Any(rp => rp.PermissionId == permission.Id))
            return;

        var rolePermission = new RolePermission(Id, permission.Id);
        RolePermissions.Add(rolePermission);
    }

    /// <summary>
    /// Permission kaldırma
    /// </summary>
    /// <param name="permission">Kaldırılacak permission</param>
    public void RemovePermission(Permission permission)
    {
        if (permission == null)
            throw new ArgumentNullException(nameof(permission));

        var rolePermission = RolePermissions.FirstOrDefault(rp => rp.PermissionId == permission.Id);
        if (rolePermission != null)
        {
            RolePermissions.Remove(rolePermission);
        }
    }

    /// <summary>
    /// Role'ü deaktive et
    /// </summary>
    public void Deactivate()
    {
        IsActive = false;
    }

    /// <summary>
    /// Role'ü aktive et
    /// </summary>
    public void Activate()
    {
        IsActive = true;
    }

    #endregion

    #region Query Methods

    /// <summary>
    /// Permission adlarını getir
    /// </summary>
    /// <returns>Permission adları</returns>
    public IEnumerable<string> GetPermissionNames()
    {
        return RolePermissions.Select(rp => rp.Permission.Name);
    }

    /// <summary>
    /// Specific permission kontrolü
    /// </summary>
    /// <param name="permissionName">Permission adı</param>
    /// <returns>Permission varsa true</returns>
    public bool HasPermission(string permissionName)
    {
        return RolePermissions.Any(rp => rp.Permission.Name == permissionName);
    }

    #endregion

    #region Private Methods

    /// <summary>
    /// Role name validation
    /// </summary>
    private static void ValidateRoleName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Role name cannot be empty.", nameof(name));

        if (name.Length > 50)
            throw new ArgumentException("Role name cannot exceed 50 characters.", nameof(name));
    }

    #endregion
}