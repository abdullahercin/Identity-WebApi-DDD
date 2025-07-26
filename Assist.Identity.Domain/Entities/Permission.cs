using Assist.Identity.Domain.Common;

namespace Assist.Identity.Domain.Entities;

/// <summary>
/// Permission Entity
/// Fine-grained authorization için permission tanımı
/// </summary>
public class Permission : BaseEntity
{
    // Private constructor - EF için
    private Permission() { }

    /// <summary>
    /// Permission oluşturma constructor
    /// </summary>
    private Permission(string name, string? description = null, string category = "General")
    {
        Name = name?.Trim() ?? throw new ArgumentNullException(nameof(name));
        Description = description?.Trim();
        Category = category?.Trim() ?? "General";
        
        // Navigation properties
        RolePermissions = new HashSet<RolePermission>();
    }

    #region Properties

    /// <summary>
    /// Permission adı - Unique olmalı
    /// </summary>
    public string? Name { get; private set; }

    /// <summary>
    /// Permission açıklaması
    /// </summary>
    public string? Description { get; private set; }

    /// <summary>
    /// Permission kategorisi - Grouping için
    /// </summary>
    public string? Category { get; private set; }

    #endregion

    #region Navigation Properties

    /// <summary>
    /// Bu permission'a sahip role'ler
    /// </summary>
    public virtual ICollection<RolePermission>? RolePermissions { get; private set; }

    #endregion

    #region Factory Methods

    /// <summary>
    /// Permission oluşturma factory method
    /// </summary>
    /// <param name="name">Permission adı</param>
    /// <param name="description">Permission açıklaması</param>
    /// <param name="category">Permission kategorisi</param>
    /// <returns>Yeni Permission entity</returns>
    public static Permission Create(string name, string? description = null, string category = "General")
    {
        ValidatePermissionName(name);
        return new Permission(name, description, category);
    }

    #endregion

    #region Private Methods

    /// <summary>
    /// Permission name validation
    /// </summary>
    private static void ValidatePermissionName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Permission name cannot be empty.", nameof(name));

        if (name.Length > 100)
            throw new ArgumentException("Permission name cannot exceed 100 characters.", nameof(name));
    }

    #endregion
}