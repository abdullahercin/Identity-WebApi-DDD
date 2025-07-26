namespace Assist.Identity.Domain.Entities;

/// <summary>
/// User-Role Many-to-Many Join Entity
/// Modern EF Core approach ile explicit join table
/// </summary>
public class UserRole
{
    // Parameterless constructor - EF için
    public UserRole() { }

    /// <summary>
    /// UserRole oluşturma constructor
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="roleId">Role ID</param>
    public UserRole(Guid userId, Guid roleId)
    {
        UserId = userId;
        RoleId = roleId;
        AssignedAt = DateTime.UtcNow;
    }

    #region Properties

    /// <summary>
    /// User ID - Composite key part 1
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Role ID - Composite key part 2
    /// </summary>
    public Guid RoleId { get; set; }

    /// <summary>
    /// Role atanma zamanı
    /// </summary>
    public DateTime AssignedAt { get; set; }

    #endregion

    #region Navigation Properties

    /// <summary>
    /// User navigation property
    /// </summary>
    public virtual User? User { get; set; }

    /// <summary>
    /// Role navigation property
    /// </summary>
    public virtual Role? Role { get; set; }

    #endregion
}