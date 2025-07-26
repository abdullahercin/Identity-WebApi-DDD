namespace Assist.Identity.Domain.Events;

/// <summary>
/// Role Assigned Domain Event
/// User'a role atandığında fırlatılır
/// Permission cache invalidation, ERP synchronization, audit için kullanılır
/// </summary>
public sealed class RoleAssignedEvent : BaseDomainEvent
{
    /// <summary>
    /// RoleAssignedEvent constructor
    /// </summary>
    /// <param name="userId">Role atanan user'ın ID'si</param>
    /// <param name="userEmail">User'ın email adresi</param>
    /// <param name="roleId">Atanan role'ün ID'si</param>
    /// <param name="roleName">Atanan role'ün adı</param>
    /// <param name="tenantId">Tenant ID'si</param>
    /// <param name="assignedBy">Role atamasını yapan user'ın ID'si</param>
    /// <param name="permissions">Role ile gelen permission'lar</param>
    public RoleAssignedEvent(
        Guid userId,
        string? userEmail,
        Guid roleId,
        string? roleName,
        Guid tenantId,
        string? assignedBy = null,
        IEnumerable<string>? permissions = null) : base(tenantId)
    {
        UserId = userId;
        UserEmail = userEmail ?? throw new ArgumentNullException(nameof(userEmail));
        RoleId = roleId;
        RoleName = roleName ?? throw new ArgumentNullException(nameof(roleName));
        AssignedBy = assignedBy;
        AssignedAt = DateTime.UtcNow;
        Permissions = permissions?.ToList() ?? new List<string>();
    }

    /// <summary>
    /// Role atanan user'ın ID'si
    /// </summary>
    public Guid UserId { get; }

    /// <summary>
    /// User'ın email adresi
    /// </summary>
    public string UserEmail { get; }

    /// <summary>
    /// Atanan role'ün ID'si
    /// </summary>
    public Guid RoleId { get; }

    /// <summary>
    /// Atanan role'ün adı
    /// "Admin", "User", "Manager" gibi
    /// </summary>
    public string RoleName { get; }

    /// <summary>
    /// Role ataması zamanı
    /// </summary>
    public DateTime AssignedAt { get; }

    /// <summary>
    /// Role atamasını yapan user'ın ID'si
    /// System tarafından yapıldıysa null olabilir
    /// </summary>
    public string? AssignedBy { get; }

    /// <summary>
    /// Role ile gelen permission'lar
    /// Cache invalidation için kullanılır
    /// </summary>
    public IReadOnlyList<string> Permissions { get; }

    /// <summary>
    /// System tarafından mı atandı kontrolü
    /// </summary>
    public bool IsSystemAssigned => string.IsNullOrWhiteSpace(AssignedBy);

    /// <summary>
    /// Has permissions check
    /// </summary>
    public bool HasPermissions => Permissions.Any();

    /// <summary>
    /// Is admin role check
    /// Admin role'ü special handling gerektirebilir
    /// </summary>
    public bool IsAdminRole => RoleName.Equals("Admin", StringComparison.OrdinalIgnoreCase) ||
                              RoleName.Equals("Administrator", StringComparison.OrdinalIgnoreCase);
}