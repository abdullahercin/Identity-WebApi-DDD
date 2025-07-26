namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Role Not Found Exception
/// Aranılan role bulunamadığında fırlatılır
/// </summary>
public class RoleNotFoundException : DomainException
{
    /// <summary>
    /// RoleNotFoundException constructor with role name
    /// </summary>
    /// <param name="roleName">Role name</param>
    public RoleNotFoundException(string roleName) 
        : base($"Role '{roleName}' was not found.")
    {
        RoleName = roleName;
    }

    /// <summary>
    /// RoleNotFoundException constructor with role ID
    /// </summary>
    /// <param name="roleId">Role ID</param>
    public RoleNotFoundException(Guid roleId) 
        : base($"Role with ID '{roleId}' was not found.")
    {
        RoleId = roleId;
    }

    /// <summary>
    /// Aranılan role'ün adı
    /// </summary>
    public string RoleName { get; }

    /// <summary>
    /// Aranılan role'ün ID'si
    /// </summary>
    public Guid? RoleId { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "Role";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "ROLE_NOT_FOUND";
}