namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Permission Not Found Exception
/// Aranılan permission bulunamadığında fırlatılır
/// </summary>
public class PermissionNotFoundException : DomainException
{
    /// <summary>
    /// PermissionNotFoundException constructor with permission name
    /// </summary>
    /// <param name="permissionName">Permission name</param>
    public PermissionNotFoundException(string permissionName) 
        : base($"Permission '{permissionName}' was not found.")
    {
        PermissionName = permissionName;
    }

    /// <summary>
    /// PermissionNotFoundException constructor with permission ID
    /// </summary>
    /// <param name="permissionId">Permission ID</param>
    public PermissionNotFoundException(Guid permissionId) 
        : base($"Permission with ID '{permissionId}' was not found.")
    {
        PermissionId = permissionId;
    }

    /// <summary>
    /// Aranılan permission'ın adı
    /// </summary>
    public string PermissionName { get; }

    /// <summary>
    /// Aranılan permission'ın ID'si
    /// </summary>
    public Guid? PermissionId { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "Permission";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "PERMISSION_NOT_FOUND";
}