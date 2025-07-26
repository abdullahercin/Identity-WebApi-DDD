namespace Assist.Identity.Application.DTOs.Requests;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Assign Role Request DTO
/// User'a role atama için
/// </summary>
public class AssignRoleRequest
{
    /// <summary>
    /// User ID
    /// </summary>
    [Required(ErrorMessage = "User ID is required")]
    public Guid UserId { get; set; }

    /// <summary>
    /// Role name
    /// </summary>
    [Required(ErrorMessage = "Role name is required")]
    public string RoleName { get; set; } = string.Empty;
}