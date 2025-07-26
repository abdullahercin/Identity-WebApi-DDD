namespace Assist.Identity.Application.DTOs.Requests;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Create Role Request DTO
/// Yeni role oluşturma için
/// </summary>
public class CreateRoleRequest
{
    /// <summary>
    /// Role name - Unique olmalı
    /// </summary>
    [Required(ErrorMessage = "Role name is required")]
    [StringLength(50, ErrorMessage = "Role name cannot exceed 50 characters")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Role description
    /// </summary>
    [StringLength(200, ErrorMessage = "Description cannot exceed 200 characters")]
    public string? Description { get; set; }

    /// <summary>
    /// Permission names - Role'e atanacak permission'lar
    /// </summary>
    public List<string> PermissionNames { get; set; } = new();
}