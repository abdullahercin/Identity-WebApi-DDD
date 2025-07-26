namespace Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// Role Response DTO
/// Role bilgilerini API'ye expose eder
/// </summary>
public class RoleResponse
{
    /// <summary>
    /// Role ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Role name
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Role description
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Role aktif mi
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Oluşturulma zamanı
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Role'ün sahip olduğu permission'lar
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Role'e sahip user sayısı
    /// </summary>
    public int UserCount { get; set; }
}