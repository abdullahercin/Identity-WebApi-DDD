namespace Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// User Response DTO
/// User bilgilerini API'ye expose eder
/// Sensitive bilgiler (password hash) burada yer almaz
/// </summary>
public class UserResponse
{
    /// <summary>
    /// User ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// First name
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Last name
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Phone number
    /// </summary>
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// User aktif mi
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Email confirmed mi
    /// </summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>
    /// Oluşturulma zamanı
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Son login zamanı
    /// </summary>
    public DateTime? LastLoginAt { get; set; }

    /// <summary>
    /// Full name - Computed property
    /// </summary>
    public string FullName => $"{FirstName} {LastName}";

    /// <summary>
    /// Display name - UI için
    /// </summary>
    public string DisplayName => !string.IsNullOrEmpty(FirstName) ? FullName : Email;

    /// <summary>
    /// User'ın role'leri
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// User'ın permission'ları
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Tenant ID - Multi-tenancy için
    /// </summary>
    public Guid TenantId { get; set; }
}