namespace Assist.Identity.Application.DTOs.Requests;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// User Registration Request DTO
/// API'ye gelen user registration verilerini taşır
/// 
/// Bu DTO iki tip property içerir:
/// 1. User Input Properties: Frontend'den kullanıcı tarafından girilen veriler
/// 2. Context Properties: Controller tarafından request context'inden alınan veriler
/// 
/// Security Note: IpAddress ve UserAgent değerleri sensitive değil ama
/// client tarafından manipüle edilebilir, bu yüzden sadece logging/analytics için kullanılmalı
/// </summary>
public class RegisterRequest
{
    #region User Input Properties

    /// <summary>
    /// Email adresi - Required ve email format validation
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(254, ErrorMessage = "Email cannot exceed 254 characters")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Password - Required ve strength validation
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 128 characters")]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Password confirmation - Must match password
    /// </summary>
    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>
    /// First name - Required
    /// </summary>
    [Required(ErrorMessage = "First name is required")]
    [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Last name - Required
    /// </summary>
    [Required(ErrorMessage = "Last name is required")]
    [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Phone number - Optional, international format
    /// </summary>
    [Phone(ErrorMessage = "Invalid phone number format")]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Role names - Optional, default "User" role will be assigned
    /// Admin tarafından bulk registration yapılırken kullanılabilir
    /// </summary>
    public List<string> RoleNames { get; set; } = new();

    /// <summary>
    /// Additional metadata - Extensibility için
    /// Campaign tracking, referral codes, analytics data gibi
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    #endregion

    #region Context Properties (Controller tarafından set edilir)

    /// <summary>
    /// Client IP address - Controller tarafından HttpContext'ten alınır
    /// 
    /// Security ve analytics purposes:
    /// - Suspicious registration pattern detection
    /// - Geographic analytics
    /// - Security audit log
    /// - Rate limiting (IP-based)
    /// 
    /// Note: Bu değer client tarafından set edilmemelidir, güvenlik riski oluşturur
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent string - Controller tarafından HttpContext'ten alınır
    /// 
    /// Analytics ve security purposes:
    /// - Device/browser analytics
    /// - Bot detection (basit seviyede)
    /// - User experience optimization
    /// - Security monitoring (unusual patterns)
    /// 
    /// Note: Bu değer de client tarafından manipüle edilebilir
    /// </summary>
    public string? UserAgent { get; set; }

    #endregion

    #region Computed Properties

    /// <summary>
    /// Full name - Computed property for convenience
    /// </summary>
    public string FullName => $"{FirstName.Trim()} {LastName.Trim()}";

    /// <summary>
    /// Has context info - Security/analytics için context bilgisi var mı kontrolü
    /// </summary>
    public bool HasContextInfo => !string.IsNullOrWhiteSpace(IpAddress) || !string.IsNullOrWhiteSpace(UserAgent);

    /// <summary>
    /// Has additional roles - Default role dışında ek role atanacak mı kontrolü
    /// </summary>
    public bool HasAdditionalRoles => RoleNames?.Any() == true;

    /// <summary>
    /// Has metadata - Ek metadata bilgisi var mı kontrolü
    /// </summary>
    public bool HasMetadata => Metadata?.Any() == true;

    #endregion
}