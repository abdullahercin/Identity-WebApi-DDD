namespace Assist.Identity.Application.DTOs.Requests;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// User Login Request DTO
/// Authentication için gerekli credentials
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Email adresi
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Password
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Remember me - Refresh token süresini uzatır
    /// </summary>
    public bool RememberMe { get; set; } = false;

    /// <summary>
    /// Client IP address - Security monitoring için
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent - Browser/client bilgisi
    /// </summary>
    public string? UserAgent { get; set; }
}