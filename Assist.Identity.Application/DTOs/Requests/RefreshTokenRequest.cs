namespace Assist.Identity.Application.DTOs.Requests;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Refresh Token Request DTO
/// Access token yenileme için
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// Refresh token string
    /// </summary>
    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Access token (opsiyonel validation için)
    /// </summary>
    public string? AccessToken { get; set; }
}