using Assist.Identity.Application.DTOs.Common;

namespace Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// Authentication Response DTO
/// Login başarılı olduğunda dönen veri
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// JWT access token
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Refresh token
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Token expiration time
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Token type (Bearer)
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// User information
    /// </summary>
    public UserResponse User { get; set; } = new();

    /// <summary>
    /// User permissions - Client-side authorization için
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// User roles
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// Session information
    /// </summary>
    public SessionInfo Session { get; set; } = new();
}