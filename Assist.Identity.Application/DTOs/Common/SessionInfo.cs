namespace Assist.Identity.Application.DTOs.Common;

/// <summary>
/// Session Information DTO
/// AuthResponse içinde kullanılan embedded DTO
/// User session bilgilerini taşır
/// </summary>
public class SessionInfo
{
    /// <summary>
    /// Session start time
    /// </summary>
    public DateTime StartedAt { get; set; }

    /// <summary>
    /// IP address
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Session expiry
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Session duration - Computed property
    /// </summary>
    public TimeSpan Duration => ExpiresAt - StartedAt;

    /// <summary>
    /// Is session active
    /// </summary>
    public bool IsActive => DateTime.UtcNow < ExpiresAt;
}