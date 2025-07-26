namespace Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// User Session DTO
/// Aktif session bilgileri
/// </summary>
public class UserSession
{
    public string SessionId { get; set; } = string.Empty;
    public DateTime StartedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? DeviceInfo { get; set; }
    public bool IsCurrentSession { get; set; }
    public DateTime LastActivity { get; set; }
}