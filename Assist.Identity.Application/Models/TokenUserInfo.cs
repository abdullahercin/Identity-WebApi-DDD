namespace Assist.Identity.Application.Models;

/// <summary>
/// Token User Info Model
/// JWT token'dan extract edilen user bilgileri
/// Authorization middleware'inde kullanılır
/// </summary>
public class TokenUserInfo
{
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public Guid TenantId { get; set; }
    public List<string> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
}