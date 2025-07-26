namespace Assist.Identity.Application.Models;

/// <summary>
/// Tenant Information DTO
/// ICurrentTenantService tarafından return edilir
/// </summary>
public class TenantInfo
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public Dictionary<string, object> Settings { get; set; } = new();
}