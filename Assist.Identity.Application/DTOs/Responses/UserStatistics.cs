namespace Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// User Statistics DTO
/// Dashboard için user istatistikleri
/// </summary>
public class UserStatistics
{
    public int TotalUsers { get; set; }
    public int ActiveUsers { get; set; }
    public int InactiveUsers { get; set; }
    public int UnconfirmedEmails { get; set; }
    public int LockedAccounts { get; set; }
    public int NewUsersThisMonth { get; set; }
    public int NewUsersThisWeek { get; set; }
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
}