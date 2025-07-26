namespace Assist.Identity.Application.Contracts;
/// <summary>
/// Current User Service Contract
/// Authentication context'inden current user bilgisi sağlar
/// 
/// Bu service JWT token'dan veya session'dan
/// current user bilgilerini extract eder
/// </summary>
public interface ICurrentUserService
{
    /// <summary>
    /// Current user ID
    /// JWT token'dan veya session'dan alınır
    /// Audit trail için kullanılır
    /// </summary>
    Guid? UserId { get; }

    /// <summary>
    /// Current user email
    /// Logging ve audit için
    /// </summary>
    string? Email { get; }

    /// <summary>
    /// Current user'ın role'leri
    /// Authorization için cached olarak tutulabilir
    /// </summary>
    IEnumerable<string> Roles { get; }

    /// <summary>
    /// Current user'ın permission'ları
    /// Fine-grained authorization için
    /// </summary>
    IEnumerable<string> Permissions { get; }

    /// <summary>
    /// User authentication durumu
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Current user'ın tenant'ına ait olup olmadığını kontrol eder
    /// Cross-tenant security için
    /// </summary>
    /// <param name="tenantId">Kontrol edilecek tenant ID</param>
    /// <returns>User bu tenant'a aitse true</returns>
    bool BelongsToTenant(Guid tenantId);
}