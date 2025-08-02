namespace Assist.Identity.Application.Models;

/// <summary>
/// Token User Info Model - Extended
/// JWT token'dan extract edilen user bilgileri
/// Authorization middleware ve CurrentUserService'te kullanılır
/// 
/// Bu model JWT token'daki tüm user claim'lerini represent eder.
/// Token'da bulunan bilgilerin application layer'a clean interface ile aktarılması için.
/// 
/// Design Principles:
/// 1. Token'daki tüm önemli bilgileri içerir
/// 2. Sensitive bilgiler (password) içermez
/// 3. Authorization için gerekli bilgileri sağlar
/// 4. UI personalization için display bilgileri içerir
/// 
/// Usage Scenarios:
/// - Authorization middleware'de user context oluşturma
/// - CurrentUserService implementation'ında user bilgilerine erişim
/// - API response'larında current user bilgisi
/// - Audit logging'de user identification
/// </summary>
public class TokenUserInfo
{
    #region Identity Information

    /// <summary>
    /// User unique identifier
    /// JWT "sub" (subject) claim'inden gelir
    /// Primary key for all user-related operations
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// User email address
    /// JWT "email" claim'inden gelir
    /// Authentication ve notification için kullanılır
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Tenant identifier
    /// JWT "tenant_id" custom claim'inden gelir
    /// Multi-tenancy için kritik bilgi
    /// </summary>
    public Guid TenantId { get; set; }

    #endregion

    #region Personal Information

    /// <summary>
    /// User first name
    /// JWT "first_name" custom claim'inden gelir
    /// UI personalization ve display için kullanılır
    /// 
    /// Use cases:
    /// - Welcome messages: "Hello, John!"
    /// - User profile display
    /// - Email personalization
    /// - Audit log readability
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// User last name
    /// JWT "last_name" custom claim'inden gelir
    /// Full name construction için kullanılır
    /// 
    /// Use cases:
    /// - Formal communication
    /// - Full name display
    /// - Sorting users by surname
    /// - Professional identification
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    #endregion

    #region Authorization Information

    /// <summary>
    /// User roles
    /// JWT "role" claim'lerinden (multiple) gelir
    /// Role-based access control (RBAC) için kullanılır
    /// 
    /// Standard role examples:
    /// - "Admin": Full system access
    /// - "Manager": Team management access
    /// - "User": Basic user access
    /// - "Guest": Limited read-only access
    /// 
    /// Authorization usage:
    /// - Controller/Action level authorization
    /// - UI conditional rendering
    /// - Feature flag management
    /// - Navigation menu customization
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// User permissions
    /// JWT "permission" custom claim'lerinden (multiple) gelir
    /// Fine-grained permission-based access control (PBAC) için kullanılır
    /// 
    /// Permission examples:
    /// - "CanReadUsers": User listing access
    /// - "CanEditProfile": Profile modification access
    /// - "CanDeleteData": Data deletion access
    /// - "CanManageRoles": Role management access
    /// 
    /// Granular authorization:
    /// - API endpoint level authorization
    /// - UI element level access control
    /// - Feature-specific permissions
    /// - Data-level security rules
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    #endregion

    #region Account Status Information

    /// <summary>
    /// Email confirmation status
    /// JWT "email_confirmed" custom claim'inden gelir
    /// 
    /// Business rules:
    /// - Unconfirmed users may have limited access
    /// - Some operations require confirmed email
    /// - Security notifications may be restricted
    /// 
    /// Use cases:
    /// - Email verification flow
    /// - Security operation gating
    /// - User onboarding status
    /// - Conditional feature access
    /// </summary>
    public bool EmailConfirmed { get; set; } = false;

    #endregion

    #region Computed Properties

    /// <summary>
    /// Full name - Computed property
    /// FirstName ve LastName'i birleştirif
    /// 
    /// Business logic:
    /// - İki isim de varsa: "John Doe"
    /// - Sadece FirstName varsa: "John"
    /// - Sadece LastName varsa: "Doe"
    /// - İkisi de yoksa: Email'in @ öncesi kısmı
    /// </summary>
    public string FullName
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(FirstName) && !string.IsNullOrWhiteSpace(LastName))
                return $"{FirstName} {LastName}";

            if (!string.IsNullOrWhiteSpace(FirstName))
                return FirstName;

            if (!string.IsNullOrWhiteSpace(LastName))
                return LastName;

            // Fallback to email username part
            if (!string.IsNullOrWhiteSpace(Email) && Email.Contains('@'))
                return Email.Split('@')[0];

            return "Unknown User";
        }
    }

    /// <summary>
    /// Display name - UI için optimize edilmiş
    /// User interface'lerde gösterim için en uygun isim formatı
    /// 
    /// Priority logic:
    /// 1. FullName (if available)
    /// 2. Email (if no name available)
    /// 3. "User" as ultimate fallback
    /// </summary>
    public string DisplayName
    {
        get
        {
            var fullName = FullName;
            if (!string.IsNullOrWhiteSpace(fullName) && fullName != "Unknown User")
                return fullName;

            if (!string.IsNullOrWhiteSpace(Email))
                return Email;

            return "User";
        }
    }

    /// <summary>
    /// User initials - Avatar placeholder için
    /// Profile picture yoksa initials kullanılabilir
    /// 
    /// Logic:
    /// - FirstName ve LastName varsa: "JD" (John Doe)
    /// - Sadece FirstName varsa: "J" (John)
    /// - Email varsa: Email'in ilk karakteri
    /// - Fallback: "U" (User)
    /// </summary>
    public string Initials
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(FirstName) && !string.IsNullOrWhiteSpace(LastName))
                return $"{FirstName[0]}{LastName[0]}".ToUpper();

            if (!string.IsNullOrWhiteSpace(FirstName))
                return FirstName[0].ToString().ToUpper();

            if (!string.IsNullOrWhiteSpace(Email))
                return Email[0].ToString().ToUpper();

            return "U";
        }
    }

    #endregion

    #region Authorization Helper Methods

    /// <summary>
    /// Role check utility
    /// Specific bir role'ün varlığını kontrol eder
    /// </summary>
    /// <param name="roleName">Kontrol edilecek role adı</param>
    /// <returns>Role varsa true</returns>
    public bool HasRole(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
            return false;

        return Roles.Any(r => r.Equals(roleName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Permission check utility
    /// Specific bir permission'ın varlığını kontrol eder
    /// </summary>
    /// <param name="permissionName">Kontrol edilecek permission adı</param>
    /// <returns>Permission varsa true</returns>
    public bool HasPermission(string permissionName)
    {
        if (string.IsNullOrWhiteSpace(permissionName))
            return false;

        return Permissions.Any(p => p.Equals(permissionName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Admin role check
    /// Admin, Administrator, SuperAdmin role'lerinden birini kontrol eder
    /// </summary>
    /// <returns>Admin role'ü varsa true</returns>
    public bool IsAdmin()
    {
        var adminRoles = new[] { "Admin", "Administrator", "SuperAdmin" };
        return Roles.Any(r => adminRoles.Contains(r, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Multiple role check
    /// Verilen role'lerden herhangi birine sahip mi kontrol eder
    /// </summary>
    /// <param name="roleNames">Kontrol edilecek role adları</param>
    /// <returns>Herhangi bir role varsa true</returns>
    public bool HasAnyRole(params string[] roleNames)
    {
        if (roleNames == null || roleNames.Length == 0)
            return false;

        return roleNames.Any(HasRole);
    }

    /// <summary>
    /// Multiple permission check
    /// Verilen permission'lardan herhangi birine sahip mi kontrol eder
    /// </summary>
    /// <param name="permissionNames">Kontrol edilecek permission adları</param>
    /// <returns>Herhangi bir permission varsa true</returns>
    public bool HasAnyPermission(params string[] permissionNames)
    {
        if (permissionNames == null || permissionNames.Length == 0)
            return false;

        return permissionNames.Any(HasPermission);
    }

    /// <summary>
    /// All permissions check
    /// Verilen tüm permission'lara sahip mi kontrol eder
    /// </summary>
    /// <param name="permissionNames">Kontrol edilecek permission adları</param>
    /// <returns>Tüm permission'lar varsa true</returns>
    public bool HasAllPermissions(params string[] permissionNames)
    {
        if (permissionNames == null || permissionNames.Length == 0)
            return true;

        return permissionNames.All(HasPermission);
    }

    #endregion

    #region Debug and Logging Support

    /// <summary>
    /// Debug string representation
    /// Logging ve debugging için yararlı string representation
    /// </summary>
    /// <returns>User bilgilerinin özeti</returns>
    public override string ToString()
    {
        return $"User: {DisplayName} ({Email}) [Tenant: {TenantId}] - Roles: {string.Join(", ", Roles)} - Permissions: {Permissions.Count}";
    }

    /// <summary>
    /// Authorization summary
    /// Authorization context için özet bilgi
    /// </summary>
    /// <returns>Authorization capability summary</returns>
    public string GetAuthorizationSummary()
    {
        return $"Roles: [{string.Join(", ", Roles)}], Permissions: [{string.Join(", ", Permissions)}], Admin: {IsAdmin()}";
    }

    #endregion
}