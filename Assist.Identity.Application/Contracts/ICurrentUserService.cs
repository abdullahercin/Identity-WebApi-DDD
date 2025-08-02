namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Current User Service Contract - Extended
/// Authentication context'inden current user bilgisi sağlar
/// 
/// Bu service JWT token'dan veya session'dan current user bilgilerini extract eder.
/// Clean Architecture pattern: Infrastructure layer HTTP context'e erişir,
/// Application layer bu interface üzerinden user bilgilerine erişir.
/// 
/// Benefits:
/// - Application layer HTTP context'den izole edilir
/// - Testing kolay (interface mock'lanabilir)
/// - Clean separation of concerns
/// - Business logic web framework'e bağımlı olmaz
/// 
/// Usage Scenarios:
/// - Repository queries (user-specific data filtering)
/// - Authorization checks (permission validation)
/// - Audit logging (user action tracking)
/// - Business rules (user context-dependent logic)
/// - UI personalization (user display information)
/// </summary>
public interface ICurrentUserService
{
    #region Core Identity Information

    /// <summary>
    /// Current user ID
    /// JWT token'dan veya session'dan alınır
    /// 
    /// Usage:
    /// - Primary key for user-related queries
    /// - Audit trail ve logging için
    /// - User ownership validation
    /// - Repository filtering (user-specific data)
    /// 
    /// Returns null when:
    /// - User not authenticated
    /// - Background/system operations
    /// - Invalid token or missing claims
    /// </summary>
    Guid? UserId { get; }

    /// <summary>
    /// Current user email
    /// Authentication principal'ından alınır
    /// 
    /// Usage:
    /// - User identification ve display
    /// - Email notifications (from context)
    /// - Audit trails (user-readable identifier)
    /// - Fallback display name
    /// 
    /// Security note: Email PII olduğu için logging'de dikkat edilmeli
    /// </summary>
    string? Email { get; }

    /// <summary>
    /// Current user tenant ID
    /// Multi-tenancy için kritik bilgi
    /// 
    /// Usage:
    /// - Data isolation (tenant-specific filtering)
    /// - Cross-tenant access prevention
    /// - Business rules (tenant-specific logic)
    /// - Resource access validation
    /// 
    /// Security: Bu değer her request'te validate edilmeli
    /// </summary>
    Guid? TenantId { get; }

    #endregion

    #region Personal Information

    /// <summary>
    /// Current user first name
    /// UI personalization için kullanılır
    /// 
    /// Usage:
    /// - Welcome messages: "Hello, John!"
    /// - User profile display
    /// - Personalized communications
    /// - UI header/navigation personalization
    /// 
    /// Privacy note: İsim bilgisi PII, dikkatli handle edilmeli
    /// </summary>
    string? FirstName { get; }

    /// <summary>
    /// Current user last name
    /// Full name construction için kullanılır
    /// 
    /// Usage:
    /// - Formal communication contexts
    /// - Full name display requirements
    /// - Professional identification
    /// - Sorting/grouping operations
    /// </summary>
    string? LastName { get; }

    /// <summary>
    /// Full name computed property
    /// FirstName ve LastName'i intelligent şekilde birleştirir
    /// 
    /// Logic:
    /// - Both names available: "John Doe"
    /// - Only FirstName: "John"
    /// - Only LastName: "Doe"
    /// - Neither: null
    /// 
    /// Usage:
    /// - UI display (user cards, headers)
    /// - Formal communications
    /// - Reports ve documents
    /// </summary>
    string? FullName { get; }

    /// <summary>
    /// Display name optimized for UI
    /// En uygun user representation'ı döndürür
    /// 
    /// Priority:
    /// 1. FullName (if available)
    /// 2. Email (if no name)
    /// 3. "User" (ultimate fallback)
    /// 
    /// Usage:
    /// - UI components (navbar, cards)
    /// - Generic user display
    /// - Fallback identification
    /// </summary>
    string DisplayName { get; }

    #endregion

    #region Account Status

    /// <summary>
    /// User authentication durumu
    /// Request context'teki authentication state'ini yansıtır
    /// 
    /// Authentication check:
    /// 1. HTTP context exists
    /// 2. User principal exists
    /// 3. Identity is authenticated
    /// 4. Valid user claims exist
    /// 
    /// Returns false for:
    /// - Background operations
    /// - System/service accounts
    /// - Invalid/expired tokens
    /// - Missing authentication claims
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Email confirmation status
    /// JWT token'daki email_confirmed claim'inden gelir
    /// 
    /// Business rules:
    /// - Unconfirmed users may have limited access
    /// - Security operations may require confirmed email
    /// - Feature access may be gated by confirmation
    /// 
    /// Usage:
    /// - Conditional feature access
    /// - Security operation validation
    /// - User onboarding flow
    /// - Email verification prompts
    /// </summary>
    bool EmailConfirmed { get; }

    #endregion

    #region Authorization Information

    /// <summary>
    /// Current user'ın role'leri
    /// JWT token'daki role claim'lerinden alınır
    /// 
    /// Role-based authorization:
    /// - Controller/Action level authorization
    /// - UI conditional rendering
    /// - Feature flagging
    /// - Navigation customization
    /// 
    /// Performance: Collection cached for request duration
    /// Security: Roles validated at token level
    /// </summary>
    IEnumerable<string> Roles { get; }

    /// <summary>
    /// Current user'ın permission'ları
    /// JWT token'daki permission claim'lerinden alınır
    /// 
    /// Fine-grained authorization:
    /// - API endpoint level authorization
    /// - Feature-specific access control
    /// - Data-level security
    /// - UI element-level permissions
    /// 
    /// Design: Capability-based security model
    /// Examples: "CanReadUsers", "CanEditProfile", "CanDeleteData"
    /// </summary>
    IEnumerable<string> Permissions { get; }

    #endregion

    #region Multi-Tenancy Support

    /// <summary>
    /// Current user'ın tenant'ına ait olup olmadığını kontrol eder
    /// Cross-tenant security validation için kritik
    /// 
    /// Validation logic:
    /// 1. User authenticated mi kontrol et
    /// 2. User'ın tenant claim'i var mı kontrol et
    /// 3. Claim'deki tenant ID requested tenant ile match ediyor mu
    /// 
    /// Security implications:
    /// - Data leakage prevention
    /// - Authorization boundary enforcement
    /// - Audit trail for cross-tenant attempts
    /// 
    /// Usage:
    /// - Repository queries (automatic tenant filtering)
    /// - API authorization middleware
    /// - Business rule validation
    /// </summary>
    /// <param name="tenantId">Kontrol edilecek tenant ID</param>
    /// <returns>User bu tenant'a aitse true</returns>
    bool BelongsToTenant(Guid tenantId);

    #endregion

    #region Authorization Utilities

    /// <summary>
    /// Role check utility
    /// Specific bir role'ün varlığını kontrol eder
    /// 
    /// Case-insensitive comparison yapılır.
    /// Role hierarchy veya inheritance desteklenmez (basit check).
    /// 
    /// Usage:
    /// - Business logic'te conditional operations
    /// - Custom authorization attributes
    /// - UI conditional rendering
    /// 
    /// Alternative: ASP.NET Core [Authorize(Roles = "Admin")] kullanılabilir
    /// </summary>
    /// <param name="roleName">Kontrol edilecek role adı</param>
    /// <returns>Role varsa true</returns>
    bool HasRole(string roleName);

    /// <summary>
    /// Permission check utility
    /// Specific bir permission'ın varlığını kontrol eder
    /// 
    /// Permission-based access control (PBAC) için core method.
    /// Case-insensitive comparison yapılır.
    /// 
    /// Usage:
    /// - Fine-grained authorization checks
    /// - Business logic guards
    /// - API endpoint authorization
    /// - UI feature toggles
    /// 
    /// Design pattern: Guard clauses in business methods
    /// Example: if (!currentUser.HasPermission("CanEditUsers")) throw...
    /// </summary>
    /// <param name="permissionName">Kontrol edilecek permission adı</param>
    /// <returns>Permission varsa true</returns>
    bool HasPermission(string permissionName);

    /// <summary>
    /// Admin role check utility
    /// Admin-level access kontrolü için convenience method
    /// 
    /// Admin roles: "Admin", "Administrator", "SuperAdmin"
    /// Case-insensitive comparison yapılır.
    /// 
    /// Usage:
    /// - Administrative operation guards
    /// - UI admin panel access
    /// - System-level authorization
    /// - Override permission checks
    /// 
    /// Business rule: Admin role'ü typically all permissions'ı imply eder
    /// </summary>
    /// <returns>User admin ise true</returns>
    bool IsAdmin();

    /// <summary>
    /// Multiple role check utility
    /// Verilen role'lerden herhangi birine sahip mi kontrol eder
    /// 
    /// OR logic: Roles'lerden biri varsa true döner
    /// Empty/null array için false döner
    /// 
    /// Usage:
    /// - Multiple role authorization
    /// - Flexible access control
    /// - Role group checking
    /// 
    /// Example: HasAnyRole("Admin", "Manager", "Supervisor")
    /// </summary>
    /// <param name="roleNames">Kontrol edilecek role adları</param>
    /// <returns>Herhangi bir role varsa true</returns>
    bool HasAnyRole(params string[] roleNames);

    /// <summary>
    /// Multiple permission check utility
    /// Verilen permission'lardan herhangi birine sahip mi kontrol eder
    /// 
    /// OR logic: Permission'lardan biri varsa true döner
    /// Empty/null array için false döner
    /// 
    /// Usage:
    /// - Alternative permission checking
    /// - Flexible authorization
    /// - Permission group validation
    /// 
    /// Example: HasAnyPermission("CanReadUsers", "CanListUsers", "CanViewUsers")
    /// </summary>
    /// <param name="permissionNames">Kontrol edilecek permission adları</param>
    /// <returns>Herhangi bir permission varsa true</returns>
    bool HasAnyPermission(params string[] permissionNames);

    /// <summary>
    /// All permissions check utility
    /// Verilen tüm permission'lara sahip mi kontrol eder
    /// 
    /// AND logic: Tüm permission'lar varsa true döner
    /// Empty/null array için true döner (vacuous truth)
    /// 
    /// Usage:
    /// - Strict authorization requirements
    /// - Complex permission combinations
    /// - Multi-step operation validation
    /// 
    /// Example: HasAllPermissions("CanReadUsers", "CanEditUsers") 
    /// // Both permissions required
    /// </summary>
    /// <param name="permissionNames">Kontrol edilecek permission adları</param>
    /// <returns>Tüm permission'lar varsa true</returns>
    bool HasAllPermissions(params string[] permissionNames);

    #endregion
}