using Assist.Identity.Domain.Common;
using Assist.Identity.Domain.Events;

namespace Assist.Identity.Domain.Entities;

/// <summary>
/// User Aggregate Root
/// Identity domain'inin ana entity'si
/// Tüm user-related business logic'i burada bulunur
/// </summary>
public class User : BaseEntity
{
    // Private constructor - Entity Framework için
    private User() { }

    /// <summary>
    /// User oluşturma constructor
    /// Private olarak tanımlanmış, sadece static factory method'lardan çağrılabilir
    /// </summary>
    private User(Email email, Password password, string firstName, string lastName, PhoneNumber phoneNumber = null)
    {
        Email = email ?? throw new ArgumentNullException(nameof(email));
        Password = password ?? throw new ArgumentNullException(nameof(password));
        FirstName = firstName ?? throw new ArgumentNullException(nameof(firstName));
        LastName = lastName ?? throw new ArgumentNullException(nameof(lastName));
        PhoneNumber = phoneNumber;
        
        // Default values
        IsActive = true;
        EmailConfirmed = false;
        LastLoginAt = null;
        FailedLoginAttempts = 0;
        LockedUntil = null;
        
        // Navigation properties initialization
        UserRoles = new HashSet<UserRole>();
        RefreshTokens = new HashSet<RefreshToken>();
    }

    #region Properties

    /// <summary>
    /// Email value object - Domain'de email validation guarantee edilir
    /// </summary>
    public Email Email { get; private set; }

    /// <summary>
    /// Password value object - Domain'de password strength guarantee edilir
    /// </summary>
    public Password Password { get; private set; }

    /// <summary>
    /// User'ın adı
    /// </summary>
    public string FirstName { get; private set; }

    /// <summary>
    /// User'ın soyadı
    /// </summary>
    public string LastName { get; private set; }

    /// <summary>
    /// Telefon numarası - Optional
    /// </summary>
    public PhoneNumber PhoneNumber { get; private set; }

    /// <summary>
    /// User aktif mi - Business rule: Deaktif user'lar login olamaz
    /// </summary>
    public bool IsActive { get; private set; }

    /// <summary>
    /// Email doğrulanmış mı - Business rule: Email doğrulanmadan bazı işlemler yapılamaz
    /// </summary>
    public bool EmailConfirmed { get; private set; }

    /// <summary>
    /// Son login zamanı - Analytics ve security için
    /// </summary>
    public DateTime? LastLoginAt { get; private set; }

    /// <summary>
    /// Başarısız login deneme sayısı - Account lockout için
    /// </summary>
    public int FailedLoginAttempts { get; private set; }

    /// <summary>
    /// Account lock süresi - Security measure
    /// </summary>
    public DateTime? LockedUntil { get; private set; }

    #endregion

    #region Navigation Properties

    /// <summary>
    /// User'ın sahip olduğu role'ler - Many-to-many relationship
    /// </summary>
    public virtual ICollection<UserRole> UserRoles { get; private set; }

    /// <summary>
    /// User'ın refresh token'ları - One-to-many relationship
    /// </summary>
    public virtual ICollection<RefreshToken> RefreshTokens { get; private set; }

    #endregion

    #region Factory Methods

    /// <summary>
    /// Yeni user oluşturma - Static factory method
    /// Business rules burada enforce edilir
    /// </summary>
    /// <param name="email">Email adresi</param>
    /// <param name="password">Password</param>
    /// <param name="firstName">Ad</param>
    /// <param name="lastName">Soyad</param>
    /// <param name="phoneNumber">Telefon numarası (opsiyonel)</param>
    /// <returns>Yeni User entity'si</returns>
    public static User Create(string email, string password, string firstName, string lastName, string phoneNumber = null)
    {
        // Value objects oluşturma - Validation burada yapılır
        var emailVO = Email.Create(email);
        var passwordVO = Password.Create(password);
        var phoneVO = !string.IsNullOrWhiteSpace(phoneNumber) ? PhoneNumber.Create(phoneNumber) : null;
        
        // Business rule validation
        ValidateUserCreation(firstName, lastName);
        
        // User entity oluşturma
        var user = new User(emailVO, passwordVO, firstName.Trim(), lastName.Trim(), phoneVO);
        
        // Domain event - User oluşturuldu
        user.AddDomainEvent(new UserCreatedEvent(
            user.Id,
            user.Email.Value,
            user.FirstName,
            user.LastName,
            user.TenantId,
            user.PhoneNumber?.Value));
        
        return user;
    }

    #endregion

    #region Business Methods

    /// <summary>
    /// Login işlemi - Business rules enforce edilir
    /// </summary>
    /// <param name="password">Plain text password</param>
    /// <param name="ipAddress">Login IP adresi (opsiyonel)</param>
    /// <param name="userAgent">Browser bilgisi (opsiyonel)</param>
    /// <exception cref="InvalidOperationException">Login business rules ihlal edilirse</exception>
    public void Login(string password, string ipAddress = null, string userAgent = null)
    {
        // Business rule: User aktif olmalı
        if (!IsActive)
            throw new InvalidOperationException("User account is not active.");

        // Business rule: Account lock kontrolü
        if (IsLockedOut())
            throw new InvalidOperationException($"Account is locked until {LockedUntil:yyyy-MM-dd HH:mm}.");

        // Business rule: Email confirmation kontrolü (opsiyonel - config'e bağlı)
        // if (!EmailConfirmed)
        //     throw new InvalidOperationException("Email address must be confirmed before login.");

        // Password doğrulama
        if (!Password.Verify(password))
        {
            // Failed login attempt
            RecordFailedLoginAttempt();
            throw new InvalidOperationException("Invalid password.");
        }

        // Successful login
        ResetFailedLoginAttempts();
        LastLoginAt = DateTime.UtcNow;

        // Domain event - User login oldu
        AddDomainEvent(new UserLoggedInEvent(
            Id,
            Email.Value,
            TenantId,
            ipAddress,
            userAgent,
            LastLoginAt.Value));
    }

    /// <summary>
    /// Password değiştirme - Clean approach
    /// Password validation Application layer'da yapılır
    /// Domain sadece assignment ve event'i handle eder
    /// </summary>
    /// <param name="newPassword">Yeni password (plain text)</param>
    /// <param name="changedBy">Değişikliği yapan user (opsiyonel)</param>
    public void ChangePassword(string newPassword, string changedBy = null)
    {
        // Business rule: Yeni password valid olmalı (Value Object validation)
        var newPasswordVO = Password.Create(newPassword);
        Password = newPasswordVO;

        // Domain event - Password değiştirildi
        AddDomainEvent(new PasswordChangedEvent(
            Id,
            Email.Value,
            TenantId,
            changedBy));
    }

    /// <summary>
    /// Email confirmation
    /// </summary>
    public void ConfirmEmail()
    {
        if (EmailConfirmed)
            throw new InvalidOperationException("Email is already confirmed.");

        EmailConfirmed = true;
    }

    /// <summary>
    /// User'ı deaktive etme
    /// </summary>
    /// <param name="deactivatedBy">Deaktive eden user</param>
    /// <param name="reason">Deaktive etme nedeni</param>
    public void Deactivate(string deactivatedBy = null, string reason = null)
    {
        if (!IsActive)
            throw new InvalidOperationException("User is already deactivated.");

        IsActive = false;

        // Tüm refresh token'ları geçersiz kıl
        foreach (var refreshToken in RefreshTokens.Where(rt => rt.IsActive))
        {
            refreshToken.Revoke();
        }

        // Domain event - User deaktive edildi
        AddDomainEvent(new UserDeactivatedEvent(
            Id,
            Email.Value,
            TenantId,
            deactivatedBy,
            reason));
    }

    /// <summary>
    /// User'ı yeniden aktive etme
    /// </summary>
    public void Reactivate()
    {
        if (IsActive)
            throw new InvalidOperationException("User is already active.");

        IsActive = true;
        ResetFailedLoginAttempts(); // Lock'u da kaldır
    }

    /// <summary>
    /// Role atama
    /// </summary>
    /// <param name="role">Atanacak role</param>
    /// <param name="assignedBy">Atamasını yapan user</param>
    public void AssignRole(Role role, string assignedBy = null)
    {
        if (role == null)
            throw new ArgumentNullException(nameof(role));

        // Business rule: Aynı role zaten atanmış mı kontrol et
        if (UserRoles.Any(ur => ur.RoleId == role.Id))
            return; // Zaten atanmış, işlem gereksiz

        // Role atama
        var userRole = new UserRole(Id, role.Id);
        UserRoles.Add(userRole);

        // Domain event - Role atandı
        AddDomainEvent(new RoleAssignedEvent(
            Id,
            Email.Value,
            role.Id,
            role.Name,
            TenantId,
            assignedBy,
            role.GetPermissionNames()));
    }

    /// <summary>
    /// Role kaldırma
    /// </summary>
    /// <param name="role">Kaldırılacak role</param>
    public void RemoveRole(Role role)
    {
        if (role == null)
            throw new ArgumentNullException(nameof(role));

        var userRole = UserRoles.FirstOrDefault(ur => ur.RoleId == role.Id);
        if (userRole != null)
        {
            UserRoles.Remove(userRole);
        }
    }

    #endregion

    #region Query Methods
    
    /// <summary>
    /// User'ın sahip olduğu role adlarını getir
    /// 
    /// JWT token generation sırasında kullanılır.
    /// Domain-driven approach: Business logic domain layer'da kalır.
    /// 
    /// Navigation path: User -> UserRoles -> Role -> Role.Name
    /// 
    /// Performance Note: 
    /// Bu method EF Core tarafından lazy loading ile çağrılabilir.
    /// Bulk operations için repository'de Include() ile eager loading yapılmalı.
    /// 
    /// Business Rules:
    /// - Sadece aktif role'ler döndürülür (IsActive = true)
    /// - Role adları distinct olarak döndürülür (theoretically impossible duplicate ama safety için)
    /// - Empty collection döndürülebilir (user'ın hiç role'ü yoksa)
    /// </summary>
    /// <returns>User'ın sahip olduğu aktif role adları</returns>
    public IEnumerable<string> GetRoleNames()
    {
        return UserRoles
            .Where(ur => ur.Role != null && ur.Role.IsActive) // Safety check + business rule
            .Select(ur => ur.Role.Name)
            .Where(name => !string.IsNullOrEmpty(name))       // Additional safety
            .Distinct()                                       // Ensure uniqueness
            .ToList();                                        // Materialize to avoid multiple enumeration
    }

    /// <summary>
    /// User'ın sahip olduğu tüm permission'ları getir
    /// 
    /// JWT token generation ve authorization sırasında kullanılır.
    /// Complex navigation path ile tüm permissions'ları aggregate eder.
    /// 
    /// Navigation path: 
    /// User -> UserRoles -> Role -> RolePermissions -> Permission -> Permission.Name
    /// 
    /// Business Logic:
    /// 1. User'ın tüm aktif role'lerini al
    /// 2. Her role'ün permission'larını al
    /// 3. Duplicate permission'ları kaldır
    /// 4. Permission adlarını döndür
    /// 
    /// Performance Considerations:
    /// - Bu method potentially expensive olabilir (multiple joins)
    /// - Production'da caching consideration yapılmalı
    /// - Repository'de Include() ile eager loading önemli
    /// 
    /// Security Note:
    /// Permission checking'de bu method kullanılır, doğru olması kritik.
    /// </summary>
    /// <returns>User'ın sahip olduğu tüm permission adları</returns>
    public IEnumerable<string> GetPermissions()
    {
        return UserRoles
            .Where(ur => ur.Role != null && ur.Role.IsActive)    // Sadece aktif role'ler
            .SelectMany(ur => ur.Role.RolePermissions)           // Her role'ün permission'ları
            .Where(rp => rp.Permission != null)                  // Safety check
            .Select(rp => rp.Permission.Name)                    // Permission adlarını al
            .Where(name => !string.IsNullOrEmpty(name))          // Null/empty check
            .Distinct()                                          // Duplicate elimination
            .ToList();                                           // Materialize
    }

    /// <summary>
    /// User'ın specific bir permission'a sahip olup olmadığını kontrol et
    /// 
    /// Authorization pipeline'da sık kullanılır.
    /// GetPermissions()'dan daha performant (early termination).
    /// 
    /// Use cases:
    /// - [Authorize] attribute'larda custom authorization
    /// - Business logic'te permission checking
    /// - UI'da conditional rendering
    /// </summary>
    /// <param name="permissionName">Kontrol edilecek permission adı</param>
    /// <returns>Permission varsa true, yoksa false</returns>
    public bool HasPermission(string permissionName)
    {
        if (string.IsNullOrWhiteSpace(permissionName))
            return false;

        return UserRoles
            .Where(ur => ur.Role != null && ur.Role.IsActive)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Any(rp => rp.Permission != null &&
                       rp.Permission.Name.Equals(permissionName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// User'ın specific bir role'e sahip olup olmadığını kontrol et
    /// 
    /// Role-based authorization için kullanılır.
    /// 
    /// Use cases:
    /// - [Authorize(Roles = "Admin")] kontrolü
    /// - Business logic'te role checking
    /// - UI'da role-based conditional rendering
    /// </summary>
    /// <param name="roleName">Kontrol edilecek role adı</param>
    /// <returns>Role varsa true, yoksa false</returns>
    public bool HasRole(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
            return false;

        return UserRoles
            .Any(ur => ur.Role != null &&
                       ur.Role.IsActive &&
                       ur.Role.Name.Equals(roleName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// User'ın herhangi bir admin role'e sahip olup olmadığını kontrol et
    /// 
    /// Admin-level operations için quick check.
    /// Business rule: "Admin" ve "Administrator" role'leri admin olarak kabul edilir.
    /// 
    /// Extensible design: İleride admin role'ler configurable yapılabilir.
    /// </summary>
    /// <returns>User admin ise true</returns>
    public bool IsAdmin()
    {
        var adminRoles = new[] { "Admin", "Administrator", "SuperAdmin" };

        return UserRoles
            .Any(ur => ur.Role != null &&
                       ur.Role.IsActive &&
                       adminRoles.Contains(ur.Role.Name, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// User'ın role ve permission bilgilerinin summary'sini getir
    /// 
    /// Debug, logging ve audit purposes için kullanılır.
    /// Production'da performance overhead olabileceği için dikkatli kullanılmalı.
    /// </summary>
    /// <returns>User'ın authorization summary'si</returns>
    public UserAuthorizationSummary GetAuthorizationSummary()
    {
        var roles = GetRoleNames().ToList();
        var permissions = GetPermissions().ToList();

        return new UserAuthorizationSummary
        {
            UserId = Id,
            Email = Email?.Value ?? "Unknown",
            RoleCount = roles.Count,
            PermissionCount = permissions.Count,
            Roles = roles,
            Permissions = permissions,
            IsAdmin = IsAdmin(),
            HasAnyRole = roles.Any(),
            HasAnyPermission = permissions.Any()
        };
    }

    /// <summary>
    /// Account lock durumu kontrolü
    /// </summary>
    /// <returns>Lock'luysa true</returns>
    public bool IsLockedOut()
    {
        return LockedUntil.HasValue && LockedUntil.Value > DateTime.UtcNow;
    }

    /// <summary>
    /// Full name property
    /// </summary>
    public string FullName => $"{FirstName} {LastName}";

    // Supporting DTO class - Application/Models klasörüne konulacak
    /// <summary>
    /// User Authorization Summary DTO
    /// Debug ve monitoring purposes için kullanılır
    /// </summary>
    public class UserAuthorizationSummary
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public int RoleCount { get; set; }
        public int PermissionCount { get; set; }
        public List<string> Roles { get; set; } = new();
        public List<string> Permissions { get; set; } = new();
        public bool IsAdmin { get; set; }
        public bool HasAnyRole { get; set; }
        public bool HasAnyPermission { get; set; }
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// Failed login attempt kaydı
    /// </summary>
    private void RecordFailedLoginAttempt()
    {
        FailedLoginAttempts++;

        // Business rule: 5 başarısız denemeden sonra 15 dakika lock
        if (FailedLoginAttempts >= 5)
        {
            LockedUntil = DateTime.UtcNow.AddMinutes(15);
        }
    }

    /// <summary>
    /// Failed login attempt'leri reset et
    /// </summary>
    private void ResetFailedLoginAttempts()
    {
        FailedLoginAttempts = 0;
        LockedUntil = null;
    }

    /// <summary>
    /// User creation validation
    /// </summary>
    private static void ValidateUserCreation(string firstName, string lastName)
    {
        if (string.IsNullOrWhiteSpace(firstName))
            throw new ArgumentException("First name cannot be empty.", nameof(firstName));

        if (string.IsNullOrWhiteSpace(lastName))
            throw new ArgumentException("Last name cannot be empty.", nameof(lastName));

        if (firstName.Length > 50)
            throw new ArgumentException("First name cannot exceed 50 characters.", nameof(firstName));

        if (lastName.Length > 50)
            throw new ArgumentException("Last name cannot exceed 50 characters.", nameof(lastName));
    }

    #endregion
}