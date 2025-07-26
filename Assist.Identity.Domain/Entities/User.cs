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
    /// </summary>
    /// <returns>Role isimleri</returns>
    public IEnumerable<string> GetRoleNames()
    {
        return UserRoles
            .Where(ur => ur.Role.IsActive)
            .Select(ur => ur.Role.Name);
    }

    /// <summary>
    /// User'ın sahip olduğu permission'ları getir
    /// </summary>
    /// <returns>Permission isimleri</returns>
    public IEnumerable<string> GetPermissions()
    {
        return UserRoles
            .Where(ur => ur.Role.IsActive)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct();
    }

    /// <summary>
    /// Specific permission kontrolü
    /// </summary>
    /// <param name="permissionName">Permission adı</param>
    /// <returns>Permission varsa true</returns>
    public bool HasPermission(string permissionName)
    {
        return GetPermissions().Contains(permissionName);
    }

    /// <summary>
    /// Specific role kontrolü
    /// </summary>
    /// <param name="roleName">Role adı</param>
    /// <returns>Role varsa true</returns>
    public bool HasRole(string roleName)
    {
        return GetRoleNames().Contains(roleName);
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