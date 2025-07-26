

using Assist.Identity.Domain.Events;

/// <summary>
/// User Created Domain Event
/// Bir user oluşturulduğunda fırlatılır
/// ERP integration, welcome email, audit log gibi side effect'ler için kullanılır
/// </summary>
public sealed class UserCreatedEvent : BaseDomainEvent
{
    /// <summary>
    /// UserCreatedEvent constructor
    /// </summary>
    /// <param name="userId">Oluşturulan user'ın ID'si</param>
    /// <param name="email">User'ın email adresi</param>
    /// <param name="firstName">User'ın adı</param>
    /// <param name="lastName">User'ın soyadı</param>
    /// <param name="tenantId">Tenant ID'si</param>
    /// <param name="phoneNumber">User'ın telefon numarası (opsiyonel)</param>
    /// <param name="assignedRoles">User'a atanan role'ler</param>
    public UserCreatedEvent(
        Guid userId,
        string? email,
        string? firstName,
        string? lastName,
        Guid tenantId,
        string? phoneNumber = null,
        IEnumerable<string>? assignedRoles = null) : base(tenantId)
    {
        UserId = userId;
        Email = email ?? throw new ArgumentNullException(nameof(email));
        FirstName = firstName ?? throw new ArgumentNullException(nameof(firstName));
        LastName = lastName ?? throw new ArgumentNullException(nameof(lastName));
        PhoneNumber = phoneNumber;
        AssignedRoles = assignedRoles?.ToList() ?? new List<string>();
    }

    /// <summary>
    /// Oluşturulan user'ın ID'si
    /// </summary>
    public Guid UserId { get; }

    /// <summary>
    /// User'ın email adresi
    /// Welcome email gönderimi için kullanılır
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// User'ın adı
    /// Personalization için kullanılır
    /// </summary>
    public string FirstName { get; }

    /// <summary>
    /// User'ın soyadı
    /// </summary>
    public string LastName { get; }

    /// <summary>
    /// User'ın telefon numarası (opsiyonel)
    /// SMS notification için kullanılabilir
    /// </summary>
    public string? PhoneNumber { get; }

    /// <summary>
    /// User'a atanan role'ler
    /// ERP'de yetkilendirme için kullanılabilir
    /// </summary>
    public IReadOnlyList<string> AssignedRoles { get; }

    /// <summary>
    /// Full name property - Convenience method
    /// </summary>
    public string FullName => $"{FirstName} {LastName}";

    /// <summary>
    /// Event has phone number check
    /// Conditional processing için kullanılır
    /// </summary>
    public bool HasPhoneNumber => !string.IsNullOrWhiteSpace(PhoneNumber);

    /// <summary>
    /// Event has roles check
    /// </summary>
    public bool HasAssignedRoles => AssignedRoles.Any();
}