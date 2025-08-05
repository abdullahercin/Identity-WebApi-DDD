using System.ComponentModel.DataAnnotations;

namespace Assist.Identity.Domain.Common;

/// <summary>
/// Base Entity Class
/// Tüm domain entities'lerin inherit edeceği base class
/// Multi-tenancy, audit trail ve domain events support'u sağlar
/// </summary>
public abstract class BaseEntity : ITenantEntity
{
    // Private list for domain events - Encapsulation için
    private readonly List<IDomainEvent> _domainEvents = new();

    /// <summary>
    /// Protected constructor - Sadece derived classes'lar tarafından çağrılabilir
    /// Entity oluşturulurken temel alanları initialize eder
    /// </summary>
    protected BaseEntity()
    {
        Id = Guid.NewGuid();
        CreatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Entity'nin benzersiz tanımlayıcısı
    /// Guid kullanıyoruz çünkü distributed system'lerde collision riski yok
    /// </summary>
    [Key]
    public Guid Id { get; protected set; }

    /// <summary>
    /// Multi-tenancy support - Her entity bir tenant'a ait
    /// Bu field tüm queries'lerde otomatik filter olarak kullanılacak
    /// </summary>
    [Required]
    public Guid TenantId { get; protected set; }

    /// <summary>
    /// Audit Fields - Entity'nin yaşam döngüsünü track eder
    /// Compliance ve debugging için kritik önemde
    /// </summary>
    [Required]
    public DateTime CreatedAt { get; protected set; }

    /// <summary>
    /// Entity'yi oluşturan kullanıcının ID'si
    /// Audit trail için gerekli
    /// </summary>
    [MaxLength(50)]
    public string CreatedBy { get; protected set; } = null!;

    /// <summary>
    /// Son güncellenme zamanı
    /// Null ise entity hiç güncellenmemiş demektir
    /// </summary>
    public DateTime? UpdatedAt { get; protected set; }

    /// <summary>
    /// Son güncelleyen kullanıcının ID'si
    /// Change tracking için gerekli
    /// </summary>
    [MaxLength(50)]
    public string? UpdatedBy { get; protected set; }

    /// <summary>
    /// Domain Events - Read-only collection olarak expose edilir
    /// Entity üzerinde olan business olayları burada tutulur
    /// Infrastructure layer bu events'leri process eder
    /// </summary>
    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    /// <summary>
    /// Tenant context'ini set eder
    /// Entity ilk oluşturulurken Infrastructure layer tarafından çağrılır
    /// Güvenlik nedeniyle sadece bir kez set edilebilir
    /// </summary>
    /// <param name="tenantId">Tenant identifier</param>
    /// <param name="userId">İşlemi yapan kullanıcı ID'si</param>
    /// <exception cref="InvalidOperationException">TenantId zaten set edilmişse</exception>
    public virtual void SetTenantContext(Guid tenantId, string createdBy = "SYSTEM")
    {
        // Güvenlik kontrolü - TenantId bir kez set edildikten sonra değiştirilemez
        if (TenantId != Guid.Empty)
        {
            throw new InvalidOperationException("TenantId can only be set once and cannot be changed.");
        }

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("TenantId cannot be empty.", nameof(tenantId));
        }

        TenantId = tenantId;
        CreatedBy = createdBy; // Default "SYSTEM", user varsa user ID'si
    }

    // Overload - User context'i olan durumlar için
    public virtual void SetTenantContext(Guid tenantId, Guid userId)
    {
        SetTenantContext(tenantId, userId.ToString());
    }

    /// <summary>
    /// Entity modification audit bilgilerini set eder
    /// Infrastructure layer tarafından entity güncellendiğinde çağrılır
    /// 
    /// Bu method mevcut SetTenantContext method'u ile tutarlı design pattern'ı takip eder:
    /// - Sadece Infrastructure layer tarafından çağrılır
    /// - Business logic ile audit concerns'ları ayırır
    /// - Domain entity'nin encapsulation'ını korur
    /// </summary>
    /// <param name="updatedBy">Entity'yi güncelleyen kullanıcının ID'si</param>
    /// <exception cref="ArgumentException">UpdatedBy empty ise</exception>
    public virtual void UpdateAuditInfo(string updatedBy)
    {
        if (string.IsNullOrWhiteSpace(updatedBy))
        {
            throw new ArgumentException("UpdatedBy cannot be empty.", nameof(updatedBy));
        }

        UpdatedAt = DateTime.UtcNow;
        UpdatedBy = updatedBy;
    }

    // Overload - DateTime'ı da parametre olarak alabilmek için
    // Bu overload testing scenarios'lar için yararlı olabilir
    /// <summary>
    /// Entity modification audit bilgilerini belirtilen zaman ile set eder
    /// Testing ve specific timing requirements için kullanılır
    /// </summary>
    /// <param name="updatedBy">Entity'yi güncelleyen kullanıcının ID'si</param>
    /// <param name="updatedAt">Güncelleme zamanı</param>
    public virtual void UpdateAuditInfo(string updatedBy, DateTime updatedAt)
    {
        if (string.IsNullOrWhiteSpace(updatedBy))
        {
            throw new ArgumentException("UpdatedBy cannot be empty.", nameof(updatedBy));
        }

        UpdatedAt = updatedAt;
        UpdatedBy = updatedBy;
    }

    /// <summary>
    /// Domain event ekleme
    /// Protected method - Sadece entity içinden çağrılabilir
    /// Business logic içinde önemli olaylar gerçekleştiğinde kullanılır
    /// </summary>
    /// <param name="domainEvent">Eklenecek domain event</param>
    protected void AddDomainEvent(IDomainEvent domainEvent)
    {
        if (domainEvent == null)
        {
            throw new ArgumentNullException(nameof(domainEvent));
        }

        _domainEvents.Add(domainEvent);
    }

    /// <summary>
    /// Domain events'leri temizle
    /// Infrastructure layer tarafından events process edildikten sonra çağrılır
    /// Memory leak'i önlemek için önemli
    /// </summary>
    public void ClearDomainEvents()
    {
        _domainEvents.Clear();
    }

    /// <summary>
    /// Belirli bir domain event type'ının olup olmadığını kontrol et
    /// Testing ve conditional logic için yararlı
    /// </summary>
    /// <typeparam name="T">Aranacak event type'ı</typeparam>
    /// <returns>Event varsa true, yoksa false</returns>
    public bool HasDomainEvent<T>() where T : IDomainEvent
    {
        return _domainEvents.Any(e => e.GetType() == typeof(T));
    }

    /// <summary>
    /// Entity'nin audit bilgilerini güncelle
    /// Infrastructure layer tarafından SaveChanges sırasında çağrılır
    /// </summary>
    /// <param name="userId">Güncelleyen kullanıcının ID'si</param>
    public virtual void UpdateAuditFields(string userId)
    {
        UpdatedAt = DateTime.UtcNow;
        UpdatedBy = userId;
    }

    /// <summary>
    /// Entity equality comparison
    /// İki entity aynı ID'ye sahipse aynı entity'dir
    /// Bu method EF Core ve collection operations için önemli
    /// </summary>
    public override bool Equals(object? obj)
    {
        if (obj is not BaseEntity other)
            return false;

        if (ReferenceEquals(this, other))
            return true;

        if (GetType() != other.GetType())
            return false;

        // New entities (Id == Guid.Empty) are never equal
        if (Id == Guid.Empty || other.Id == Guid.Empty)
            return false;

        return Id == other.Id;
    }

    /// <summary>
    /// Hash code generation
    /// Entity'nin ID'si üzerinden hash code üretir
    /// Dictionary ve HashSet operations için gerekli
    /// </summary>
    public override int GetHashCode()
    {
        return Id.GetHashCode();
    }

    /// <summary>
    /// Equality operators
    /// == ve != operatorlerini override eder
    /// </summary>
    public static bool operator ==(BaseEntity left, BaseEntity? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(BaseEntity left, BaseEntity right)
    {
        return !Equals(left, right);
    }

    /// <summary>
    /// String representation
    /// Debugging ve logging için yararlı
    /// </summary>
    public override string ToString()
    {
        return $"{GetType().Name} [Id: {Id}]";
    }
    
    
}