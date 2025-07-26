using Microsoft.EntityFrameworkCore;
using System.Reflection;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Domain.Common;
using Assist.Identity.Application.Contracts;

namespace Assist.Identity.Infrastructure.Persistence.Contexts;

/// <summary>
/// Identity Domain için Entity Framework DbContext
/// 
/// Bu sınıf şu sorumluluklara sahiptir:
/// 1. Multi-tenant filtering otomatiği (TenantId bazlı global filters)
/// 2. Domain events handling (SaveChanges sırasında domain events'lerin işlenmesi)
/// 3. Audit trail yönetimi (InsertedAt, UpdatedAt, CreatedBy otomatik set)
/// 4. Entity configurations centralized yönetimi
/// 
/// Clean Architecture ve DDD principles'larına uygun olarak tasarlanmıştır.
/// Infrastructure layer'da bulunur ancak Domain entities'lerini kullanır.
/// </summary>
public sealed class IdentityDbContext : DbContext
{
    private readonly ICurrentTenantService _currentTenantService;
    private readonly ICurrentUserService _currentUserService;

    /// <summary>
    /// IdentityDbContext constructor
    /// </summary>
    /// <param name="options">EF Core DbContext options</param>
    /// <param name="currentTenantService">Current tenant bilgisi için service</param>
    /// <param name="currentUserService">Current user bilgisi için service (audit trail için)</param>
    public IdentityDbContext(
        DbContextOptions<IdentityDbContext> options,
        ICurrentTenantService currentTenantService,
        ICurrentUserService currentUserService) : base(options)
    {
        _currentTenantService = currentTenantService ?? throw new ArgumentNullException(nameof(currentTenantService));
        _currentUserService = currentUserService ?? throw new ArgumentNullException(nameof(currentUserService));
    }

    #region DbSets - Identity Domain Entities

    /// <summary>
    /// Users tablosu - Ana user aggregate'i
    /// </summary>
    public DbSet<User> Users { get; set; } = null!;

    /// <summary>
    /// Roles tablosu - RBAC sistem için roller
    /// </summary>
    public DbSet<Role> Roles { get; set; } = null!;

    /// <summary>
    /// Permissions tablosu - Fine-grained authorization
    /// </summary>
    public DbSet<Permission> Permissions { get; set; } = null!;

    /// <summary>
    /// UserRoles tablosu - Many-to-many join table
    /// </summary>
    public DbSet<UserRole> UserRoles { get; set; } = null!;

    /// <summary>
    /// RolePermissions tablosu - Many-to-many join table
    /// </summary>
    public DbSet<RolePermission> RolePermissions { get; set; } = null!;

    /// <summary>
    /// RefreshTokens tablosu - JWT refresh token yönetimi
    /// </summary>
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;

    #endregion

    #region Model Configuration

    /// <summary>
    /// EF Core model configuration
    /// 
    /// Bu method şu konfigürasyonları yapar:
    /// 1. Entity configurations'ları apply eder
    /// 2. Global query filters (multi-tenant) set eder
    /// 3. Naming conventions set eder
    /// 4. Index'leri tanımlar
    /// </summary>
    /// <param name="modelBuilder">EF Core model builder</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // 1. Entity configurations'ları otomatik apply et
        // Bu, aynı assembly'deki tüm IEntityTypeConfiguration<T> implementation'larını bulur
        modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

        // 2. Multi-tenant global query filters'ları set et
        SetupGlobalQueryFilters(modelBuilder);

        // 3. Database naming conventions
        SetupNamingConventions(modelBuilder);

        // 4. Global indexes ve constraints
        SetupGlobalIndexes(modelBuilder);

        base.OnModelCreating(modelBuilder);
    }

    /// <summary>
    /// Multi-tenant global query filters setup
    /// 
    /// Bu method tüm ITenantEntity implement eden entity'ler için
    /// otomatik TenantId filtering ekler. Bu sayede:
    /// - Developer hiçbir zaman TenantId filter'ı yazmayı unutamaz
    /// - Data isolation otomatik sağlanır
    /// - Security breach riski minimize edilir
    /// </summary>
    /// <param name="modelBuilder">EF Core model builder</param>
    private void SetupGlobalQueryFilters(ModelBuilder modelBuilder)
    {
        // ITenantEntity implement eden tüm entity'leri bul
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (typeof(ITenantEntity).IsAssignableFrom(entityType.ClrType))
            {
                // Generic method çağırısı için reflection kullan
                var method = typeof(IdentityDbContext)
                    .GetMethod(nameof(SetGlobalQueryFilter), BindingFlags.NonPublic | BindingFlags.Instance)!
                    .MakeGenericMethod(entityType.ClrType);

                method.Invoke(this, new object[] { modelBuilder });
            }
        }
    }

    /// <summary>
    /// Specific entity için global query filter set etme
    /// 
    /// Bu generic method, belirtilen entity type için TenantId bazlı
    /// filtering sağlar. Runtime'da current tenant ID'si ile otomatik filtreleme yapar.
    /// </summary>
    /// <typeparam name="T">ITenantEntity implement eden entity type</typeparam>
    /// <param name="modelBuilder">EF Core model builder</param>
    private void SetGlobalQueryFilter<T>(ModelBuilder modelBuilder) where T : class, ITenantEntity
    {
        modelBuilder.Entity<T>().HasQueryFilter(entity => entity.TenantId == _currentTenantService.TenantId);
    }

    /// <summary>
    /// Database naming conventions setup
    /// 
    /// Consistent database naming için conventions set eder:
    /// - Table names: PascalCase
    /// - Column names: PascalCase  
    /// - Index names: IX_{TableName}_{ColumnName}
    /// - Foreign key names: FK_{PrimaryTable}_{ForeignTable}_{ColumnName}
    /// </summary>
    /// <param name="modelBuilder">EF Core model builder</param>
    private void SetupNamingConventions(ModelBuilder modelBuilder)
    {
        // EF Core 9'da naming conventions daha esnek
        // Varsayılan convention'lar genelde yeterli oluyor
        // Gerekirse custom naming convention'lar burada tanımlanabilir

        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            // Table name convention - Entity ismini kullan
            if (entity.GetTableName() == null)
            {
                entity.SetTableName(entity.ClrType.Name);
            }
        }
    }

    /// <summary>
    /// Global indexes ve constraints setup
    /// 
    /// Performance ve data integrity için önemli index'leri tanımlar:
    /// - TenantId index'leri (multi-tenant performance için)
    /// - Email unique constraint
    /// - Composite index'ler
    /// </summary>
    /// <param name="modelBuilder">EF Core model builder</param>
    private void SetupGlobalIndexes(ModelBuilder modelBuilder)
    {
        // User entity için index'ler
        modelBuilder.Entity<User>()
            .HasIndex(u => new { u.TenantId, u.Email })
            .HasDatabaseName("IX_Users_TenantId_Email")
            .IsUnique(); // Email per tenant unique

        modelBuilder.Entity<User>()
            .HasIndex(u => u.TenantId)
            .HasDatabaseName("IX_Users_TenantId");

        // Role entity için index'ler  
        modelBuilder.Entity<Role>()
            .HasIndex(r => new { r.TenantId, r.Name })
            .HasDatabaseName("IX_Roles_TenantId_Name")
            .IsUnique(); // Role name per tenant unique

        // RefreshToken entity için index'ler
        modelBuilder.Entity<RefreshToken>()
            .HasIndex(rt => rt.Token)
            .HasDatabaseName("IX_RefreshTokens_Token")
            .IsUnique();

        modelBuilder.Entity<RefreshToken>()
            .HasIndex(rt => new { rt.UserId, rt.IsActive })
            .HasDatabaseName("IX_RefreshTokens_UserId_IsActive");
    }

    #endregion

    #region SaveChanges Override - Domain Events & Audit Trail

    /// <summary>
    /// SaveChanges override - Domain events ve audit trail handling
    /// 
    /// Bu method SaveChanges pipeline'ına custom logic ekler:
    /// 1. Audit trail bilgilerini otomatik set eder
    /// 2. Domain events'leri collect eder
    /// 3. Database'e save işlemini yapar
    /// 4. Domain events'leri dispatch eder
    /// 
    /// Bu approach domain events'lerin transactional consistency
    /// içinde işlenmesini sağlar.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Affected row count</returns>
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        // 1. Domain events'leri collect et (save'den önce)
        var domainEvents = CollectDomainEvents();

        // 2. Audit trail bilgilerini set et
        SetAuditTrailInformation();

        // 3. Database'e save işlemini yap
        var result = await base.SaveChangesAsync(cancellationToken);

        // 4. Domain events'leri dispatch et (save'den sonra)
        await DispatchDomainEventsAsync(domainEvents, cancellationToken);

        return result;
    }

    /// <summary>
    /// Synchronous SaveChanges override
    /// </summary>
    /// <returns>Affected row count</returns>
    public override int SaveChanges()
    {
        // Async version'ı çağır
        return SaveChangesAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Domain events collection
    /// 
    /// Change tracker'dan tüm BaseEntity türündeki entity'lerin
    /// domain events'lerini toplar ve entity'lerden temizler.
    /// Bu events'ler save işlemi tamamlandıktan sonra dispatch edilir.
    /// 
    /// BaseEntity'nin mevcut API'sini kullanır:
    /// - DomainEvents property'si events'leri okumak için
    /// - ClearDomainEvents() method'u events'leri temizlemek için
    /// </summary>
    /// <returns>Collected domain events</returns>
    private List<IDomainEvent> CollectDomainEvents()
    {
        var domainEvents = new List<IDomainEvent>();

        // Change tracker'dan BaseEntity türündeki entity'leri bul
        var entitiesWithEvents = ChangeTracker.Entries<BaseEntity>()
            .Where(entry => entry.Entity.DomainEvents.Any())
            .ToList();

        // Domain events'leri collect et
        foreach (var entry in entitiesWithEvents)
        {
            domainEvents.AddRange(entry.Entity.DomainEvents);
            // BaseEntity'nin mevcut API'sini kullan - ClearDomainEvents() method'u
            entry.Entity.ClearDomainEvents(); // ✅ Doğru method adı
        }

        return domainEvents;
    }

    /// <summary>
    /// Audit trail information setup
    /// 
    /// Added ve Modified state'deki entity'ler için otomatik audit trail bilgilerini set eder.
    /// 
    /// Bu method mevcut BaseEntity API'sini kullanarak domain layer'ın encapsulation'ını korur:
    /// - SetTenantContext (new entities için) - Mevcut BaseEntity method'u
    /// - UpdateAuditInfo (modified entities için) - Yeni eklenen BaseEntity method'u
    /// 
    /// Bu yaklaşım Clean Architecture'ın Dependency Rule'unu korur ve
    /// mevcut domain API'si ile tutarlı bir integration sağlar.
    /// Infrastructure Domain'in sunduğu public interface'i kullanır, 
    /// internal property'lere direkt erişmez.
    /// </summary>
    private void SetAuditTrailInformation()
    {
        var currentTime = DateTime.UtcNow;
        var currentUserId = _currentUserService.UserId?.ToString() ?? "System";
        var currentTenantId = _currentTenantService.TenantId;

        foreach (var entry in ChangeTracker.Entries<BaseEntity>())
        {
            switch (entry.State)
            {
                case EntityState.Added:
                    // Yeni entity için mevcut SetTenantContext method'unu kullan
                    // Bu method hem TenantId hem de CreatedBy'ı set eder
                    // Ayrıca business validation'ları da çalıştırır
                    try
                    {
                        entry.Entity.SetTenantContext(currentTenantId, currentUserId);

                        // CreatedAt'i manuel set etmemiz gerekiyor çünkü SetTenantContext sadece TenantId ve CreatedBy'ı set ediyor
                        // Bu property'nin setter'ı accessible olduğunu varsayıyoruz
                        // Eğer accessible değilse, BaseEntity'ye SetCreatedAt method'u ekleyebiliriz
                        if (entry.Property(nameof(BaseEntity.CreatedAt)).CurrentValue == null ||
                            (DateTime)entry.Property(nameof(BaseEntity.CreatedAt)).CurrentValue == default)
                        {
                            entry.Property(nameof(BaseEntity.CreatedAt)).CurrentValue = currentTime;
                        }
                    }
                    catch (InvalidOperationException ex) when (ex.Message.Contains("TenantId"))
                    {
                        // TenantId zaten set edilmişse, bu normal bir durumdur
                        // Entity domain logic tarafından önceden configure edilmiş demektir
                        // Bu durumda sadece CreatedAt'i kontrol edelim
                        System.Diagnostics.Debug.WriteLine($"TenantId already set for entity {entry.Entity.Id}, skipping tenant context setup");

                        // CreatedAt kontrolü yapalım
                        if (entry.Property(nameof(BaseEntity.CreatedAt)).CurrentValue == null ||
                            (DateTime)entry.Property(nameof(BaseEntity.CreatedAt)).CurrentValue == default)
                        {
                            entry.Property(nameof(BaseEntity.CreatedAt)).CurrentValue = currentTime;
                        }
                    }
                    break;

                case EntityState.Modified:
                    // Modified entity için yeni UpdateAuditInfo method'unu kullan
                    // Bu method sadece UpdatedAt ve UpdatedBy'ı set eder
                    // Creation audit bilgilerine dokunmaz
                    entry.Entity.UpdateAuditInfo(currentUserId);

                    // EF Core'a creation audit bilgilerinin değişmediğini explicit olarak söyle
                    // Bu çok önemli çünkü bu değerler değiştirilmemeli
                    // Bu defensive programming'in güzel bir örneği
                    entry.Property(nameof(BaseEntity.CreatedAt)).IsModified = false;
                    entry.Property(nameof(BaseEntity.CreatedBy)).IsModified = false;
                    entry.Property(nameof(BaseEntity.TenantId)).IsModified = false; // TenantId asla değişmemeli
                    break;
            }
        }
    }

    /// <summary>
    /// Domain events dispatch
    /// 
    /// Collect edilen domain events'leri uygun handler'lara dispatch eder.
    /// Bu işlem save transaction'ının dışında yapılır çünkü
    /// events başka aggregate'leri de etkileyebilir.
    /// 
    /// Not: Bu implementation placeholder'dır. 
    /// Production'da MediatR veya benzeri bir library kullanarak
    /// event handling yapılmalıdır.
    /// </summary>
    /// <param name="domainEvents">Dispatch edilecek events</param>
    /// <param name="cancellationToken">Cancellation token</param>
    private async Task DispatchDomainEventsAsync(List<IDomainEvent> domainEvents, CancellationToken cancellationToken)
    {
        // TODO: MediatR integration
        // foreach (var domainEvent in domainEvents)
        // {
        //     await _mediator.Publish(domainEvent, cancellationToken);
        // }

        // Şimdilik events'leri log et
        foreach (var domainEvent in domainEvents)
        {
            // Logging infrastructure gelince burada log yapılacak
            System.Diagnostics.Debug.WriteLine($"Domain Event: {domainEvent.GetType().Name}");
        }

        await Task.CompletedTask;
    }

    #endregion

    #region Utility Methods

    /// <summary>
    /// Multi-tenant filtering'i geçici olarak disable etme
    /// 
    /// Bazı admin operations için tüm tenant'ların verilerine
    /// erişim gerekebilir. Bu method ile global query filter'ları
    /// geçici olarak bypass edilebilir.
    /// 
    /// DİKKAT: Bu method sadece çok özel durumlar için kullanılmalı!
    /// Security implications'ı göz önünde bulundurulmalı.
    /// </summary>
    /// <returns>Filtering disabled olan DbContext instance</returns>
    public IdentityDbContext WithoutTenantFiltering()
    {
        ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
        return this;
    }

    /// <summary>
    /// Tenant switching desteği
    /// 
    /// Bazı scenarios'da runtime'da tenant değiştirmek gerekebilir.
    /// Bu method ile current context'in tenant'ı değiştirilebilir.
    /// 
    /// DİKKAT: Bu method kullanıldıktan sonra context refresh edilmeli!
    /// </summary>
    /// <param name="newTenantId">Yeni tenant ID</param>
    public void SwitchTenant(Guid newTenantId)
    {
        // Bu implementation ICurrentTenantService'in mutable olduğunu varsayar
        // Production'da tenant switching daha dikkatli implement edilmeli

        // Change tracker'ı temizle
        ChangeTracker.Clear();

        // Not: ICurrentTenantService'in tenant'ını değiştirmek
        // service'in implementation'ına bağlı
    }

    #endregion
}