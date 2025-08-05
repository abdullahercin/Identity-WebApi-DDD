using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Persistence.Configurations;

/// <summary>
/// RolePermission Join Table Configuration for EF Core
/// 
/// Bu configuration Many-to-Many join table için tasarlanmıştır.
/// RolePermission, Role ve Permission arasındaki ilişkiyi temsil eder.
/// 
/// Learning Focus:
/// 1. Composite primary key configuration (RoleId + PermissionId)
/// 2. Join table best practices
/// 3. Foreign key relationships from join table perspective
/// 4. Join table indexing strategies
/// </summary>
public class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    public void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        ConfigureTable(builder);
        ConfigureKeys(builder);
        ConfigureProperties(builder);
        ConfigureNavigationProperties(builder);
        ConfigureIndexes(builder);
    }

    /// <summary>
    /// Table configuration
    /// </summary>
    private static void ConfigureTable(EntityTypeBuilder<RolePermission> builder)
    {
        builder.ToTable("RolePermissions");
    }

    /// <summary>
    /// Composite primary key configuration
    /// RoleId + PermissionId birlikte unique olmalı
    /// </summary>
    private static void ConfigureKeys(EntityTypeBuilder<RolePermission> builder)
    {
        // Composite primary key - RoleId + PermissionId
        builder.HasKey(rp => new { rp.RoleId, rp.PermissionId });
    }

    /// <summary>
    /// Properties configuration
    /// Join table'da sadece foreign key'ler var
    /// </summary>
    private static void ConfigureProperties(EntityTypeBuilder<RolePermission> builder)
    {
        builder.Property(rp => rp.RoleId)
            .IsRequired();

        builder.Property(rp => rp.PermissionId)
            .IsRequired();
    }

    /// <summary>
    /// Navigation properties configuration
    /// Join table'dan parent entity'lere referanslar
    /// </summary>
    private static void ConfigureNavigationProperties(EntityTypeBuilder<RolePermission> builder)
    {
        // Role relationship
        builder.HasOne(rp => rp.Role)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.RoleId)
            .OnDelete(DeleteBehavior.Cascade);

        // Permission relationship
        builder.HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionId)
            .OnDelete(DeleteBehavior.Cascade);
    }

    /// <summary>
    /// Indexes configuration
    /// Join table için performance optimization
    /// </summary>
    private static void ConfigureIndexes(EntityTypeBuilder<RolePermission> builder)
    {
        // RoleId index - "Bu role'ün tüm permission'larını getir" query'si için
        builder.HasIndex(rp => rp.RoleId)
            .HasDatabaseName("IX_RolePermissions_RoleId");

        // PermissionId index - "Bu permission'a sahip tüm role'leri getir" query'si için
        builder.HasIndex(rp => rp.PermissionId)
            .HasDatabaseName("IX_RolePermissions_PermissionId");
    }
}