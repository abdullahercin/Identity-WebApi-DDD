using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Persistence.Configurations;

/// <summary>
/// UserRole Join Table Configuration for EF Core
/// 
/// Bu configuration Many-to-Many join table için tasarlanmıştır.
/// UserRole, User ve Role arasındaki ilişkiyi temsil eder.
/// 
/// Learning Focus:
/// 1. Composite primary key configuration (UserId + RoleId)
/// 2. Join table with additional properties (AssignedAt)
/// 3. Audit trail in join tables
/// 4. Performance indexing for user-role queries
/// </summary>
public class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> builder)
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
    private static void ConfigureTable(EntityTypeBuilder<UserRole> builder)
    {
        builder.ToTable("UserRoles");
    }

    /// <summary>
    /// Composite primary key configuration
    /// UserId + RoleId birlikte unique olmalı
    /// </summary>
    private static void ConfigureKeys(EntityTypeBuilder<UserRole> builder)
    {
        // Composite primary key - UserId + RoleId
        builder.HasKey(ur => new { ur.UserId, ur.RoleId });
    }

    /// <summary>
    /// Properties configuration
    /// Join table foreign key'leri + additional audit property
    /// </summary>
    private static void ConfigureProperties(EntityTypeBuilder<UserRole> builder)
    {
        builder.Property(ur => ur.UserId)
            .IsRequired();

        builder.Property(ur => ur.RoleId)
            .IsRequired();

        // Additional property - Role atanma zamanı
        builder.Property(ur => ur.AssignedAt)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()"); // SQL Server için, SQLite için "datetime('now')" kullanın
    }

    /// <summary>
    /// Navigation properties configuration
    /// Join table'dan parent entity'lere referanslar
    /// </summary>
    private static void ConfigureNavigationProperties(EntityTypeBuilder<UserRole> builder)
    {
        // User relationship
        builder.HasOne(ur => ur.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        // Role relationship
        builder.HasOne(ur => ur.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ur => ur.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }

    /// <summary>
    /// Indexes configuration
    /// Join table için performance optimization
    /// </summary>
    private static void ConfigureIndexes(EntityTypeBuilder<UserRole> builder)
    {
        // UserId index - "Bu user'ın tüm role'lerini getir" query'si için
        builder.HasIndex(ur => ur.UserId)
            .HasDatabaseName("IX_UserRoles_UserId");

        // RoleId index - "Bu role'e sahip tüm user'ları getir" query'si için
        builder.HasIndex(ur => ur.RoleId)
            .HasDatabaseName("IX_UserRoles_RoleId");

        // AssignedAt index - Audit queries için
        builder.HasIndex(ur => ur.AssignedAt)
            .HasDatabaseName("IX_UserRoles_AssignedAt");
    }
}