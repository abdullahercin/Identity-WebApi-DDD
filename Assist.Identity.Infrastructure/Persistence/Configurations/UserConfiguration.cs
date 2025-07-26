using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Persistence.Configurations;

/// <summary>
/// User Entity Configuration for EF Core
/// 
/// Bu class User domain entity'sinin database mapping'ini tanımlar.
/// Basit, anlaşılır ve maintainable approach kullanır.
/// 
/// Odak noktalar:
/// 1. Value Objects'lerin (Email, Password, PhoneNumber) clean mapping'i
/// 2. Essential indexes (TenantId + Email for authentication)
/// 3. Navigation properties'lerin proper relationship configuration'ı
/// 4. Clear ve readable configuration structure
/// </summary>
public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        ConfigureTable(builder);
        ConfigureValueObjects(builder);
        ConfigureProperties(builder);
        ConfigureNavigationProperties(builder);
        ConfigureEssentialIndexes(builder);
    }

    /// <summary>
    /// Table configuration - Simple and clear
    /// </summary>
    private static void ConfigureTable(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("Users");

        // Primary key configuration
        builder.HasKey(u => u.Id);
        builder.Property(u => u.Id)
            .ValueGeneratedNever(); // Domain'de generate ediliyor
    }

    /// <summary>
    /// Value Objects configuration
    /// Domain richness'ını koruyarak database'e map eder
    /// </summary>
    private static void ConfigureValueObjects(EntityTypeBuilder<User> builder)
    {
        // Email Value Object - Authentication için kritik
        builder.OwnsOne(u => u.Email, emailBuilder =>
        {
            emailBuilder.Property(e => e.Value)
                .HasColumnName("Email")
                .HasMaxLength(254)
                .IsRequired();
        });

        // Password Value Object - Security için critical
        builder.OwnsOne(u => u.Password, passwordBuilder =>
        {
            passwordBuilder.Property(p => p.HashedValue)
                .HasColumnName("PasswordHash")
                .HasMaxLength(256)
                .IsRequired();
        });

        // PhoneNumber Value Object - Optional field
        builder.OwnsOne(u => u.PhoneNumber, phoneBuilder =>
        {
            phoneBuilder.Property(p => p.Value)
                .HasColumnName("PhoneNumber")
                .HasMaxLength(20)
                .IsRequired(false);

            phoneBuilder.Property(p => p.CountryCode)
                .HasColumnName("PhoneCountryCode")
                .HasMaxLength(3)
                .IsRequired(false);

            phoneBuilder.Property(p => p.NationalNumber)
                .HasColumnName("PhoneNationalNumber")
                .HasMaxLength(15)
                .IsRequired(false);
        });
    }

    /// <summary>
    /// Regular properties configuration
    /// Basit ve straightforward mapping
    /// </summary>
    private static void ConfigureProperties(EntityTypeBuilder<User> builder)
    {
        // Basic user information
        builder.Property(u => u.FirstName)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.LastName)
            .HasMaxLength(50)
            .IsRequired();

        // Account status - Simple boolean fields
        builder.Property(u => u.IsActive)
            .IsRequired()
            .HasDefaultValue(true);

        builder.Property(u => u.EmailConfirmed)
            .IsRequired()
            .HasDefaultValue(false);

        // Security fields - Basic configuration
        builder.Property(u => u.LastLoginAt)
            .IsRequired(false);

        builder.Property(u => u.FailedLoginAttempts)
            .IsRequired()
            .HasDefaultValue(0);

        builder.Property(u => u.LockedUntil)
            .IsRequired(false);

        // Computed property - Database'de store edilmez
        builder.Ignore(u => u.FullName);
    }

    /// <summary>
    /// Navigation properties configuration
    /// Clear relationship definitions
    /// </summary>
    private static void ConfigureNavigationProperties(EntityTypeBuilder<User> builder)
    {
        // User Roles - Many to Many through UserRole
        builder.HasMany(u => u.UserRoles)
            .WithOne(ur => ur.User)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        // Refresh Tokens - One to Many
        builder.HasMany(u => u.RefreshTokens)
            .WithOne(rt => rt.User)
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }

    /// <summary>
    /// Essential indexes only
    /// Sadece gerçekten gerekli olan performance-critical indexes
    /// </summary>
    private static void ConfigureEssentialIndexes(EntityTypeBuilder<User> builder)
    {
        // Multi-tenant authentication için kritik index
        // Bu olmadan login queries çok yavaş olur
        builder.HasIndex(u => new { u.TenantId, u.Email.Value })
            .HasDatabaseName("IX_Users_TenantId_Email")
            .IsUnique();

        // Tenant filtering için gerekli
        // Tüm user queries bu index'i kullanır
        builder.HasIndex(u => u.TenantId)
            .HasDatabaseName("IX_Users_TenantId");

        // Active user queries için - Frequently used
        builder.HasIndex(u => new { u.TenantId, u.IsActive })
            .HasDatabaseName("IX_Users_TenantId_IsActive");
    }
}