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

    private static void ConfigureTable(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("Users");
        builder.HasKey(u => u.Id);
        builder.Property(u => u.Id).ValueGeneratedNever();
    }

    /// <summary>
    /// Value Objects configuration - HasConversion Approach
    /// 
    /// OwnsOne yerine HasConversion kullanıyoruz:
    /// - Value Object korunur (Domain zenginliği)
    /// - EF Core mapping basitleşir (OwnsOne karmaşıklığı yok)
    /// - Property conflict'i engellenir
    /// </summary>
    private static void ConfigureValueObjects(EntityTypeBuilder<User> builder)
    {
        // EMAIL VALUE OBJECT - HasConversion ile
        builder.Property(u => u.Email)
            .HasConversion(
                email => email.Value,           // Domain → Database (Email → string)
                value => Email.Create(value)    // Database → Domain (string → Email)
            )
            .HasColumnName("Email")
            .HasMaxLength(254)
            .IsRequired();

        // PASSWORD VALUE OBJECT - Aynı yaklaşım
        builder.Property(u => u.Password)
            .HasConversion(
                password => password.HashedValue,           // Domain → Database
                value => Password.FromHash(value)     // Database → Domain
            )
            .HasColumnName("PasswordHash")
            .HasMaxLength(256)
            .IsRequired();

        // PHONE NUMBER VALUE OBJECT - Null-safe conversion
        builder.Property(u => u.PhoneNumber)
            .HasConversion(
                phone => phone != null ? phone.Value : null,                    // Domain → Database
                value => !string.IsNullOrEmpty(value) ? PhoneNumber.Create(value) : null  // Database → Domain
            )
            .HasColumnName("PhoneNumber")
            .HasMaxLength(20)
            .IsRequired(false);
    }

    private static void ConfigureProperties(EntityTypeBuilder<User> builder)
    {
        builder.Property(u => u.FirstName)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.LastName)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.IsActive)
            .IsRequired()
            .HasDefaultValue(true);

        builder.Property(u => u.EmailConfirmed)
            .IsRequired()
            .HasDefaultValue(false);

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

    private static void ConfigureEssentialIndexes(EntityTypeBuilder<User> builder)
    {
        // Lambda expression kullanarak - EF Core value object'i handle eder
        builder.HasIndex(u => new { u.TenantId, u.Email })
            .HasDatabaseName("IX_Users_TenantId_Email")
            .IsUnique();

        builder.HasIndex(u => u.TenantId)
            .HasDatabaseName("IX_Users_TenantId");

        builder.HasIndex(u => new { u.TenantId, u.IsActive })
            .HasDatabaseName("IX_Users_TenantId_IsActive");
    }
}