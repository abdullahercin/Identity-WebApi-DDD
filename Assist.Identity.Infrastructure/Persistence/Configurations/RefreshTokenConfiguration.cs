using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Persistence.Configurations;

/// <summary>
/// RefreshToken Entity Configuration for EF Core
/// 
/// This configuration is different from our previous ones because RefreshToken
/// is a technical/security entity rather than a business entity.
/// 
/// RefreshToken Purpose:
/// - Allows users to stay logged in without re-entering password
/// - Works with JWT access tokens for secure authentication
/// - Can be revoked for security purposes (logout, security breach)
/// 
/// Learning Focus:
/// 1. Technical entity configuration (security-focused)
/// 2. One-to-many relationship from the "child" side (RefreshToken belongs to User)
/// 3. Security-specific indexing strategies
/// 4. Token lifecycle management through database design
/// </summary>
public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        // Same familiar structure - consistency across all configurations
        ConfigureTable(builder);
        ConfigureProperties(builder);
        ConfigureNavigationProperties(builder);
        ConfigureSecurityIndexes(builder);
    }

    /// <summary>
    /// Step 1: Table configuration
    /// Following our established pattern for consistency
    /// </summary>
    private static void ConfigureTable(EntityTypeBuilder<RefreshToken> builder)
    {
        // Table name: "RefreshTokens" (following our naming convention)
        builder.ToTable("RefreshTokens");

        // Primary key from BaseEntity (same as all our entities)
        builder.HasKey(rt => rt.Id);
        builder.Property(rt => rt.Id)
            .ValueGeneratedNever(); // Domain generates Id, not database
    }

    /// <summary>
    /// Step 2: Properties configuration
    /// RefreshToken has security-focused properties with specific requirements
    /// </summary>
    private static void ConfigureProperties(EntityTypeBuilder<RefreshToken> builder)
    {
        // UserId property - Links token to specific user
        // This is a foreign key but also a regular property for queries
        builder.Property(rt => rt.UserId)
            .IsRequired();                      // Every token must belong to a user

        // TOKEN property - The actual refresh token string
        // This is a cryptographically secure random string
        builder.Property(rt => rt.Token)
            .HasMaxLength(256)                  // Long enough for secure tokens
            .IsRequired();                      // Every refresh token must have a token value

        // EXPIRESAT property - When this token becomes invalid
        // Critical for security - expired tokens should not work
        builder.Property(rt => rt.ExpiresAt)
            .IsRequired();                      // Every token must have expiration

        // ISACTIVE property - Whether token can be used
        // Allows "soft deletion" - revoke without deleting record
        builder.Property(rt => rt.IsActive)
            .IsRequired()                       // Must always have a value
            .HasDefaultValue(true);             // New tokens are active by default

        // REVOKEDAT property - When token was manually revoked
        // Important for security audit trails
        builder.Property(rt => rt.RevokedAt)
            .IsRequired(false);                 // Most tokens are never manually revoked
    }

    /// <summary>
    /// Step 3: Navigation Properties configuration
    /// RefreshToken has a simple one-to-many relationship with User
    /// This is the "child" side of the relationship we saw in UserConfiguration
    /// </summary>
    private static void ConfigureNavigationProperties(EntityTypeBuilder<RefreshToken> builder)
    {
        // USER relationship
        // This is the "child" side - RefreshToken belongs to User
        // One User can have many RefreshTokens (multiple devices, sessions)
        builder.HasOne(rt => rt.User)
            .WithMany(u => u.RefreshTokens)            // User can have many RefreshTokens
            .HasForeignKey(rt => rt.UserId)            // Foreign key pointing to User
            .OnDelete(DeleteBehavior.Cascade);         // Delete tokens when User is deleted
    }

    /// <summary>
    /// Step 4: Security-specific indexes
    /// RefreshToken indexing is focused on security and performance of token operations
    /// These indexes are different from business entity indexes
    /// </summary>
    private static void ConfigureSecurityIndexes(EntityTypeBuilder<RefreshToken> builder)
    {
        // TOKEN unique index - Most critical security index
        // Every token must be globally unique across all tenants
        // This prevents token collision attacks
        builder.HasIndex(rt => rt.Token)
            .HasDatabaseName("IX_RefreshTokens_Token")
            .IsUnique();                               // Absolutely must be unique

        // USER + ACTIVE tokens index
        // Common query: "Get all active tokens for this user"
        // Used for user session management and security monitoring
        builder.HasIndex(rt => new { rt.UserId, rt.IsActive })
            .HasDatabaseName("IX_RefreshTokens_UserId_IsActive");

        // TENANT filtering index
        // All token queries filter by tenant for data isolation
        builder.HasIndex(rt => rt.TenantId)
            .HasDatabaseName("IX_RefreshTokens_TenantId");

        // EXPIRATION cleanup index
        // System cleanup job: "Find all expired tokens to delete"
        // This index makes token cleanup operations very fast
        builder.HasIndex(rt => rt.ExpiresAt)
            .HasDatabaseName("IX_RefreshTokens_ExpiresAt");

        // REVOCATION audit index
        // Security monitoring: "Show me all revoked tokens"
        // Used for security analysis and audit trails
        builder.HasIndex(rt => rt.RevokedAt)
            .HasDatabaseName("IX_RefreshTokens_RevokedAt")
            .HasFilter("RevokedAt IS NOT NULL");       // Only index tokens that were actually revoked
    }
}