using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Persistence.Configurations;

/// <summary>
/// Permission Entity Configuration for EF Core
/// 
/// This is the simplest configuration in our domain model.
/// Permission represents fine-grained access rights like "CanReadUsers", "CanEditRoles".
/// 
/// Learning Focus:
/// 1. How simple entities with just basic properties are configured
/// 2. Category-based organization of permissions
/// 3. One-to-many relationship from the "child" side
/// 4. Reinforcing the patterns learned from User and Role configurations
/// </summary>
public class PermissionConfiguration : IEntityTypeConfiguration<Permission>
{
    public void Configure(EntityTypeBuilder<Permission> builder)
    {
        // Same familiar structure as User and Role configurations
        // This consistency makes our codebase easy to understand and maintain
        ConfigureTable(builder);
        ConfigureProperties(builder);
        ConfigureNavigationProperties(builder);
        ConfigureIndexes(builder);
    }

    /// <summary>
    /// Step 1: Table configuration
    /// Following the same pattern as User and Role - consistency is key!
    /// </summary>
    private static void ConfigureTable(EntityTypeBuilder<Permission> builder)
    {
        // Table name: "Permissions" (following our naming convention)
        builder.ToTable("Permissions");

        // Primary key from BaseEntity (same pattern as all our entities)
        builder.HasKey(p => p.Id);
        builder.Property(p => p.Id)
            .ValueGeneratedNever(); // Domain generates Id, not database
    }

    /// <summary>
    /// Step 2: Properties configuration
    /// Permission has 3 simple string properties - very straightforward!
    /// </summary>
    private static void ConfigureProperties(EntityTypeBuilder<Permission> builder)
    {
        // NAME property - The permission identifier
        // Examples: "CanReadUsers", "CanEditRoles", "CanDeleteData"
        // This should be unique per tenant and used in code for authorization checks
        builder.Property(p => p.Name)
            .HasMaxLength(100)          // Longer than Role names (more descriptive)
            .IsRequired();              // Every permission must have a name

        // DESCRIPTION property - Human-readable explanation
        // Examples: "Allows reading user information", "Allows editing role assignments"
        // This helps administrators understand what each permission does
        builder.Property(p => p.Description)
            .HasMaxLength(500)          // Longer than Role description (more detail needed)
            .IsRequired(false);         // Description is optional but recommended

        // CATEGORY property - Logical grouping
        // Examples: "User Management", "Role Management", "System Administration"
        // This helps organize permissions in admin interfaces
        builder.Property(p => p.Category)
            .HasMaxLength(50)           // Categories should be short and clear
            .IsRequired(false)          // Category is optional
            .HasDefaultValue("General"); // Default category for permissions without specific category
    }

    /// <summary>
    /// Step 3: Navigation Properties configuration
    /// Permission has only one relationship - to RolePermission join table
    /// This is simpler than User and Role because Permission doesn't directly connect to Users
    /// </summary>
    private static void ConfigureNavigationProperties(EntityTypeBuilder<Permission> builder)
    {
        // ROLE PERMISSIONS relationship
        // This is the "other side" of the relationship we configured in RoleConfiguration
        // One Permission can be assigned to many Roles (through RolePermission join table)
        builder.HasMany(p => p.RolePermissions)
            .WithOne(rp => rp.Permission)              // RolePermission points back to Permission
            .HasForeignKey(rp => rp.PermissionId)      // Foreign key in RolePermission table
            .OnDelete(DeleteBehavior.Cascade);         // Delete RolePermissions when Permission is deleted
    }

    /// <summary>
    /// Indexes configuration - Design-time compatible
    /// Simple but essential indexes for permission-based queries
    /// </summary>
    private static void ConfigureIndexes(EntityTypeBuilder<Permission> builder)
    {
        // TENANT + NAME composite unique index
        builder.HasIndex("TenantId", "Name")
            .HasDatabaseName("IX_Permissions_TenantId_Name")
            .IsUnique();

        // TENANT index for basic filtering
        builder.HasIndex(p => p.TenantId)
            .HasDatabaseName("IX_Permissions_TenantId");

        // CATEGORY index for admin interface grouping
        builder.HasIndex("TenantId", "Category")
            .HasDatabaseName("IX_Permissions_TenantId_Category")
            .HasFilter("Category IS NOT NULL");
    }
}