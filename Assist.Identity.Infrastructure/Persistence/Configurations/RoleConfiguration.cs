using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Persistence.Configurations;

/// <summary>
/// Role Entity Configuration for EF Core
/// 
/// This class maps the Role domain entity to database tables.
/// Role is simpler than User - no value objects, just basic properties
/// and two important relationships.
/// 
/// Learning Focus:
/// 1. How to configure simple string properties with constraints
/// 2. How to set up many-to-many relationships from "the other side"
/// 3. How to create indexes for role-based queries
/// 4. Clean and maintainable configuration structure
/// </summary>
public class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        // Step by step configuration - each method has a clear purpose
        ConfigureTable(builder);
        ConfigureProperties(builder);
        ConfigureNavigationProperties(builder);
        ConfigureIndexes(builder);
    }

    /// <summary>
    /// Step 1: Table configuration
    /// Simple and straightforward - just like UserConfiguration
    /// </summary>
    private static void ConfigureTable(EntityTypeBuilder<Role> builder)
    {
        // Table name: "Roles" (plural form, following convention)
        builder.ToTable("Roles");

        // Primary key comes from BaseEntity (Id property)
        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id)
            .ValueGeneratedNever(); // Domain generates the Id, not database
    }

    /// <summary>
    /// Step 2: Properties configuration
    /// Role has only 3 simple properties - much easier than User!
    /// </summary>
    private static void ConfigureProperties(EntityTypeBuilder<Role> builder)
    {
        // NAME property - This is the most important property
        // Examples: "Admin", "Manager", "User", "Guest"
        builder.Property(r => r.Name)
            .HasMaxLength(50)           // Role names should be short and clear
            .IsRequired();              // Every role must have a name

        // DESCRIPTION property - Optional explanation
        // Examples: "Full system access", "Can manage team members"
        builder.Property(r => r.Description)
            .HasMaxLength(200)          // Longer than Name, but not too long
            .IsRequired(false);         // Description is optional

        // ISACTIVE property - Enable/disable roles
        // This allows "soft deactivation" without deleting role
        builder.Property(r => r.IsActive)
            .IsRequired()               // Must always have a value
            .HasDefaultValue(true);     // New roles are active by default
    }

    /// <summary>
    /// Step 3: Navigation Properties configuration
    /// This is where Role connects to User and Permission entities
    /// These are "many-to-many" relationships using join tables
    /// </summary>
    private static void ConfigureNavigationProperties(EntityTypeBuilder<Role> builder)
    {
        // USER ROLES relationship
        // This is the "other side" of the relationship we saw in UserConfiguration
        // One Role can be assigned to many Users (through UserRole join table)
        builder.HasMany(r => r.UserRoles)
            .WithOne(ur => ur.Role)                    // UserRole points back to Role
            .HasForeignKey(ur => ur.RoleId)            // Foreign key in UserRole table
            .OnDelete(DeleteBehavior.Cascade);         // Delete UserRoles when Role is deleted

        // ROLE PERMISSIONS relationship  
        // One Role can have many Permissions (through RolePermission join table)
        // This is how we control what each role can do in the system
        builder.HasMany(r => r.RolePermissions)
            .WithOne(rp => rp.Role)                    // RolePermission points back to Role
            .HasForeignKey(rp => rp.RoleId)            // Foreign key in RolePermission table
            .OnDelete(DeleteBehavior.Cascade);         // Delete RolePermissions when Role is deleted
    }

    /// <summary>
    /// Indexes configuration - Design-time compatible
    /// Performance optimization for common queries
    /// </summary>
    private static void ConfigureIndexes(EntityTypeBuilder<Role> builder)
    {
        // TENANT + NAME composite unique index
        builder.HasIndex("TenantId", "Name")
            .HasDatabaseName("IX_Roles_TenantId_Name")
            .IsUnique();

        // TENANT index for filtering
        builder.HasIndex(r => r.TenantId)
            .HasDatabaseName("IX_Roles_TenantId");

        // ACTIVE ROLES index
        builder.HasIndex("TenantId", "IsActive")
            .HasDatabaseName("IX_Roles_TenantId_IsActive");
    }
}