
namespace Assist.Identity.Domain.ValueObjects
{
    /// <summary>
    /// User Authorization Snapshot - Domain Value Object
    /// 
    /// Domain layer'da user'ın authorization durumunun snapshot'ını temsil eder.
    /// Clean Architecture: Domain layer hiçbir başka katmana depend etmez.
    /// 
    /// Bu class:
    /// - Domain logic için kullanılır
    /// - Primitive types kullanır (external dependency yok)
    /// - Immutable value object pattern
    /// - Application layer'da richer DTO'ya map edilir
    /// 
    /// Design Pattern: Value Object
    /// - Immutable (readonly properties)
    /// - Equals/GetHashCode override (value equality)
    /// - No identity (pure data representation)
    /// </summary>
    public sealed class UserAuthorizationSummary : IEquatable<UserAuthorizationSummary>
    {
        /// <summary>
        /// UserAuthorizationSnapshot constructor
        /// Immutable value object pattern
        /// </summary>
        public UserAuthorizationSummary(
            Guid userId,
            string email,
            string firstName,
            string lastName,
            Guid tenantId,
            bool isActive,
            bool emailConfirmed,
            DateTime? lastLoginAt,
            IEnumerable<string> roles,
            IEnumerable<string> permissions)
        {
            UserId = userId;
            Email = email ?? string.Empty;
            FirstName = firstName ?? string.Empty;
            LastName = lastName ?? string.Empty;
            TenantId = tenantId;
            IsActive = isActive;
            EmailConfirmed = emailConfirmed;
            LastLoginAt = lastLoginAt;

            // Immutable collections
            Roles = roles?.ToList().AsReadOnly() ?? new List<string>().AsReadOnly();
            Permissions = permissions?.ToList().AsReadOnly() ?? new List<string>().AsReadOnly();

            // Computed at construction time
            RoleCount = Roles.Count;
            PermissionCount = Permissions.Count;
            IsAdmin = roles?.Any(r => AdminRoles.Contains(r, StringComparer.OrdinalIgnoreCase)) ?? false;
            HasAnyRole = Roles.Any();
            HasAnyPermission = Permissions.Any();
        }

        #region Static Configuration

        /// <summary>
        /// Admin role names - Domain business rule
        /// </summary>
        private static readonly string[] AdminRoles = { "Admin", "Administrator", "SuperAdmin" };

        #endregion

        #region Properties

        /// <summary>User unique identifier</summary>
        public Guid UserId { get; }

        /// <summary>User email address</summary>
        public string Email { get; }

        /// <summary>User first name</summary>
        public string FirstName { get; }

        /// <summary>User last name</summary>
        public string LastName { get; }

        /// <summary>Tenant identifier</summary>
        public Guid TenantId { get; }

        /// <summary>Account active status</summary>
        public bool IsActive { get; }

        /// <summary>Email confirmation status</summary>
        public bool EmailConfirmed { get; }

        /// <summary>Last login timestamp</summary>
        public DateTime? LastLoginAt { get; }

        /// <summary>User roles - Immutable collection</summary>
        public IReadOnlyList<string> Roles { get; }

        /// <summary>User permissions - Immutable collection</summary>
        public IReadOnlyList<string> Permissions { get; }

        /// <summary>Role count</summary>
        public int RoleCount { get; }

        /// <summary>Permission count</summary>
        public int PermissionCount { get; }

        /// <summary>Admin access indicator</summary>
        public bool IsAdmin { get; }

        /// <summary>Has any role</summary>
        public bool HasAnyRole { get; }

        /// <summary>Has any permission</summary>
        public bool HasAnyPermission { get; }

        #endregion

        #region Computed Properties

        /// <summary>
        /// Full name - Domain logic
        /// </summary>
        public string FullName
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(FirstName) && !string.IsNullOrWhiteSpace(LastName))
                    return $"{FirstName} {LastName}";

                if (!string.IsNullOrWhiteSpace(FirstName))
                    return FirstName;

                if (!string.IsNullOrWhiteSpace(LastName))
                    return LastName;

                return Email;
            }
        }

        /// <summary>
        /// Authorization level - Domain business logic
        /// </summary>
        public AuthorizationLevelEnum.AuthorizationLevel Level
        {
            get
            {
                if (IsAdmin)
                    return AuthorizationLevelEnum.AuthorizationLevel.Administrator;

                if (RoleCount >= 3 || PermissionCount >= 10)
                    return AuthorizationLevelEnum.AuthorizationLevel.PowerUser;

                if (HasAnyRole && HasAnyPermission)
                    return AuthorizationLevelEnum.AuthorizationLevel.StandardUser;

                if (HasAnyRole || HasAnyPermission)
                    return AuthorizationLevelEnum.AuthorizationLevel.LimitedUser;

                return AuthorizationLevelEnum.AuthorizationLevel.NoAccess;
            }
        }

        #endregion

        #region Domain Business Methods

        /// <summary>
        /// Check if user has specific role
        /// Domain business logic
        /// </summary>
        public bool HasRole(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return false;

            return Roles.Any(r => r.Equals(roleName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Check if user has specific permission
        /// Domain business logic
        /// </summary>
        public bool HasPermission(string permissionName)
        {
            if (string.IsNullOrWhiteSpace(permissionName))
                return false;

            return Permissions.Any(p => p.Equals(permissionName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Check if user can perform admin operations
        /// Domain business rule
        /// </summary>
        public bool CanPerformAdminOperations() => IsAdmin && IsActive && EmailConfirmed;

        /// <summary>
        /// Check if account needs attention
        /// Domain business rule
        /// </summary>
        public bool NeedsAttention()
        {
            return !IsActive ||
                   !EmailConfirmed ||
                   (!HasAnyRole && !HasAnyPermission) ||
                   (LastLoginAt == null) ||
                   (LastLoginAt < DateTime.UtcNow.AddDays(-90));
        }

        #endregion

        #region Value Object Implementation

        /// <summary>
        /// Value equality check
        /// Value objects are equal if all properties are equal
        /// </summary>
        public bool Equals(UserAuthorizationSummary? other)
        {
            if (other is null) return false;
            if (ReferenceEquals(this, other)) return true;

            return UserId.Equals(other.UserId) &&
                   Email == other.Email &&
                   FirstName == other.FirstName &&
                   LastName == other.LastName &&
                   TenantId.Equals(other.TenantId) &&
                   IsActive == other.IsActive &&
                   EmailConfirmed == other.EmailConfirmed &&
                   Nullable.Equals(LastLoginAt, other.LastLoginAt) &&
                   Roles.SequenceEqual(other.Roles) &&
                   Permissions.SequenceEqual(other.Permissions);
        }

        /// <summary>
        /// Object equality override
        /// </summary>
        public override bool Equals(object? obj)
        {
            return obj is UserAuthorizationSummary other && Equals(other);
        }

        /// <summary>
        /// GetHashCode override
        /// Required for value object pattern
        /// </summary>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(UserId);
            hash.Add(Email);
            hash.Add(FirstName);
            hash.Add(LastName);
            hash.Add(TenantId);
            hash.Add(IsActive);
            hash.Add(EmailConfirmed);
            hash.Add(LastLoginAt);

            // Hash collections
            foreach (var role in Roles)
                hash.Add(role);
            foreach (var permission in Permissions)
                hash.Add(permission);

            return hash.ToHashCode();
        }

        /// <summary>
        /// Equality operators
        /// </summary>
        public static bool operator ==(UserAuthorizationSummary left, UserAuthorizationSummary right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(UserAuthorizationSummary left, UserAuthorizationSummary right)
        {
            return !Equals(left, right);
        }

        #endregion

        #region String Representation

        /// <summary>
        /// String representation for debugging
        /// </summary>
        public override string ToString()
        {
            return $"AuthSnapshot: {FullName} ({Email}) | Tenant: {TenantId} | " +
                   $"Roles: {RoleCount} | Permissions: {PermissionCount} | Level: {Level}";
        }

        #endregion
    }
}