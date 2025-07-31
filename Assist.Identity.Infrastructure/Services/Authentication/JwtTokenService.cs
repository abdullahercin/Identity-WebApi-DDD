using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.Models;

namespace Assist.Identity.Infrastructure.Services.Authentication;

/// <summary>
/// JWT Token Service Implementation
/// 
/// This service implements secure JWT token management for authentication and authorization.
/// It handles the complete token lifecycle: generation, validation, and management.
/// 
/// Key Learning Points:
/// 1. Enterprise JWT implementation patterns
/// 2. Security configuration for token services
/// 3. Claims-based authentication (user info, roles, permissions in tokens)
/// 4. Async service operations (I/O bound security operations)
/// 5. Complex configuration management
/// 6. Error handling in security-critical services
/// 
/// Security Features:
/// - RSA/HMAC signing algorithms
/// - Configurable token expiration
/// - Claims-based user information
/// - Token validation with proper error handling
/// - Cryptographically secure refresh token generation
/// 
/// This is significantly more complex than PasswordHashingService!
/// </summary>
public class JwtTokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly ICurrentTenantService _currentTenantService;

    // JWT Configuration Settings - Loaded from appsettings.json
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _accessTokenExpirationMinutes;
    private readonly int _refreshTokenExpirationDays;
    private readonly SigningCredentials _signingCredentials;

    /// <summary>
    /// Constructor - Dependency injection and configuration setup
    /// 
    /// Much more complex than PasswordHashingService constructor because
    /// this service requires extensive configuration for security.
    /// </summary>
    public JwtTokenService(
        IConfiguration configuration,
        ICurrentTenantService currentTenantService)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _currentTenantService = currentTenantService ?? throw new ArgumentNullException(nameof(currentTenantService));

        // Load JWT configuration from appsettings.json
        // These settings are critical for security - any misconfiguration can compromise the system
        _secretKey = _configuration["Jwt:SecretKey"]
            ?? throw new InvalidOperationException("JWT SecretKey not configured");
        _issuer = _configuration["Jwt:Issuer"]
            ?? throw new InvalidOperationException("JWT Issuer not configured");
        _audience = _configuration["Jwt:Audience"]
            ?? throw new InvalidOperationException("JWT Audience not configured");

        // Token expiration configuration
        _accessTokenExpirationMinutes = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "15");
        _refreshTokenExpirationDays = int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"] ?? "7");

        // Create signing credentials
        // HMAC SHA256 is industry standard for JWT signing
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    #region Token Generation

    /// <summary>
    /// Generate JWT access token with user information, roles, and permissions
    /// 
    /// This is the most complex method in the service. It creates a JWT token containing:
    /// - User identification (ID, email, name)
    /// - Tenant information (for multi-tenancy)
    /// - Role assignments
    /// - Permission grants
    /// - Token metadata (expiration, issuer, etc.)
    /// 
    /// The resulting token allows stateless authentication - all user info is in the token.
    /// </summary>
    public async Task<string> GenerateAccessTokenAsync(
        User user,
        IEnumerable<string> roles,
        IEnumerable<string> permissions,
        CancellationToken cancellationToken = default)
    {
        // Input validation - critical for security service
        if (user == null)
            throw new ArgumentNullException(nameof(user));
        if (roles == null)
            throw new ArgumentNullException(nameof(roles));
        if (permissions == null)
            throw new ArgumentNullException(nameof(permissions));

        try
        {
            // Create claims collection - this is the heart of JWT tokens
            // Claims represent user information that will be embedded in the token
            var claims = new List<Claim>
            {
                // Standard JWT claims (defined in JWT specification)
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),        // Subject (user ID)
                new(JwtRegisteredClaimNames.Email, user.Email.Value),        // Email
                new(JwtRegisteredClaimNames.GivenName, user.FirstName),      // First name
                new(JwtRegisteredClaimNames.FamilyName, user.LastName),      // Last name
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID (unique token identifier)
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), // Issued at

                // Custom claims for our application
                new("tenant_id", _currentTenantService.TenantId.ToString()), // Multi-tenancy support
                new("full_name", user.FullName),                             // Full name for UI display
                new("is_active", user.IsActive.ToString()),                  // User status
                new("email_confirmed", user.EmailConfirmed.ToString())       // Email verification status
            };

            // Add role claims - Multiple roles supported
            // Each role becomes a separate claim for flexible authorization
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Add permission claims - Fine-grained authorization
            // Each permission becomes a separate claim
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permission", permission));
            }

            // Create JWT token descriptor
            // This defines all the token properties and security settings
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),                           // All the claims we built above
                Expires = DateTime.UtcNow.AddMinutes(_accessTokenExpirationMinutes), // Token expiration
                Issuer = _issuer,                                               // Who issued this token
                Audience = _audience,                                           // Who can use this token
                SigningCredentials = _signingCredentials,                       // How to verify token authenticity

                // Additional security settings
                NotBefore = DateTime.UtcNow,                                    // Token not valid before this time
                IssuedAt = DateTime.UtcNow                                      // When token was issued
            };

            // Generate the actual JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(securityToken);

            // Return the JWT token as string
            // This token can be sent to client and used for subsequent requests
            return await Task.FromResult(tokenString);
        }
        catch (Exception ex)
        {
            // Log error but don't expose internal details for security
            System.Diagnostics.Debug.WriteLine($"Access token generation failed: {ex.Message}");
            throw new InvalidOperationException("Failed to generate access token.", ex);
        }
    }

    /// <summary>
    /// Generate cryptographically secure refresh token
    /// 
    /// Refresh tokens are different from access tokens:
    /// - They're random strings (not JWT)
    /// - They're long-lived (days instead of minutes)
    /// - They're used to get new access tokens
    /// - They can be revoked individually
    /// 
    /// This is much simpler than access token generation but still security-critical.
    /// </summary>
    public async Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Generate cryptographically secure random bytes
            // 32 bytes = 256 bits of entropy - very secure
            var randomBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            // Convert to base64 string for easy storage and transmission
            var refreshToken = Convert.ToBase64String(randomBytes);

            return await Task.FromResult(refreshToken);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Refresh token generation failed: {ex.Message}");
            throw new InvalidOperationException("Failed to generate refresh token.", ex);
        }
    }

    #endregion

    #region Token Validation

    /// <summary>
    /// Validate JWT token for authenticity and expiration
    /// 
    /// This method performs comprehensive token validation:
    /// - Signature verification (token wasn't tampered with)
    /// - Expiration check (token is still valid)
    /// - Issuer/Audience validation (token is for our application)
    /// - Format validation (token structure is correct)
    /// </summary>
    public async Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Token validation parameters - these must match token generation settings
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,                          // Verify token issuer
                ValidateAudience = true,                        // Verify token audience
                ValidateLifetime = true,                        // Check expiration
                ValidateIssuerSigningKey = true,                // Verify signature

                ValidIssuer = _issuer,                          // Expected issuer
                ValidAudience = _audience,                      // Expected audience
                IssuerSigningKey = _signingCredentials.Key,     // Signing key for verification

                // Clock skew tolerance (allows small time differences between servers)
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            // Attempt to validate token
            // If validation fails, this will throw an exception
            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            // Additional validation: ensure it's actually a JWT token
            if (validatedToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            return await Task.FromResult(true);
        }
        catch (SecurityTokenException)
        {
            // Token validation failed - this is normal for invalid/expired tokens
            return false;
        }
        catch (Exception ex)
        {
            // Unexpected error - log but don't expose details
            System.Diagnostics.Debug.WriteLine($"Token validation error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Extract user information from JWT token
    /// 
    /// This method parses a valid JWT token and extracts user information
    /// that was embedded during token generation. This allows stateless
    /// authentication - no database lookup needed to get user info.
    /// </summary>
    public async Task<TokenUserInfo?> GetUserInfoFromTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            // Validate and parse token
            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken)
                return null;

            // Extract user information from claims
            var userInfo = new TokenUserInfo
            {
                UserId = Guid.Parse(principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? Guid.Empty.ToString()),
                Email = principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value ?? string.Empty,
                FirstName = principal.FindFirst(JwtRegisteredClaimNames.GivenName)?.Value ?? string.Empty,
                LastName = principal.FindFirst(JwtRegisteredClaimNames.FamilyName)?.Value ?? string.Empty,
                FullName = principal.FindFirst("full_name")?.Value ?? string.Empty,
                TenantId = Guid.Parse(principal.FindFirst("tenant_id")?.Value ?? Guid.Empty.ToString()),
                IsActive = bool.Parse(principal.FindFirst("is_active")?.Value ?? "false"),
                EmailConfirmed = bool.Parse(principal.FindFirst("email_confirmed")?.Value ?? "false"),

                // Extract roles and permissions
                Roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
                Permissions = principal.FindAll("permission").Select(c => c.Value).ToList()
            };

            return await Task.FromResult(userInfo);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Token parsing failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Check if token is expired
    /// 
    /// Simple utility method to check token expiration without full validation.
    /// Useful for determining if token refresh is needed.
    /// </summary>
    public async Task<bool> IsTokenExpiredAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return true;

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);

            // Check if token expiration time is in the past
            var isExpired = jwtToken.ValidTo <= DateTime.UtcNow;

            return await Task.FromResult(isExpired);
        }
        catch (Exception)
        {
            // If we can't parse the token, consider it expired
            return true;
        }
    }

    #endregion

    #region Token Management

    /// <summary>
    /// Revoke a specific token
    /// 
    /// In a complete implementation, this would add the token to a blacklist.
    /// For now, we'll implement basic token revocation logic.
    /// </summary>
    public async Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token cannot be null or empty.", nameof(token));

        try
        {
            // In a production system, you would:
            // 1. Add token to blacklist/revocation list
            // 2. Store in cache (Redis) or database
            // 3. Check blacklist during validation

            // For now, we'll just validate that it's a proper token
            var isValid = await ValidateTokenAsync(token, cancellationToken);
            if (!isValid)
            {
                throw new ArgumentException("Invalid token cannot be revoked.", nameof(token));
            }

            // TODO: Implement actual token blacklisting
            // This would typically involve storing the token JTI (JWT ID) in a blacklist
            // and checking it during validation

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Token revocation failed: {ex.Message}");
            throw new InvalidOperationException("Failed to revoke token.", ex);
        }
    }

    /// <summary>
    /// Revoke all tokens for a specific user
    /// 
    /// This would be used when user changes password, account is compromised, etc.
    /// In production, this would invalidate all user's tokens system-wide.
    /// </summary>
    public async Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        try
        {
            // In production implementation:
            // 1. Add user ID to global revocation list with timestamp
            // 2. During token validation, check if token was issued before revocation time
            // 3. Also revoke all refresh tokens for this user in database

            // TODO: Implement actual user token revocation

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"User token revocation failed: {ex.Message}");
            throw new InvalidOperationException("Failed to revoke user tokens.", ex);
        }
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// Get token validation parameters
    /// 
    /// Helper method to create consistent validation parameters
    /// used across multiple validation methods.
    /// </summary>
    private TokenValidationParameters GetValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            IssuerSigningKey = _signingCredentials.Key,
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    }

    #endregion
}