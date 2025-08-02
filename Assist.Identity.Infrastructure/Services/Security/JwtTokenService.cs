using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Assist.Identity.Infrastructure.Services.Security;

/// <summary>
/// JWT Token Service Implementation
/// 
/// Bu service JWT (JSON Web Token) generation, validation ve parsing'i handle eder.
/// Modern web uygulamalarında stateless authentication için kritik bir component'tir.
/// 
/// JWT Benefits Over Traditional Sessions:
/// 1. Stateless: Server'da session bilgisi tutma ihtiyacı yok
/// 2. Scalable: Multiple server'lar arasında session sharing problemi yok
/// 3. Cross-Platform: Mobile, web, API'lar aynı token'ı kullanabilir
/// 4. Self-Contained: Token içinde user bilgileri mevcut, database lookup gereksiz
/// 5. Secure: Cryptographic signing ile token integrity garantili
/// 
/// JWT Structure:
/// Header.Payload.Signature
/// - Header: Algorithm ve token type bilgisi
/// - Payload: User claims (ID, email, roles, permissions, expiration)
/// - Signature: Token'ın değiştirilmediğini garanti eden cryptographic signature
/// 
/// Security Considerations:
/// - Secret key güvenli şekilde store edilmeli (Environment variables, Azure Key Vault)
/// - Token expiration time reasonable olmalı (çok uzun güvenlik riski, çok kısa UX problemi)
/// - Sensitive bilgiler payload'da olmamalı (password, personal data)
/// - HTTPS kullanımı mandatory (token hijacking prevention)
/// </summary>
public class JwtTokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly JwtSettings _jwtSettings;

    /// <summary>
    /// JwtTokenService constructor
    /// 
    /// Configuration'dan JWT settings'leri alır ve validate eder.
    /// Fail-fast principle: Invalid configuration application'ı başlatmaz.
    /// </summary>
    /// <param name="configuration">Application configuration</param>
    /// <param name="logger">Structured logging interface</param>
    public JwtTokenService(IConfiguration configuration, ILogger<JwtTokenService> logger)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Load and validate JWT settings
        _jwtSettings = LoadJwtSettings();
        ValidateJwtSettings();

        _logger.LogInformation("JwtTokenService initialized with issuer: {Issuer}", _jwtSettings.Issuer);
    }

    #region Token Generation

    /// <summary>
    /// Access token generation
    /// 
    /// Access token workflow:
    /// 1. User'ın temel bilgilerini claims'lere çevir
    /// 2. Roles ve permissions'ları token'a embed et
    /// 3. Expiration time set et (genelde 15-60 dakika)
    /// 4. Token'ı cryptographic olarak sign et
    /// 5. Base64 encoded JWT string döndür
    /// 
    /// Token içeriği:
    /// - Standard claims: sub (subject), iat (issued at), exp (expiration)
    /// - Custom claims: email, tenant_id, roles, permissions
    /// - Security claims: jti (JWT ID) for token tracking
    /// 
    /// Performance considerations:
    /// - Token size: Çok fazla claim token size'ını artırır
    /// - Network overhead: Her request'te token gönderilir
    /// - Parsing cost: Token her request'te parse edilir
    /// </summary>
    public async Task<string> GenerateAccessTokenAsync(User user, IEnumerable<string> roles, IEnumerable<string> permissions, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Generating access token for user: {UserId}", user.Id);

            // JWT Claims - token içinde carry edilecek bilgiler
            var claims = new List<Claim>
            {
                // Standard JWT claims (RFC 7519)
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),           // Subject: User ID
                new(JwtRegisteredClaimNames.Email, user.Email.Value!),          // Email address
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),    // JWT ID: Unique token identifier
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), // Issued at
                
                // Custom application claims
                new("tenant_id", user.TenantId.ToString()),                     // Multi-tenancy support
                new("first_name", user.FirstName),                             // User display name
                new("last_name", user.LastName),                               // User display name
                new("full_name", user.FullName),                               // Computed full name
                new("email_confirmed", user.EmailConfirmed.ToString().ToLower()) // Email verification status
            };

            // Add roles as multiple claims (standard approach)
            // This allows ASP.NET Core authorization to work seamlessly
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Add permissions as custom claims
            // Permissions için custom claim type kullanıyoruz
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permission", permission));
            }

            // Token descriptor - JWT creation için configuration
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(GetSigningKey(), SecurityAlgorithms.HmacSha256Signature)
            };

            // JWT token generation
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(securityToken);

            _logger.LogDebug("Access token generated successfully for user: {UserId}, expires at: {ExpiresAt}",
                user.Id, tokenDescriptor.Expires);

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate access token for user: {UserId}", user.Id);
            throw new InvalidOperationException($"Token generation failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Refresh token generation
    /// 
    /// Refresh token characteristics:
    /// - Longer expiration time (days or weeks)
    /// - Cryptographically secure random string
    /// - One-time use (consumed when used)
    /// - Stored in database for validation
    /// - Can be revoked for security
    /// 
    /// Refresh token workflow:
    /// 1. Generate cryptographically secure random string
    /// 2. No user information embedded (unlike access token)
    /// 3. Store in database with user association
    /// 4. Return to client for future token refresh requests
    /// 
    /// Security benefits:
    /// - Access token kısa ömürlü (15-60 dakika)
    /// - Refresh token uzun ömürlü ama revokable
    /// - Compromise durumunda damage limitation
    /// </summary>
    public async Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Generate cryptographically secure random bytes
            var randomBytes = new byte[64]; // 512 bits of entropy
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            // Convert to base64 for string representation
            var refreshToken = Convert.ToBase64String(randomBytes);

            _logger.LogDebug("Refresh token generated successfully, length: {Length}", refreshToken.Length);

            return await Task.FromResult(refreshToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate refresh token");
            throw new InvalidOperationException($"Refresh token generation failed: {ex.Message}", ex);
        }
    }

    #endregion

    #region Token Validation

    /// <summary>
    /// Token validation
    /// 
    /// Validation process:
    /// 1. Parse JWT structure (Header.Payload.Signature)
    /// 2. Verify cryptographic signature
    /// 3. Check token expiration
    /// 4. Validate issuer and audience
    /// 5. Ensure token format compliance
    /// 
    /// Validation failures:
    /// - Malformed token structure
    /// - Invalid signature (token tampered)
    /// - Expired token
    /// - Wrong issuer/audience
    /// - Missing required claims
    /// 
    /// Performance note:
    /// Token validation çok frequent operation (her request'te)
    /// Bu yüzden efficient olması kritik
    /// </summary>
    public async Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogDebug("Token validation failed: empty token");
                return false;
            }

            var tokenHandler = new JwtSecurityTokenHandler();

            // Token validation parameters
            var validationParameters = GetTokenValidationParameters();

            // Validate token and extract principal
            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            // Additional custom validations
            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                _logger.LogDebug("Token validation failed: not a valid JWT token");
                return false;
            }

            // Verify algorithm (prevent algorithm substitution attacks)
            if (!jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                _logger.LogDebug("Token validation failed: invalid algorithm: {Algorithm}", jwtToken.Header.Alg);
                return false;
            }

            _logger.LogDebug("Token validation successful");
            return await Task.FromResult(true);
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger.LogDebug(ex, "Token validation failed: token expired");
            return false;
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogDebug(ex, "Token validation failed: security token error");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            return false;
        }
    }

    /// <summary>
    /// Extract user information from token
    /// 
    /// Token parsing workflow:
    /// 1. Validate token structure ve signature
    /// 2. Extract claims from payload
    /// 3. Map claims to strongly-typed model
    /// 4. Handle missing or invalid claims gracefully
    /// 
    /// Claims mapping:
    /// - sub → UserId
    /// - email → Email
    /// - tenant_id → TenantId  
    /// - role claims → Roles collection
    /// - permission claims → Permissions collection
    /// 
    /// Error handling:
    /// - Invalid token format
    /// - Missing required claims
    /// - Type conversion errors
    /// - Expired tokens
    /// </summary>
    public async Task<TokenUserInfo?> GetUserInfoFromTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogDebug("GetUserInfo failed: empty token");
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetTokenValidationParameters();

            // Validate and parse token
            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            // Extract user information from claims
            var userInfo = new TokenUserInfo();

            // Extract User ID (required claim)
            var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub);
            if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
            {
                _logger.LogWarning("Token missing or invalid user ID claim");
                return null;
            }
            userInfo.UserId = userId;

            // Extract Email (required claim)
            var emailClaim = principal.FindFirst(JwtRegisteredClaimNames.Email);
            if (emailClaim == null)
            {
                _logger.LogWarning("Token missing email claim");
                return null;
            }
            userInfo.Email = emailClaim.Value;

            // Extract Tenant ID (required for multi-tenancy)
            var tenantIdClaim = principal.FindFirst("tenant_id");
            if (tenantIdClaim != null && Guid.TryParse(tenantIdClaim.Value, out var tenantId))
            {
                userInfo.TenantId = tenantId;
            }
            else
            {
                _logger.LogWarning("Token missing or invalid tenant ID claim");
                return null;
            }

            // Extract Roles
            userInfo.Roles = principal.FindAll(ClaimTypes.Role)
                .Select(c => c.Value)
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .ToList();

            // Extract Permissions
            userInfo.Permissions = principal.FindAll("permission")
                .Select(c => c.Value)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .ToList();

            _logger.LogDebug("User info extracted from token - UserId: {UserId}, Email: {Email}, Roles: {RoleCount}, Permissions: {PermissionCount}",
                userInfo.UserId, userInfo.Email, userInfo.Roles.Count, userInfo.Permissions.Count);

            return await Task.FromResult(userInfo);
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogDebug(ex, "Failed to extract user info: invalid token");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error extracting user info from token");
            return null;
        }
    }

    /// <summary>
    /// Check if token is expired
    /// 
    /// Expiration checking benefits:
    /// - Early detection before API calls
    /// - Client-side token refresh logic
    /// - Proactive user experience
    /// - Reduced server-side validation load
    /// </summary>
    public async Task<bool> IsTokenExpiredAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return true;

            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadJwtToken(token);

            // Check expiration without signature validation (faster)
            var isExpired = jsonToken.ValidTo <= DateTime.UtcNow;

            _logger.LogDebug("Token expiration check - Valid until: {ValidTo}, Is expired: {IsExpired}",
                jsonToken.ValidTo, isExpired);

            return await Task.FromResult(isExpired);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking token expiration");
            return true; // Assume expired if cannot parse
        }
    }

    #endregion

    #region Token Management

    /// <summary>
    /// Token revocation
    /// 
    /// JWT stateless nature makes revocation challenging:
    /// - JWT'ler inherently stateless (server'da token list yok)
    /// - Revocation için token blacklist gerekiyor
    /// - Redis cache ideal blacklist storage
    /// - Blacklist check her validation'da yapılmalı
    /// 
    /// Revocation strategies:
    /// 1. Blacklist approach (implement burada)
    /// 2. Short expiration + refresh pattern
    /// 3. Token versioning
    /// 4. External token validation service
    /// </summary>
    public async Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogDebug("Cannot revoke empty token");
                return;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadJwtToken(token);

            // Extract JTI (JWT ID) for blacklisting
            var jtiClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            if (jtiClaim == null)
            {
                _logger.LogWarning("Cannot revoke token: missing JTI claim");
                return;
            }

            var jti = jtiClaim.Value;
            var expiration = jsonToken.ValidTo;

            // Add to blacklist with appropriate expiration
            // Note: Bu implementation ICacheService gerektirir
            // Şimdilik placeholder, gerçek implementation cache service ile yapılacak

            _logger.LogInformation("Token revoked - JTI: {JTI}, Expires: {Expiration}", jti, expiration);

            // TODO: Implement blacklist storage
            // await _cacheService.SetAsync($"blacklist:{jti}", true, expiration - DateTime.UtcNow);

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke token");
            throw new InvalidOperationException($"Token revocation failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Revoke all tokens for a specific user
    /// 
    /// Use cases:
    /// - Password change (security measure)
    /// - Account deactivation
    /// - Suspicious activity detection
    /// - Admin action (force logout)
    /// 
    /// Implementation strategy:
    /// - User-based token versioning
    /// - Increment user token version
    /// - Validate token version on each request
    /// </summary>
    public async Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Revoking all tokens for user: {UserId}", userId);

            // TODO: Implement user token version strategy
            // 1. Increment user token version in database
            // 2. Add user to "force logout" list with timestamp
            // 3. Validate user token version on each request

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke all user tokens for user: {UserId}", userId);
            throw new InvalidOperationException($"User token revocation failed: {ex.Message}", ex);
        }
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// Load JWT settings from configuration
    /// 
    /// Configuration structure:
    /// {
    ///   "JWT": {
    ///     "SecretKey": "your-secret-key-here",
    ///     "Issuer": "YourApp",
    ///     "Audience": "YourApp-Users", 
    ///     "AccessTokenExpirationMinutes": 60,
    ///     "RefreshTokenExpirationDays": 30
    ///   }
    /// }
    /// </summary>
    private JwtSettings LoadJwtSettings()
    {
        return new JwtSettings
        {
            SecretKey = _configuration["JWT:SecretKey"] ?? GenerateDefaultSecretKey(),
            Issuer = _configuration["JWT:Issuer"] ?? "Assist.Identity",
            Audience = _configuration["JWT:Audience"] ?? "Assist.Identity.Users",
            AccessTokenExpirationMinutes = int.Parse(_configuration["JWT:AccessTokenExpirationMinutes"] ?? "60"),
            RefreshTokenExpirationDays = int.Parse(_configuration["JWT:RefreshTokenExpirationDays"] ?? "30")
        };
    }

    /// <summary>
    /// Generate default secret key for development
    /// Production'da environment variable veya secure storage kullanılmalı
    /// </summary>
    private string GenerateDefaultSecretKey()
    {
        _logger.LogWarning("JWT SecretKey not configured, generating default key for development");

        // Generate 256-bit key for HMAC-SHA256
        var key = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);

        return Convert.ToBase64String(key);
    }

    /// <summary>
    /// Validate JWT configuration
    /// Fail-fast principle: invalid configuration prevents application startup
    /// </summary>
    private void ValidateJwtSettings()
    {
        if (string.IsNullOrWhiteSpace(_jwtSettings.SecretKey))
            throw new InvalidOperationException("JWT SecretKey is required");

        if (_jwtSettings.SecretKey.Length < 32)
            throw new InvalidOperationException("JWT SecretKey must be at least 32 characters");

        if (string.IsNullOrWhiteSpace(_jwtSettings.Issuer))
            throw new InvalidOperationException("JWT Issuer is required");

        if (string.IsNullOrWhiteSpace(_jwtSettings.Audience))
            throw new InvalidOperationException("JWT Audience is required");

        if (_jwtSettings.AccessTokenExpirationMinutes <= 0 || _jwtSettings.AccessTokenExpirationMinutes > 1440)
            throw new InvalidOperationException("JWT AccessTokenExpirationMinutes must be between 1-1440 minutes");

        if (_jwtSettings.RefreshTokenExpirationDays <= 0 || _jwtSettings.RefreshTokenExpirationDays > 365)
            throw new InvalidOperationException("JWT RefreshTokenExpirationDays must be between 1-365 days");
    }

    /// <summary>
    /// Get signing key for token creation and validation
    /// </summary>
    private SymmetricSecurityKey GetSigningKey()
    {
        var keyBytes = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);
        return new SymmetricSecurityKey(keyBytes);
    }

    /// <summary>
    /// Get token validation parameters
    /// Centralized validation configuration
    /// </summary>
    private TokenValidationParameters GetTokenValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = GetSigningKey(),
            ValidateIssuer = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5), // Allow 5 minutes clock skew
            RequireExpirationTime = true,
            RequireSignedTokens = true
        };
    }

    #endregion
}

/// <summary>
/// JWT Configuration Settings
/// Internal configuration model for JWT service
/// </summary>
internal class JwtSettings
{
    public string SecretKey { get; set; } = null!;
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationDays { get; set; }
}