using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Infrastructure.Configuration;

namespace Assist.Identity.Infrastructure.Services.Security;

/// <summary>
/// JWT Token Service Implementation - Interface Compliant
/// 
/// Bu implementation ITokenService interface'ine tam uyumlu.
/// User entity'sindeki domain methods'ları kullanarak roles ve permissions alır.
/// 
/// Key Changes:
/// 1. GenerateAccessTokenAsync sadece User entity alır (interface'e uygun)
/// 2. User.GetRoleNames() ve User.GetPermissions() domain methods kullanır
/// 3. Eksik method'lar implement edildi (GetUserIdFromTokenAsync, GetTokenExpirationAsync)
/// 4. JwtSettings class'ı ve dependencies düzeltildi
/// </summary>
public class JwtTokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly JwtSettings _jwtSettings;
    private readonly TokenValidationParameters _tokenValidationParameters;

    /// <summary>
    /// JwtTokenService constructor
    /// Configuration'dan JWT settings'leri alır ve validate eder
    /// </summary>
    public JwtTokenService(IConfiguration configuration, ILogger<JwtTokenService> logger)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Load and validate JWT settings
        _jwtSettings = LoadJwtSettings();
        ValidateJwtSettings();

        // Setup token validation parameters
        _tokenValidationParameters = CreateTokenValidationParameters();

        _logger.LogInformation("JwtTokenService initialized with issuer: {Issuer}", _jwtSettings.Issuer);
    }

    #region Token Generation

    /// <summary>
    /// Access token generation - Interface compliant
    /// 
    /// DDD Approach: User entity üzerindeki domain methods kullanılır
    /// - User.GetRoleNames() → roles for authorization
    /// - User.GetPermissions() → fine-grained permissions
    /// 
    /// Bu approach'ın avantajları:
    /// 1. Business logic domain layer'da kalır
    /// 2. Interface clean ve simple
    /// 3. Token service business rules'ları bilmez
    /// 4. User entity kendi responsibility'lerini handle eder
    /// </summary>
    public async Task<string> GenerateAccessTokenAsync(User user, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Generating access token for user: {UserId}", user.Id);

            // Domain methods kullanarak roles ve permissions al
            var roles = user.GetRoleNames().ToList();
            var permissions = user.GetPermissions().ToList();

            _logger.LogDebug("User {UserId} has {RoleCount} roles and {PermissionCount} permissions",
                user.Id, roles.Count, permissions.Count);

            // JWT Claims oluştur
            var claims = BuildAccessTokenClaims(user, roles, permissions);

            // Token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(GetSigningKey(), SecurityAlgorithms.HmacSha256Signature)
            };

            // JWT token generate et
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
    /// Cryptographically secure random string generate eder
    /// </summary>
    public async Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Cryptographically secure random bytes
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            // URL-safe base64 string
            var refreshToken = Convert.ToBase64String(randomBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");

            _logger.LogDebug("Refresh token generated successfully");
            return refreshToken;
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
    /// Token validation - JWT signature, expiration, format kontrolü
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

            // Token format kontrolü
            if (!tokenHandler.CanReadToken(token))
            {
                _logger.LogDebug("Token validation failed: invalid token format");
                return false;
            }

            // Token validation
            var principal = tokenHandler.ValidateToken(token, _tokenValidationParameters, out SecurityToken validatedToken);

            // Additional security checks
            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                _logger.LogDebug("Token validation failed: not a valid JWT");
                return false;
            }

            // Algorithm verification (prevent algorithm substitution attacks)
            if (!jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                _logger.LogWarning("Token validation failed: invalid algorithm: {Algorithm}", jwtToken.Header.Alg);
                return false;
            }

            _logger.LogDebug("Token validation successful");
            return true;
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogDebug("Token validation failed: token expired");
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
    /// Token'dan user bilgilerini extract etme
    /// Authorization pipeline için TokenUserInfo oluşturur
    /// </summary>
    public async Task<TokenUserInfo?> GetUserInfoFromTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return null;

            // Token validation ve claims extraction
            var principal = tokenHandler.ValidateToken(token, _tokenValidationParameters, out _);

            // Required claims extract et
            var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var emailClaim = principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value;
            var tenantIdClaim = principal.FindFirst("tenant_id")?.Value;
            var firstNameClaim = principal.FindFirst("first_name")?.Value;
            var lastNameClaim = principal.FindFirst("last_name")?.Value;

            // Validation
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId) ||
                string.IsNullOrEmpty(tenantIdClaim) || !Guid.TryParse(tenantIdClaim, out var tenantId))
            {
                _logger.LogWarning("Token contains invalid user or tenant ID claims");
                return null;
            }

            // Roles ve permissions extract et
            var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
            var permissions = principal.FindAll("permission").Select(c => c.Value).ToList();

            // Email confirmed claim extract et
            var emailConfirmedClaim = principal.FindFirst("email_confirmed")?.Value;
            var emailConfirmed = bool.TryParse(emailConfirmedClaim, out var confirmed) && confirmed;

            return new TokenUserInfo
            {
                UserId = userId,
                Email = emailClaim ?? string.Empty,
                TenantId = tenantId,
                FirstName = firstNameClaim ?? string.Empty,
                LastName = lastNameClaim ?? string.Empty,
                EmailConfirmed = emailConfirmed,
                Roles = roles,
                Permissions = permissions
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract user info from token");
            return null;
        }
    }

    /// <summary>
    /// Token expiration kontrolü
    /// </summary>
    public async Task<bool> IsTokenExpiredAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return true;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return true;

            var jwtToken = tokenHandler.ReadJwtToken(token);
            return jwtToken.ValidTo <= DateTime.UtcNow;
        }
        catch
        {
            return true; // Fail secure
        }
    }

    #endregion

    #region Token Management

    /// <summary>
    /// Token revocation - Blacklist approach
    /// JWT'nin stateless nature nedeniyle revocation challenging
    /// </summary>
    public async Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return;

            var jwtToken = tokenHandler.ReadJwtToken(token);
            var jti = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

            if (!string.IsNullOrEmpty(jti))
            {
                // TODO: Implement blacklist with cache service
                // For now, just log the revocation
                _logger.LogInformation("Token revoked - JTI: {JTI}, Expires: {Expiration}", jti, jwtToken.ValidTo);

                // Bu implementation cache service gerektirir:
                // var blacklistKey = $"revoked_token:{jti}";
                // var expirationTime = jwtToken.ValidTo - DateTime.UtcNow;
                // await _cacheService.SetAsync(blacklistKey, "revoked", expirationTime, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke token");
            throw new InvalidOperationException($"Token revocation failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// User'ın tüm token'larını revoke etme
    /// Password change, security breach durumlarında
    /// </summary>
    public async Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Revoking all tokens for user: {UserId}", userId);

            // TODO: Implement user-based token versioning strategy
            // Options:
            // 1. User token version field'ı increment et
            // 2. User security stamp update et
            // 3. Cache-based force logout list

            await Task.CompletedTask; // Placeholder
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke all user tokens for user: {UserId}", userId);
            throw new InvalidOperationException($"Token revocation failed: {ex.Message}", ex);
        }
    }

    #endregion

    #region Token Utilities

    /// <summary>
    /// Token'dan user ID extract etme - Quick access
    /// </summary>
    public async Task<Guid?> GetUserIdFromTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return null;

            // Direct claim access (no full validation for performance)
            var jwtToken = tokenHandler.ReadJwtToken(token);
            var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;

            return Guid.TryParse(userIdClaim, out var userId) ? userId : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Token expiration time'ını getirme
    /// Client-side token management için
    /// </summary>
    public async Task<DateTime?> GetTokenExpirationAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return null;

            var jwtToken = tokenHandler.ReadJwtToken(token);
            return jwtToken.ValidTo;
        }
        catch
        {
            return null;
        }
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// JWT claims builder - Token content oluşturur
    /// </summary>
    private List<Claim> BuildAccessTokenClaims(User user, List<string> roles, List<string> permissions)
    {
        var claims = new List<Claim>
        {
            // Standard JWT claims
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email?.Value ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            
            // Custom application claims
            new("tenant_id", user.TenantId.ToString()),
            new("first_name", user.FirstName ?? string.Empty),
            new("last_name", user.LastName ?? string.Empty),
            new("email_confirmed", user.EmailConfirmed.ToString().ToLower())
        };

        // Role claims
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Permission claims
        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        return claims;
    }

    /// <summary>
    /// JWT settings configuration'dan yükleme
    /// </summary>
    private JwtSettings LoadJwtSettings()
    {
        return new JwtSettings
        {
            SecretKey = _configuration["JWT:SecretKey"] ??
                throw new InvalidOperationException("JWT:SecretKey configuration is missing"),
            Issuer = _configuration["JWT:Issuer"] ??
                throw new InvalidOperationException("JWT:Issuer configuration is missing"),
            Audience = _configuration["JWT:Audience"] ??
                throw new InvalidOperationException("JWT:Audience configuration is missing"),
            AccessTokenExpirationMinutes = int.Parse(_configuration["JWT:AccessTokenExpirationMinutes"] ?? "60"),
            RefreshTokenExpirationDays = int.Parse(_configuration["JWT:RefreshTokenExpirationDays"] ?? "7")
        };
    }

    /// <summary>
    /// JWT settings validation
    /// </summary>
    private void ValidateJwtSettings()
    {
        if (string.IsNullOrWhiteSpace(_jwtSettings.SecretKey) || _jwtSettings.SecretKey.Length < 32)
            throw new InvalidOperationException("JWT SecretKey must be at least 32 characters long");

        if (string.IsNullOrWhiteSpace(_jwtSettings.Issuer))
            throw new InvalidOperationException("JWT Issuer cannot be empty");

        if (string.IsNullOrWhiteSpace(_jwtSettings.Audience))
            throw new InvalidOperationException("JWT Audience cannot be empty");

        if (_jwtSettings.AccessTokenExpirationMinutes <= 0)
            throw new InvalidOperationException("JWT AccessTokenExpirationMinutes must be positive");

        if (_jwtSettings.RefreshTokenExpirationDays <= 0)
            throw new InvalidOperationException("JWT RefreshTokenExpirationDays must be positive");
    }

    /// <summary>
    /// Signing key oluşturma
    /// </summary>
    private SymmetricSecurityKey GetSigningKey()
    {
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
    }

    /// <summary>
    /// Token validation parameters oluşturma
    /// </summary>
    private TokenValidationParameters CreateTokenValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidAudience = _jwtSettings.Audience,
            IssuerSigningKey = GetSigningKey(),
            ClockSkew = TimeSpan.Zero // Exact expiration time validation
        };
    }

    #endregion
}