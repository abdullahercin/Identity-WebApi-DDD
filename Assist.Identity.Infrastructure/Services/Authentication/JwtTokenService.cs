using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Infrastructure.Services.Authentication;

/// <summary>
/// JWT Token Service Implementation
/// ITokenService'in concrete JWT implementation'ı
/// 
/// Infrastructure Layer: JWT specific implementation details
/// Microsoft.IdentityModel.Tokens kullanır
/// </summary>
public class JwtTokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<JwtTokenService> _logger;
    private readonly ICacheService _cacheService;

    // JWT Configuration Keys
    private const string JWT_SECTION = "JwtSettings";
    private const string JWT_SECRET_KEY = "JwtSettings:SecretKey";
    private const string JWT_ISSUER = "JwtSettings:Issuer";
    private const string JWT_AUDIENCE = "JwtSettings:Audience";
    private const string JWT_EXPIRY_MINUTES = "JwtSettings:ExpiryInMinutes";

    public JwtTokenService(
        IConfiguration configuration,
        ILogger<JwtTokenService> logger,
        ICacheService cacheService)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
    }

    #region Token Generation

    public async Task<string> GenerateAccessTokenAsync(User user, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Generating access token for user {UserId}", user.Id);

            // JWT Configuration
            var secretKey = GetSecretKey();
            var issuer = GetIssuer();
            var audience = GetAudience();
            var expiryMinutes = GetExpiryMinutes();

            // Security Key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // User domain method'larını kullan - Clean Architecture principle
            var roles = user.GetRoleNames().ToList();
            var permissions = user.GetPermissions().ToList();

            // JWT Claims - Standard ve custom claims
            var claims = new List<Claim>
            {
                // Standard JWT Claims
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email.Value ?? string.Empty),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64),

                // Custom Claims - Application specific
                new("tenant_id", user.TenantId.ToString()),
                new("first_name", user.FirstName),
                new("last_name", user.LastName),
                new("full_name", user.FullName),
                new("is_active", user.IsActive.ToString()),
                new("email_confirmed", user.EmailConfirmed.ToString())
            };

            // Role Claims - Multiple roles
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Permission Claims - Fine-grained authorization
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permission", permission));
            }

            // Phone number if exists
            if (user.PhoneNumber != null)
            {
                claims.Add(new Claim("phone_number", user.PhoneNumber.Value ?? string.Empty));
            }

            // JWT Token Generation
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(expiryMinutes),
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = credentials,

                // Additional security
                NotBefore = DateTime.UtcNow,
                IssuedAt = DateTime.UtcNow
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            _logger.LogInformation("Access token generated successfully for user {UserId}", user.Id);

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating access token for user {UserId}", user.Id);
            throw new InvalidOperationException("Failed to generate access token", ex);
        }
    }

    public async Task<string> GenerateRefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Cryptographically secure random token
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            var refreshToken = Convert.ToBase64String(randomBytes);

            _logger.LogDebug("Refresh token generated successfully");

            return await Task.FromResult(refreshToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating refresh token");
            throw new InvalidOperationException("Failed to generate refresh token", ex);
        }
    }

    #endregion

    #region Token Validation

    public async Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return false;

            var tokenHandler = new JwtSecurityTokenHandler();

            // Token format kontrolü
            if (!tokenHandler.CanReadToken(token))
                return false;

            // Validation parameters
            var validationParameters = GetTokenValidationParameters();

            // Token validation
            var result = await tokenHandler.ValidateTokenAsync(token, validationParameters);

            return result.IsValid;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Token validation failed for token: {Token}",
                token.Substring(0, Math.Min(20, token.Length)) + "...");
            return false;
        }
    }

    public async Task<TokenUserInfo?> GetUserInfoFromTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return null;

            var jsonToken = tokenHandler.ReadJwtToken(token);

            // Extract claims
            var userIdClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub);
            var emailClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email);
            var tenantIdClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "tenant_id");

            var roleClaims = jsonToken.Claims.Where(c => c.Type == ClaimTypes.Role).ToList();
            var permissionClaims = jsonToken.Claims.Where(c => c.Type == "permission").ToList();

            // Validation
            if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
                return null;

            if (tenantIdClaim == null || !Guid.TryParse(tenantIdClaim.Value, out var tenantId))
                return null;

            // TokenUserInfo oluştur
            var userInfo = new TokenUserInfo
            {
                UserId = userId,
                Email = emailClaim?.Value ?? string.Empty,
                TenantId = tenantId,
                Roles = roleClaims.Select(c => c.Value).ToList(),
                Permissions = permissionClaims.Select(c => c.Value).ToList()
            };

            return await Task.FromResult(userInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting user info from token");
            return null;
        }
    }

    public async Task<bool> IsTokenExpiredAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return true;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return true;

            var jsonToken = tokenHandler.ReadJwtToken(token);

            // Expiration claim kontrolü
            return jsonToken.ValidTo <= DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error checking token expiration");
            return true; // Error durumunda expired kabul et
        }
    }

    #endregion

    #region Token Management

    public async Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            // JWT stateless nature nedeniyle revocation için blacklist kullanıyoruz
            var tokenId = GetTokenId(token);
            if (!string.IsNullOrEmpty(tokenId))
            {
                var expiration = await GetTokenExpirationAsync(token, cancellationToken);
                var ttl = expiration?.Subtract(DateTime.UtcNow) ?? TimeSpan.FromHours(1);

                // Blacklist cache'e ekle
                await _cacheService.SetAsync($"revoked_token:{tokenId}", "true", ttl, cancellationToken);

                _logger.LogInformation("Token {TokenId} revoked successfully", tokenId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking token");
            throw new InvalidOperationException("Failed to revoke token", ex);
        }
    }

    public async Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            // User'ın tüm token'larını revoke etmek için user_revoked timestamp kullanıyoruz
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            await _cacheService.SetAsync($"user_tokens_revoked:{userId}", timestamp, TimeSpan.FromDays(30), cancellationToken);

            _logger.LogInformation("All tokens revoked for user {UserId}", userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking all tokens for user {UserId}", userId);
            throw new InvalidOperationException("Failed to revoke user tokens", ex);
        }
    }

    #endregion

    #region Token Utilities

    public async Task<Guid?> GetUserIdFromTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var userInfo = await GetUserInfoFromTokenAsync(token, cancellationToken);
        return userInfo?.UserId;
    }

    public async Task<DateTime?> GetTokenExpirationAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
                return null;

            var jsonToken = tokenHandler.ReadJwtToken(token);
            return await Task.FromResult(jsonToken.ValidTo);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error getting token expiration");
            return null;
        }
    }

    #endregion

    #region Private Helper Methods

    private string GetSecretKey()
    {
        var secretKey = _configuration[JWT_SECRET_KEY];
        if (string.IsNullOrWhiteSpace(secretKey))
            throw new InvalidOperationException("JWT Secret Key is not configured");

        if (secretKey.Length < 32)
            throw new InvalidOperationException("JWT Secret Key must be at least 32 characters long");

        return secretKey;
    }

    private string GetIssuer()
    {
        return _configuration[JWT_ISSUER] ?? "Assist.Identity";
    }

    private string GetAudience()
    {
        return _configuration[JWT_AUDIENCE] ?? "Assist.Identity.Users";
    }

    private int GetExpiryMinutes()
    {
        return _configuration.GetValue<int>(JWT_EXPIRY_MINUTES, 60); // Default 1 hour
    }

    private TokenValidationParameters GetTokenValidationParameters()
    {
        var secretKey = GetSecretKey();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidIssuer = GetIssuer(),
            ValidateAudience = true,
            ValidAudience = GetAudience(),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5), // Tolerance for time differences
            RequireExpirationTime = true
        };
    }

    private string? GetTokenId(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(token))
                return null;

            var jsonToken = tokenHandler.ReadJwtToken(token);
            return jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
        }
        catch
        {
            return null;
        }
    }

    #endregion
}