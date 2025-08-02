using System.ComponentModel.DataAnnotations;

namespace Assist.Identity.Infrastructure.Configuration;

/// <summary>
/// JWT Configuration Settings
/// appsettings.json'daki JWT section'ını strongly-typed olarak map eder
/// 
/// Configuration validation:
/// - Required properties ile missing configuration catch edilir
/// - Range attributes ile reasonable values enforce edilir
/// - Custom validation ile business rules check edilir
/// 
/// Security considerations:
/// - SecretKey minimum 32 karakter olmalı (256-bit)
/// - Production'da Azure Key Vault kullanılmalı
/// - Token expiration times reasonable olmalı
/// </summary>
public class JwtSettings
{
    /// <summary>
    /// JWT Section Name - Configuration binding için
    /// </summary>
    public const string SectionName = "JWT";

    /// <summary>
    /// JWT token signing için secret key
    /// 
    /// Security Requirements:
    /// - Minimum 32 karakter (256-bit güvenlik)
    /// - Random, predictable olmayan değer
    /// - Production'da environment variable veya Key Vault
    /// - Development'da bile güçlü key kullan
    /// 
    /// Format: Base64 encoded string önerilir
    /// </summary>
    [Required(ErrorMessage = "JWT SecretKey is required")]
    [MinLength(32, ErrorMessage = "JWT SecretKey must be at least 32 characters long for security")]
    public string SecretKey { get; set; } = null!;

    /// <summary>
    /// JWT Issuer - Token'ı kim oluşturdu
    /// 
    /// Standard JWT claim: "iss"
    /// Validation: Token'ın trusted source'dan geldiğini garanti eder
    /// Value: Genelde API'nin domain name'i veya identifier'ı
    /// </summary>
    [Required(ErrorMessage = "JWT Issuer is required")]
    public string Issuer { get; set; } = null!;

    /// <summary>
    /// JWT Audience - Token kimin için oluşturuldu
    /// 
    /// Standard JWT claim: "aud"
    /// Validation: Token'ın correct recipient'a gittiğini garanti eder
    /// Value: Client application identifier'ı
    /// </summary>
    [Required(ErrorMessage = "JWT Audience is required")]
    public string Audience { get; set; } = null!;

    /// <summary>
    /// Access Token expiration time (minutes)
    /// 
    /// Security vs UX balance:
    /// - Kısa süre: Daha güvenli, ama frequent token refresh
    /// - Uzun süre: Better UX, ama security risk
    /// 
    /// Recommended values:
    /// - Development: 60 minutes
    /// - Production: 15-30 minutes
    /// - High-security: 5-15 minutes
    /// </summary>
    [Range(5, 1440, ErrorMessage = "Access token expiration must be between 5 minutes and 24 hours")]
    public int AccessTokenExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Refresh Token expiration time (days)
    /// 
    /// Refresh token strategy:
    /// - Longer expiration than access token
    /// - One-time use (consumed when used)
    /// - Can be revoked for security
    /// 
    /// Recommended values:
    /// - Development: 7 days
    /// - Production: 30 days
    /// - Enterprise: 90 days
    /// </summary>
    [Range(1, 365, ErrorMessage = "Refresh token expiration must be between 1 day and 1 year")]
    public int RefreshTokenExpirationDays { get; set; } = 7;

    /// <summary>
    /// Configuration validation
    /// Startup time'da configuration'ın valid olduğunu garanti eder
    /// </summary>
    public void Validate()
    {
        var validationContext = new ValidationContext(this);
        var validationResults = new List<ValidationResult>();

        if (!Validator.TryValidateObject(this, validationContext, validationResults, true))
        {
            var errors = string.Join("; ", validationResults.Select(r => r.ErrorMessage));
            throw new InvalidOperationException($"JWT Configuration validation failed: {errors}");
        }

        // Additional business validation
        if (SecretKey.Length < 32)
        {
            throw new InvalidOperationException("JWT SecretKey must be at least 32 characters for security");
        }

        if (AccessTokenExpirationMinutes >= (RefreshTokenExpirationDays * 24 * 60))
        {
            throw new InvalidOperationException("Access token expiration should be much shorter than refresh token expiration");
        }
    }
}