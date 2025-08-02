namespace Assist.Identity.Infrastructure.Configuration;

/// <summary>
/// Email Configuration Settings
/// appsettings.json'dan email ayarlarını map eder
/// 
/// Configuration structure:
/// {
///   "Email": {
///     "Smtp": { ... },
///     "FromEmail": "...",
///     "Templates": { ... }
///   }
/// }
/// </summary>
public class EmailSettings
{
    /// <summary>
    /// Configuration section name
    /// IConfiguration.GetSection("Email") için kullanılır
    /// </summary>
    public const string SectionName = "Email";

    /// <summary>
    /// SMTP server ayarları
    /// </summary>
    public SmtpSettings Smtp { get; set; } = new();

    /// <summary>
    /// Gönderen email adresi
    /// </summary>
    public string FromEmail { get; set; } = string.Empty;

    /// <summary>
    /// Gönderen adı
    /// </summary>
    public string FromName { get; set; } = string.Empty;

    /// <summary>
    /// Reply-to email adresi (opsiyonel)
    /// </summary>
    public string? ReplyToEmail { get; set; }

    /// <summary>
    /// Support email adresi
    /// </summary>
    public string SupportEmail { get; set; } = string.Empty;

    /// <summary>
    /// Template ayarları
    /// </summary>
    public TemplateSettings Templates { get; set; } = new();

    /// <summary>
    /// Bulk email ayarları
    /// </summary>
    public BulkEmailSettings BulkEmail { get; set; } = new();
}

/// <summary>
/// SMTP Server Configuration
/// SMTP sunucu bağlantı ayarları
/// </summary>
public class SmtpSettings
{
    /// <summary>
    /// SMTP server host adresi
    /// Örnek: smtp.gmail.com, localhost
    /// </summary>
    public string Host { get; set; } = "localhost";

    /// <summary>
    /// SMTP server port
    /// Genelde: 587 (TLS), 465 (SSL), 25 (unsecured)
    /// </summary>
    public int Port { get; set; } = 587;

    /// <summary>
    /// SMTP authentication username
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// SMTP authentication password
    /// Production'da secrets manager kullanılmalı
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// SSL/TLS enable durumu
    /// Modern SMTP servers için true olmalı
    /// </summary>
    public bool EnableSsl { get; set; } = true;

    /// <summary>
    /// Connection timeout (milliseconds)
    /// Default: 30 saniye
    /// </summary>
    public int TimeoutMs { get; set; } = 30000;

    /// <summary>
    /// SMTP settings validation
    /// Critical alanların dolu olduğunu kontrol eder
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host))
            throw new InvalidOperationException("SMTP Host is required");

        if (Port <= 0 || Port > 65535)
            throw new InvalidOperationException($"Invalid SMTP Port: {Port}");

        if (TimeoutMs <= 0)
            throw new InvalidOperationException($"Invalid timeout: {TimeoutMs}ms");
    }
}

/// <summary>
/// Email Template Configuration
/// Template sistemi ayarları
/// </summary>
public class TemplateSettings
{
    /// <summary>
    /// Template'ların bulunduğu klasör
    /// File-based template system için
    /// </summary>
    public string? TemplateDirectory { get; set; }

    /// <summary>
    /// Template cache süresini (dakika)
    /// Performance optimization için
    /// </summary>
    public int CacheMinutes { get; set; } = 60;

    /// <summary>
    /// Default template language
    /// Multi-language support için
    /// </summary>
    public string DefaultLanguage { get; set; } = "en";

    /// <summary>
    /// Template engine type
    /// "Embedded", "File", "Razor" vs.
    /// </summary>
    public string EngineType { get; set; } = "Embedded";
}

/// <summary>
/// Bulk Email Configuration
/// Toplu email gönderimi için ayarlar
/// </summary>
public class BulkEmailSettings
{
    /// <summary>
    /// Maksimum concurrent email sayısı
    /// Rate limiting için kullanılır
    /// </summary>
    public int MaxConcurrentEmails { get; set; } = 5;

    /// <summary>
    /// Batch size - Kaç emailde bir pause
    /// Büyük listeler için memory management
    /// </summary>
    public int BatchSize { get; set; } = 100;

    /// <summary>
    /// Batch'ler arası bekleme süresi (milliseconds)
    /// Provider rate limiting için
    /// </summary>
    public int BatchDelayMs { get; set; } = 1000;

    /// <summary>
    /// Maximum retry attempts
    /// Başarısız email'ler için retry logic
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Retry delay (milliseconds)
    /// Exponential backoff için base delay
    /// </summary>
    public int RetryDelayMs { get; set; } = 5000;

    /// <summary>
    /// Bulk email validation
    /// Settings'lerin reasonable olduğunu kontrol eder
    /// </summary>
    public void Validate()
    {
        if (MaxConcurrentEmails <= 0 || MaxConcurrentEmails > 50)
            throw new InvalidOperationException($"MaxConcurrentEmails must be between 1-50, got: {MaxConcurrentEmails}");

        if (BatchSize <= 0 || BatchSize > 10000)
            throw new InvalidOperationException($"BatchSize must be between 1-10000, got: {BatchSize}");
    }
}

/// <summary>
/// App Configuration
/// Frontend URL'leri ve app-specific ayarlar
/// </summary>
public class AppSettings
{
    public const string SectionName = "App";

    /// <summary>
    /// Application base URL
    /// Email'lerdeki link'ler için kullanılır
    /// </summary>
    public string BaseUrl { get; set; } = "https://localhost:5000";

    /// <summary>
    /// Frontend route'ları
    /// Email template'lerinde kullanılır
    /// </summary>
    public UrlSettings Urls { get; set; } = new();
}

/// <summary>
/// URL Configuration
/// Email'lerde kullanılan frontend route'ları
/// </summary>
public class UrlSettings
{
    public string Login { get; set; } = "/login";
    public string EmailConfirmation { get; set; } = "/confirm-email";
    public string PasswordReset { get; set; } = "/reset-password";
    public string SecuritySettings { get; set; } = "/security";
    public string Dashboard { get; set; } = "/dashboard";
}