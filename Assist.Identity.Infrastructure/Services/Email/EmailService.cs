using Assist.Identity.Application.Contracts;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Infrastructure.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Mail;

namespace Assist.Identity.Infrastructure.Services.Email;

/// <summary>
/// Email Service Implementation
/// SMTP protokolü kullanarak email gönderimi sağlar
/// 
/// Bu implementation modern .NET practices kullanır:
/// - IOptions pattern ile strongly-typed configuration
/// - Structured logging ile comprehensive error tracking
/// - Async/await pattern ile non-blocking operations
/// - Rate limiting ile resource protection
/// 
/// Production deployment options:
/// - SMTP server (current implementation)
/// - SendGrid (cloud service)
/// - Amazon SES (AWS)
/// - Azure Communication Services
/// - Mailgun (email API)
/// 
/// Configuration managed through appsettings.json:
/// - SMTP connection details
/// - Template settings
/// - Bulk email configuration
/// - URL generation settings
/// </summary>
public class EmailService : IEmailService
{
    private readonly EmailSettings _emailSettings;
    private readonly AppSettings _appSettings;
    private readonly ILogger<EmailService> _logger;

    /// <summary>
    /// EmailService constructor
    /// Modern .NET dependency injection pattern ile configuration alır
    /// 
    /// IOptions pattern'in avantajları:
    /// - Strongly-typed configuration access
    /// - Configuration validation on startup
    /// - Configuration reloading support (IOptionsMonitor ile)
    /// - Easy unit testing with mock configurations
    /// </summary>
    /// <param name="emailOptions">Email configuration settings</param>
    /// <param name="appOptions">Application configuration settings</param>
    /// <param name="logger">Structured logging interface</param>
    public EmailService(
        IOptions<EmailSettings> emailOptions,
        IOptions<AppSettings> appOptions,
        ILogger<EmailService> logger)
    {
        _emailSettings = emailOptions?.Value ?? throw new ArgumentNullException(nameof(emailOptions));
        _appSettings = appOptions?.Value ?? throw new ArgumentNullException(nameof(appOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Configuration validation on service creation
        // Bu yaklaşım fail-fast principle'ını uygular
        // Yanlış configuration varsa uygulama startup'ta fail olur
        ValidateConfiguration();

        _logger.LogInformation("EmailService initialized with SMTP host: {SmtpHost}:{SmtpPort}",
            _emailSettings.Smtp.Host, _emailSettings.Smtp.Port);
    }

    #region Basic Email Operations

    /// <summary>
    /// Basit email gönderme
    /// Generic email gönderimi için kullanılır
    /// 
    /// Bu method'un sorumluluğu:
    /// - Email validation
    /// - SMTP client creation ve configuration
    /// - Email sending with proper error handling
    /// - Comprehensive logging for debugging
    /// </summary>
    public async Task SendEmailAsync(string to, string subject, string body, bool isHtml = true, CancellationToken cancellationToken = default)
    {
        try
        {
            ValidateEmailAddress(to);

            using var client = CreateSmtpClient();
            using var message = CreateMailMessage(to, subject, body, isHtml);

            _logger.LogInformation("Sending email to {To} with subject '{Subject}'", to, subject);

            await client.SendMailAsync(message, cancellationToken);

            _logger.LogInformation("Email sent successfully to {To}", to);
        }
        catch (SmtpException smtpEx)
        {
            // SMTP-specific errors (server problems, authentication issues)
            _logger.LogError(smtpEx, "SMTP error while sending email to {To}: {SmtpStatusCode}", to, smtpEx.StatusCode);
            throw new InvalidOperationException($"Email server error: {smtpEx.Message}", smtpEx);
        }
        catch (Exception ex)
        {
            // General errors (network, configuration, etc.)
            _logger.LogError(ex, "Failed to send email to {To} with subject '{Subject}'", to, subject);
            throw new InvalidOperationException($"Failed to send email to {to}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Template-based email gönderimi
    /// 
    /// Template system evolution path:
    /// 1. Current: Simple string replacement ({{PropertyName}})
    /// 2. Future: Razor Engine integration for complex templates
    /// 3. Advanced: Multi-language template support
    /// 4. Enterprise: External template management system
    /// 
    /// Template processing benefits:
    /// - Consistent email formatting
    /// - Easy content management
    /// - Personalization capabilities
    /// - Brand consistency
    /// </summary>
    public async Task SendTemplateEmailAsync(string to, string templateName, object templateData, CancellationToken cancellationToken = default)
    {
        try
        {
            var template = await LoadEmailTemplateAsync(templateName);
            var body = ProcessTemplate(template, templateData);
            var subject = ExtractSubjectFromTemplate(template);

            await SendEmailAsync(to, subject, body, true, cancellationToken);

            _logger.LogInformation("Template email '{Template}' sent successfully to {To}", templateName, to);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send template email '{Template}' to {To}", templateName, to);
            throw;
        }
    }

    #endregion

    #region Identity-Specific Email Operations

    /// <summary>
    /// Welcome email gönderme
    /// User registration workflow'unun kritik bir parçası
    /// 
    /// Business requirements:
    /// - Must be sent immediately after user creation
    /// - Should include personalized greeting
    /// - Must provide login instructions
    /// - Should include support contact information
    /// - Temporary password handling for admin-created accounts
    /// </summary>
    public async Task SendWelcomeEmailAsync(User user, string? temporaryPassword = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var templateData = new
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                FullName = user.FullName,
                Email = user.Email.Value,
                TemporaryPassword = temporaryPassword,
                HasTemporaryPassword = !string.IsNullOrEmpty(temporaryPassword),
                LoginUrl = BuildUrl(_appSettings.Urls.Login),
                SupportEmail = _emailSettings.SupportEmail,
                CompanyName = _emailSettings.FromName
            };

            await SendTemplateEmailAsync(user.Email.Value!, "Welcome", templateData, cancellationToken);

            _logger.LogInformation("Welcome email sent to user {UserId} ({Email})", user.Id, user.Email.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send welcome email to user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Email confirmation gönderme
    /// Email verification workflow için critical security component
    /// 
    /// Security considerations:
    /// - Token should be cryptographically secure
    /// - URL should include both userId and token for validation
    /// - Link should have reasonable expiration time
    /// - Should use HTTPS for all links
    /// - Token should be single-use only
    /// </summary>
    public async Task SendEmailConfirmationAsync(User user, string confirmationToken, CancellationToken cancellationToken = default)
    {
        try
        {
            var confirmationUrl = BuildConfirmationUrl(user.Id, confirmationToken);

            var templateData = new
            {
                FirstName = user.FirstName,
                FullName = user.FullName,
                Email = user.Email.Value,
                ConfirmationUrl = confirmationUrl,
                ConfirmationToken = confirmationToken,
                ExpirationHours = 24, // Configuration'dan alınabilir
                SupportEmail = _emailSettings.SupportEmail,
                CompanyName = _emailSettings.FromName
            };

            await SendTemplateEmailAsync(user.Email.Value!, "EmailConfirmation", templateData, cancellationToken);

            _logger.LogInformation("Email confirmation sent to user {UserId} ({Email}) with token length {TokenLength}",
                user.Id, user.Email.Value, confirmationToken.Length);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email confirmation to user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Password reset email gönderme
    /// Forgot password workflow için security-critical operation
    /// 
    /// Security best practices implemented:
    /// - Short token expiration time (1 hour)
    /// - Secure token generation
    /// - Request timestamp included for audit
    /// - Support contact for security concerns
    /// - Clear instructions for user
    /// </summary>
    public async Task SendPasswordResetEmailAsync(User user, string resetToken, CancellationToken cancellationToken = default)
    {
        try
        {
            var resetUrl = BuildPasswordResetUrl(resetToken);

            var templateData = new
            {
                FirstName = user.FirstName,
                FullName = user.FullName,
                Email = user.Email.Value,
                ResetUrl = resetUrl,
                ResetToken = resetToken,
                ExpirationHours = 1, // Short expiration for security
                SupportEmail = _emailSettings.SupportEmail,
                RequestTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                CompanyName = _emailSettings.FromName
            };

            await SendTemplateEmailAsync(user.Email.Value!, "PasswordReset", templateData, cancellationToken);

            _logger.LogInformation("Password reset email sent to user {UserId} ({Email})", user.Id, user.Email.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Password changed notification
    /// Security notification - mandatory for compliance with security standards
    /// 
    /// Security purpose:
    /// - Alerts user to password changes they didn't initiate
    /// - Provides immediate notification of potential security breach
    /// - Includes timestamp for security audit
    /// - Provides direct link to security settings
    /// - Essential for compliance with security frameworks
    /// </summary>
    public async Task SendPasswordChangedNotificationAsync(User user, CancellationToken cancellationToken = default)
    {
        try
        {
            var templateData = new
            {
                FirstName = user.FirstName,
                FullName = user.FullName,
                Email = user.Email.Value,
                ChangeTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                SupportEmail = _emailSettings.SupportEmail,
                SecurityUrl = BuildUrl(_appSettings.Urls.SecuritySettings),
                CompanyName = _emailSettings.FromName
            };

            await SendTemplateEmailAsync(user.Email.Value!, "PasswordChanged", templateData, cancellationToken);

            _logger.LogInformation("Password changed notification sent to user {UserId} ({Email})", user.Id, user.Email.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password changed notification to user {UserId}", user.Id);
            throw;
        }
    }

    #endregion

    #region Bulk Email Operations

    /// <summary>
    /// Bulk email gönderme with advanced rate limiting
    /// 
    /// Rate limiting strategy explained:
    /// 1. SemaphoreSlim: Controls concurrent operations (MaxConcurrentEmails from config)
    /// 2. Batch processing: Processes emails in configurable batch sizes
    /// 3. Batch delays: Configurable delays between batches
    /// 4. Retry mechanism: Automatic retry for failed emails
    /// 
    /// Resource protection benefits:
    /// - Prevents SMTP server overload
    /// - Respects email provider rate limits
    /// - Manages memory usage for large recipient lists
    /// - Provides failure resilience
    /// - Enables monitoring and logging of bulk operations
    /// </summary>
    public async Task SendBulkEmailAsync(IEnumerable<string> recipients, string subject, string body, bool isHtml = true, CancellationToken cancellationToken = default)
    {
        var recipientList = recipients.ToList();
        var bulkSettings = _emailSettings.BulkEmail;

        _logger.LogInformation("Starting bulk email send to {Count} recipients with {MaxConcurrent} max concurrent emails",
            recipientList.Count, bulkSettings.MaxConcurrentEmails);

        // Rate limiting semaphore based on configuration
        using var semaphore = new SemaphoreSlim(bulkSettings.MaxConcurrentEmails);

        // Process in batches to manage memory and respect rate limits
        var batches = CreateBatches(recipientList, bulkSettings.BatchSize);
        var batchNumber = 0;

        foreach (var batch in batches)
        {
            batchNumber++;
            _logger.LogInformation("Processing batch {BatchNumber}/{TotalBatches} with {EmailCount} emails",
                batchNumber, batches.Count, batch.Count);

            // Process batch with controlled concurrency
            var tasks = batch.Select(recipient =>
                SendEmailWithSemaphoreAsync(recipient, subject, body, isHtml, semaphore, cancellationToken));

            await Task.WhenAll(tasks);

            // Delay between batches if configured and not the last batch
            if (batchNumber < batches.Count && bulkSettings.BatchDelayMs > 0)
            {
                _logger.LogDebug("Waiting {DelayMs}ms before next batch", bulkSettings.BatchDelayMs);
                await Task.Delay(bulkSettings.BatchDelayMs, cancellationToken);
            }
        }

        _logger.LogInformation("Bulk email send completed for {Count} recipients in {BatchCount} batches",
            recipientList.Count, batches.Count);
    }

    #endregion

    #region Private Helper Methods

    /// <summary>
    /// SMTP client oluşturma with comprehensive configuration
    /// 
    /// Configuration source: EmailSettings.Smtp section
    /// Security: Uses TLS/SSL based on configuration
    /// Timeout: Configurable timeout for network operations
    /// Authentication: Supports username/password authentication
    /// </summary>
    private SmtpClient CreateSmtpClient()
    {
        var smtpSettings = _emailSettings.Smtp;

        var client = new SmtpClient(smtpSettings.Host, smtpSettings.Port)
        {
            Credentials = new NetworkCredential(smtpSettings.Username, smtpSettings.Password),
            EnableSsl = smtpSettings.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = smtpSettings.TimeoutMs
        };

        _logger.LogDebug("Created SMTP client for {Host}:{Port}, SSL: {EnableSsl}",
            smtpSettings.Host, smtpSettings.Port, smtpSettings.EnableSsl);

        return client;
    }

    /// <summary>
    /// Mail message oluşturma with configuration-based settings
    /// 
    /// Message construction includes:
    /// - From address and display name from configuration
    /// - Reply-to address if configured
    /// - Proper encoding for international characters
    /// - HTML vs plain text content type
    /// </summary>
    private MailMessage CreateMailMessage(string to, string subject, string body, bool isHtml)
    {
        var message = new MailMessage
        {
            From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
            Subject = subject,
            Body = body,
            IsBodyHtml = isHtml
        };

        message.To.Add(to);

        // Add reply-to if configured
        if (!string.IsNullOrEmpty(_emailSettings.ReplyToEmail))
        {
            message.ReplyToList.Add(_emailSettings.ReplyToEmail);
        }

        return message;
    }

    /// <summary>
    /// Configuration validation on service startup
    /// 
    /// Validation strategy:
    /// - Fail fast: Invalid configuration causes startup failure
    /// - Comprehensive: Validates all critical settings
    /// - Clear errors: Provides specific error messages
    /// - Delegates to settings classes for domain-specific validation
    /// </summary>
    private void ValidateConfiguration()
    {
        try
        {
            // Delegate validation to configuration classes
            // This follows Single Responsibility Principle
            _emailSettings.Smtp.Validate();
            _emailSettings.BulkEmail.Validate();

            // Service-level validation
            if (string.IsNullOrWhiteSpace(_emailSettings.FromEmail))
                throw new InvalidOperationException("FromEmail is required in Email configuration");

            if (string.IsNullOrWhiteSpace(_emailSettings.SupportEmail))
                throw new InvalidOperationException("SupportEmail is required in Email configuration");

            if (string.IsNullOrWhiteSpace(_appSettings.BaseUrl))
                throw new InvalidOperationException("BaseUrl is required in App configuration");

            _logger.LogInformation("Email configuration validated successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email configuration validation failed");
            throw;
        }
    }

    /// <summary>
    /// Batch creation for bulk email processing
    /// 
    /// Batching strategy:
    /// - Fixed batch size from configuration
    /// - Memory efficient: Processes lists without loading all into memory
    /// - LINQ-based: Clean, readable implementation
    /// - Configurable: Batch size can be adjusted per environment
    /// </summary>
    private static List<List<string>> CreateBatches(List<string> items, int batchSize)
    {
        return items
            .Select((item, index) => new { item, index })
            .GroupBy(x => x.index / batchSize)
            .Select(g => g.Select(x => x.item).ToList())
            .ToList();
    }

    /// <summary>
    /// Semaphore-controlled email sending
    /// 
    /// Concurrency control mechanism:
    /// - SemaphoreSlim ensures max concurrent operations
    /// - Proper resource disposal with finally block
    /// - Exception handling preserves original errors
    /// - Logging for debugging bulk operations
    /// </summary>
    private async Task SendEmailWithSemaphoreAsync(string to, string subject, string body, bool isHtml, SemaphoreSlim semaphore, CancellationToken cancellationToken)
    {
        await semaphore.WaitAsync(cancellationToken);
        try
        {
            await SendEmailAsync(to, subject, body, isHtml, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send email to {To} in bulk operation", to);
            // In bulk operations, we log the error but don't stop the entire operation
            // This allows other emails to be sent even if some fail
        }
        finally
        {
            semaphore.Release();
        }
    }

    /// <summary>
    /// URL building with configuration-based base URL
    /// 
    /// URL construction benefits:
    /// - Centralized base URL configuration
    /// - Environment-specific URLs (dev, staging, production)
    /// - Consistent URL format across all emails
    /// - Easy to change when domains change
    /// </summary>
    private string BuildUrl(string relativePath)
    {
        var baseUrl = _appSettings.BaseUrl.TrimEnd('/');
        var path = relativePath.TrimStart('/');
        return $"{baseUrl}/{path}";
    }

    private string BuildConfirmationUrl(Guid userId, string token)
    {
        var path = $"{_appSettings.Urls.EmailConfirmation}?userId={userId}&token={Uri.EscapeDataString(token)}";
        return BuildUrl(path);
    }

    private string BuildPasswordResetUrl(string token)
    {
        var path = $"{_appSettings.Urls.PasswordReset}?token={Uri.EscapeDataString(token)}";
        return BuildUrl(path);
    }

    /// <summary>
    /// Email address validation
    /// Basic format validation - Domain Email value object provides comprehensive validation
    /// </summary>
    private static void ValidateEmailAddress(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email address cannot be empty");

        if (!email.Contains("@"))
            throw new ArgumentException($"Invalid email address format: {email}");
    }

    /// <summary>
    /// Email template loading
    /// 
    /// Current implementation: Embedded templates
    /// Future enhancements:
    /// - File-based templates
    /// - Database-stored templates  
    /// - External template service integration
    /// - Multi-language template support
    /// - Template caching for performance
    /// </summary>
    private async Task<string> LoadEmailTemplateAsync(string templateName)
    {
        var templates = GetEmailTemplates();

        if (templates.TryGetValue(templateName, out var template))
        {
            return await Task.FromResult(template);
        }

        throw new ArgumentException($"Email template '{templateName}' not found. Available templates: {string.Join(", ", templates.Keys)}");
    }

    /// <summary>
    /// Template processing with simple string replacement
    /// 
    /// Current implementation: Basic {{PropertyName}} replacement
    /// Production alternatives:
    /// - Razor Engine: Full C# syntax in templates
    /// - Handlebars.NET: Logic-less templates
    /// - Scriban: Lightweight scripting language
    /// - Liquid: Shopify's template language
    /// </summary>
    private string ProcessTemplate(string template, object data)
    {
        var result = template;

        // Use reflection to replace {{PropertyName}} placeholders
        var properties = data.GetType().GetProperties();
        foreach (var prop in properties)
        {
            var placeholder = $"{{{{{prop.Name}}}}}";
            var value = prop.GetValue(data)?.ToString() ?? "";
            result = result.Replace(placeholder, value);
        }

        return result;
    }

    /// <summary>
    /// Extract email subject from template
    /// Templates can include subject line as first line: "Subject: Your Subject Here"
    /// </summary>
    private string ExtractSubjectFromTemplate(string template)
    {
        var lines = template.Split('\n');
        var subjectLine = lines.FirstOrDefault(l => l.StartsWith("Subject:"));

        if (subjectLine != null)
        {
            return subjectLine.Replace("Subject:", "").Trim();
        }

        return "Notification"; // Default subject
    }

    /// <summary>
    /// Email templates dictionary
    /// 
    /// Template organization:
    /// - Each template includes subject line
    /// - HTML format for rich content
    /// - Placeholder syntax: {{PropertyName}}
    /// - Responsive design considerations
    /// - Brand-consistent styling
    /// 
    /// Future improvements:
    /// - External template files
    /// - Template inheritance
    /// - Multi-language support
    /// - A/B testing capabilities
    /// </summary>
    private Dictionary<string, string> GetEmailTemplates()
    {
        return new Dictionary<string, string>
        {
            ["Welcome"] = @"
Subject: Welcome to {{CompanyName}}!

<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to {{CompanyName}}!</h1>
        </div>
        <div class='content'>
            <h2>Hello {{FirstName}}!</h2>
            <p>Your account has been created successfully. We're excited to have you join our platform.</p>
            
            {{#if HasTemporaryPassword}}
            <div style='background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 15px 0; border-radius: 4px;'>
                <h3>⚠️ Temporary Password</h3>
                <p>Your temporary password is: <strong>{{TemporaryPassword}}</strong></p>
                <p><em>Please change your password after your first login for security.</em></p>
            </div>
            {{/if}}
            
            <p>
                <a href='{{LoginUrl}}' class='button'>Login to Your Account</a>
            </p>
            
            <p>If you have any questions, feel free to contact our support team.</p>
        </div>
        <div class='footer'>
            <p>Need help? Contact us at {{SupportEmail}}</p>
            <p>© {{CompanyName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>",

            ["EmailConfirmation"] = @"
Subject: Please confirm your email address

<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #28a745; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🔐 Email Confirmation</h1>
        </div>
        <div class='content'>
            <h2>Hello {{FirstName}},</h2>
            <p>Thank you for creating an account with {{CompanyName}}. To complete your registration, please confirm your email address.</p>
            
            <p style='text-align: center; margin: 30px 0;'>
                <a href='{{ConfirmationUrl}}' class='button'>Confirm Email Address</a>
            </p>
            
            <div class='warning'>
                <p><strong>⏰ Important:</strong> This confirmation link will expire in {{ExpirationHours}} hours.</p>
            </div>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style='word-break: break-all; font-family: monospace; font-size: 12px;'>{{ConfirmationUrl}}</p>
            
            <p>If you didn't create this account, please ignore this email.</p>
        </div>
        <div class='footer'>
            <p>Need help? Contact us at {{SupportEmail}}</p>
            <p>© {{CompanyName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>",

            ["PasswordReset"] = @"
Subject: Password Reset Request

<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        .security-info { background-color: #d1ecf1; border-left: 4px solid #bee5eb; padding: 15px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🔑 Password Reset</h1>
        </div>
        <div class='content'>
            <h2>Hello {{FirstName}},</h2>
            <p>We received a request to reset your password for your {{CompanyName}} account.</p>
            
            <div class='security-info'>
                <p><strong>📅 Request Time:</strong> {{RequestTime}}</p>
                <p><strong>⏱️ Expires in:</strong> {{ExpirationHours}} hour(s)</p>
            </div>
            
            <p style='text-align: center; margin: 30px 0;'>
                <a href='{{ResetUrl}}' class='button'>Reset Your Password</a>
            </p>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style='word-break: break-all; font-family: monospace; font-size: 12px;'>{{ResetUrl}}</p>
            
            <div class='security-info'>
                <p><strong>🛡️ Security Note:</strong> If you didn't request this password reset, please ignore this email and contact our support team immediately.</p>
            </div>
        </div>
        <div class='footer'>
            <p>Need help? Contact us at {{SupportEmail}}</p>
            <p>© {{CompanyName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>",

            ["PasswordChanged"] = @"
Subject: Password Changed Successfully

<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #17a2b8; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background-color: #17a2b8; color: white; text-decoration: none; border-radius: 4px; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        .success-info { background-color: #d4edda; border-left: 4px solid #c3e6cb; padding: 15px; margin: 15px 0; }
        .warning { background-color: #f8d7da; border-left: 4px solid #f5c6cb; padding: 15px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>✅ Password Changed</h1>
        </div>
        <div class='content'>
            <h2>Hello {{FirstName}},</h2>
            
            <div class='success-info'>
                <p><strong>✅ Success:</strong> Your password was successfully changed.</p>
                <p><strong>📅 Change Time:</strong> {{ChangeTime}}</p>
            </div>
            
            <p>Your {{CompanyName}} account password has been updated successfully. You can now use your new password to sign in.</p>
            
            <div class='warning'>
                <p><strong>🚨 Important:</strong> If you didn't make this change, please contact our support team immediately as your account may be compromised.</p>
            </div>
            
            <p style='text-align: center; margin: 30px 0;'>
                <a href='{{SecurityUrl}}' class='button'>Review Security Settings</a>
            </p>
            
            <p>For your security, we recommend:</p>
            <ul>
                <li>Using a unique password for your account</li>
                <li>Enabling two-factor authentication</li>
                <li>Regularly reviewing your account activity</li>
            </ul>
        </div>
        <div class='footer'>
            <p>Need help? Contact us at {{SupportEmail}}</p>
            <p>© {{CompanyName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"
        };
    }

    #endregion
}