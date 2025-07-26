using Assist.Identity.Domain.Entities;

namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Email Service Contract
/// Email sending operations
/// SMTP, SendGrid gibi farklı providers destekler
/// </summary>
public interface IEmailService
{
    #region Basic Email Operations

    /// <summary>
    /// Basit email gönderme
    /// </summary>
    /// <param name="to">Alıcı email adresi</param>
    /// <param name="subject">Email subject'i</param>
    /// <param name="body">Email body (HTML veya plain text)</param>
    /// <param name="isHtml">Body HTML mi</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendEmailAsync(string to, string subject, string body, bool isHtml = true, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email template ile gönderim
    /// </summary>
    /// <param name="to">Alıcı email adresi</param>
    /// <param name="templateName">Template adı</param>
    /// <param name="templateData">Template'de kullanılacak data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendTemplateEmailAsync(string to, string templateName, object templateData, CancellationToken cancellationToken = default);

    #endregion

    #region Identity-Specific Email Operations

    /// <summary>
    /// Welcome email gönderme
    /// User registration sonrasında
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="temporaryPassword">Geçici password (varsa)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendWelcomeEmailAsync(User user, string? temporaryPassword = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email confirmation gönderme
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="confirmationToken">Confirmation token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendEmailConfirmationAsync(User user, string confirmationToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Password reset email gönderme
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="resetToken">Reset token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendPasswordResetEmailAsync(User user, string resetToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Password changed notification
    /// Security notification
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendPasswordChangedNotificationAsync(User user, CancellationToken cancellationToken = default);

    #endregion

    #region Bulk Email Operations

    /// <summary>
    /// Bulk email gönderme
    /// Admin notifications için
    /// </summary>
    /// <param name="recipients">Alıcı listesi</param>
    /// <param name="subject">Email subject'i</param>
    /// <param name="body">Email body</param>
    /// <param name="isHtml">Body HTML mi</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendBulkEmailAsync(IEnumerable<string> recipients, string subject, string body, bool isHtml = true, CancellationToken cancellationToken = default);

    #endregion
}