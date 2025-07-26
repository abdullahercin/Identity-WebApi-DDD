namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Email Not Confirmed Exception
/// Email doğrulanmadan yapılamayan işlem denendiğinde fırlatılır
/// </summary>
public class EmailNotConfirmedException : DomainException
{
    /// <summary>
    /// EmailNotConfirmedException constructor
    /// </summary>
    /// <param name="email">Unconfirmed email</param>
    public EmailNotConfirmedException(string email) 
        : base($"Email address '{email}' must be confirmed before performing this action.")
    {
        Email = email;
    }

    /// <summary>
    /// EmailNotConfirmedException constructor with action
    /// </summary>
    /// <param name="email">Unconfirmed email</param>
    /// <param name="attemptedAction">Attempted action</param>
    public EmailNotConfirmedException(string email, string attemptedAction) 
        : base($"Email address '{email}' must be confirmed before {attemptedAction}.")
    {
        Email = email;
        AttemptedAction = attemptedAction;
    }

    /// <summary>
    /// Doğrulanmamış email adresi
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Denenen işlem
    /// </summary>
    public string AttemptedAction { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "Authentication";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "EMAIL_NOT_CONFIRMED";
}