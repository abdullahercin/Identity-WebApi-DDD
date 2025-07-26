namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Account Locked Exception
/// Kilitli account ile login denemesi yapıldığında fırlatılır
/// </summary>
public class AccountLockedException : DomainException
{
    /// <summary>
    /// AccountLockedException constructor
    /// </summary>
    /// <param name="email">Locked account email</param>
    /// <param name="lockedUntil">Lock expiration time</param>
    public AccountLockedException(string email, DateTime lockedUntil) 
        : base($"Account '{email}' is locked until {lockedUntil:yyyy-MM-dd HH:mm} UTC.")
    {
        Email = email;
        LockedUntil = lockedUntil;
    }

    /// <summary>
    /// AccountLockedException constructor with reason
    /// </summary>
    /// <param name="email">Locked account email</param>
    /// <param name="lockedUntil">Lock expiration time</param>
    /// <param name="reason">Lock reason</param>
    public AccountLockedException(string email, DateTime lockedUntil, string reason) 
        : base($"Account '{email}' is locked until {lockedUntil:yyyy-MM-dd HH:mm} UTC. Reason: {reason}")
    {
        Email = email;
        LockedUntil = lockedUntil;
        Reason = reason;
    }

    /// <summary>
    /// Kilitli account'un email'i
    /// </summary>
    public string Email { get; }

    /// <summary>
    /// Lock'un bittiği zaman
    /// </summary>
    public DateTime LockedUntil { get; }

    /// <summary>
    /// Lock nedeni
    /// </summary>
    public string Reason { get; }

    /// <summary>
    /// Remaining lock time
    /// </summary>
    public TimeSpan RemainingLockTime => LockedUntil > DateTime.UtcNow ? LockedUntil - DateTime.UtcNow : TimeSpan.Zero;

    /// <summary>
    /// Is still locked check
    /// </summary>
    public bool IsStillLocked => DateTime.UtcNow < LockedUntil;

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "Authentication";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "ACCOUNT_LOCKED";
}