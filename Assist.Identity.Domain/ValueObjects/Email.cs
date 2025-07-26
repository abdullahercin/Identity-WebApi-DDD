using Assist.Identity.Domain.ValueObjects;

using System.Text.RegularExpressions;

/// <summary>
/// Email Value Object
/// Email validation ve normalization'ı domain seviyesinde sağlar
/// Bu sayede invalid email sisteme giremez
/// </summary>
public sealed class Email : ValueObject
{
    // RFC 5322 compliant email regex (basitleştirilmiş)
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Private constructor - Sadece factory method ile oluşturulabilir
    /// Bu approach validation'ı zorunlu kılar
    /// </summary>
    private Email(string? value)
    {
        Value = value;
    }

    /// <summary>
    /// Email value - Always normalized (lowercase, trimmed)
    /// </summary>
    public string? Value { get; }

    /// <summary>
    /// Email oluşturma factory method
    /// Validation ve normalization burada yapılır
    /// </summary>
    /// <param name="email">Email string'i</param>
    /// <returns>Validate edilmiş Email object'i</returns>
    /// <exception cref="ArgumentException">Email invalid ise</exception>
    public static Email? Create(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be empty or whitespace.", nameof(email));

        // Normalization: trim ve lowercase
        email = email.Trim().ToLowerInvariant();

        // Length validation (RFC 5321 limit)
        if (email.Length > 254)
            throw new ArgumentException("Email address is too long. Maximum length is 254 characters.", nameof(email));

        // Format validation
        if (!EmailRegex.IsMatch(email))
            throw new ArgumentException($"'{email}' is not a valid email address.", nameof(email));

        return new Email(email);
    }

    /// <summary>
    /// Email validation - Static method
    /// Object oluşturmadan validation yapmak için
    /// </summary>
    /// <param name="email">Validate edilecek email</param>
    /// <returns>Valid ise true, invalid ise false</returns>
    public static bool IsValid(string? email)
    {
        try
        {
            Create(email);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Email domain'ini extract eder
    /// Business logic'te domain-based filtering için kullanılabilir
    /// </summary>
    public string? Domain => Value?.Split('@')[1];

    /// <summary>
    /// Local part'ı extract eder (@ işaretinden önceki kısım)
    /// </summary>
    public string? LocalPart => Value?.Split('@')[0];

    /// <summary>
    /// Equality components for value object comparison
    /// </summary>
    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Value;
    }

    /// <summary>
    /// Implicit conversion - Email'den string'e otomatik dönüşüm
    /// Bu sayede Email object'i string bekleyen yerlerde kullanılabilir
    /// </summary>
    public static implicit operator string?(Email email) => email?.Value;

    /// <summary>
    /// String representation
    /// </summary>
    public override string? ToString() => Value;
}
