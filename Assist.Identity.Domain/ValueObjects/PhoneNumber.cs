using Assist.Identity.Domain.ValueObjects;
using System.Text.RegularExpressions;

/// <summary>
/// PhoneNumber Value Object
/// Uluslararası telefon numarası format validation'ı sağlar
/// ITU-T E.164 standardına uygun format destekler
/// </summary>
public sealed class PhoneNumber : ValueObject
{
    // International phone number regex - E.164 format
    private static readonly Regex PhoneRegex = new(
        @"^\+(\d{1,3})\s?(\d{1,4})\s?(\d{1,4})\s?(\d{1,4})$",
        RegexOptions.Compiled);

    /// <summary>
    /// Private constructor
    /// </summary>
    private PhoneNumber(string? value, string? countryCode, string? nationalNumber)
    {
        Value = value;
        CountryCode = countryCode;
        NationalNumber = nationalNumber;
    }

    /// <summary>
    /// Full phone number with country code (+90 532 123 45 67)
    /// </summary>
    public string? Value { get; }

    /// <summary>
    /// Country code (90 for Turkey)
    /// </summary>
    public string? CountryCode { get; }

    /// <summary>
    /// National number without country code
    /// </summary>
    public string? NationalNumber { get; }

    /// <summary>
    /// PhoneNumber oluşturma factory method
    /// </summary>
    /// <param name="phoneNumber">International format phone number</param>
    /// <returns>Validate edilmiş PhoneNumber object'i</returns>
    public static PhoneNumber Create(string? phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
            throw new ArgumentException("Phone number cannot be empty.", nameof(phoneNumber));

        // Normalize - sadece rakamlar ve + işareti kalsın
        var normalized = Regex.Replace(phoneNumber.Trim(), @"[^\d+]", " ");
        normalized = Regex.Replace(normalized, @"\s+", " ").Trim();

        if (!normalized.StartsWith("+"))
            throw new ArgumentException("Phone number must start with country code (+).", nameof(phoneNumber));

        if (normalized.Length < 8 || normalized.Length > 18)
            throw new ArgumentException("Phone number length is invalid.", nameof(phoneNumber));

        var match = PhoneRegex.Match(normalized);
        if (!match.Success)
            throw new ArgumentException($"'{phoneNumber}' is not a valid international phone number format. Use: +90 532 123 45 67", nameof(phoneNumber));

        var countryCode = match.Groups[1].Value;
        var nationalParts = match.Groups.Cast<Group>().Skip(2).Select(g => g.Value).Where(v => !string.IsNullOrEmpty(v));
        var nationalNumber = string.Join("", nationalParts);

        // Country code validation (1-3 digits)
        if (countryCode.Length < 1 || countryCode.Length > 3)
            throw new ArgumentException("Invalid country code.", nameof(phoneNumber));

        return new PhoneNumber(normalized, countryCode, nationalNumber);
    }

    /// <summary>
    /// Phone number validation
    /// </summary>
    /// <param name="phoneNumber">Validate edilecek phone number</param>
    /// <returns>Valid ise true</returns>
    public static bool IsValid(string? phoneNumber)
    {
        try
        {
            Create(phoneNumber);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Display format (with spaces)
    /// </summary>
    public string? ToDisplayFormat()
    {
        return Value;
    }

    /// <summary>
    /// Compact format (no spaces)
    /// </summary>
    public string ToCompactFormat()
    {
        return $"+{CountryCode}{NationalNumber}";
    }

    /// <summary>
    /// National format (without country code)
    /// </summary>
    public string ToNationalFormat()
    {
        // Turkey format örneği: 0532 123 45 67
        if (NationalNumber != null && CountryCode == "90" && NationalNumber.Length == 10)
        {
            return $"0{NationalNumber.Substring(0, 3)} {NationalNumber.Substring(3, 3)} {NationalNumber.Substring(6, 2)} {NationalNumber.Substring(8, 2)}";
        }

        // Generic format
        return "0" + NationalNumber;
    }

    /// <summary>
    /// Equality components
    /// </summary>
    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return CountryCode;
        yield return NationalNumber;
    }

    /// <summary>
    /// Implicit conversion to string
    /// </summary>
    public static implicit operator string?(PhoneNumber phoneNumber) => phoneNumber?.Value;

    /// <summary>
    /// String representation
    /// </summary>
    public override string? ToString() => Value;
}