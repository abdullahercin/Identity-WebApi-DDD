using Assist.Identity.Domain.ValueObjects;

/// <summary>
/// Password Value Object
/// Password strength validation ve hashing'i domain seviyesinde sağlar
/// Plain text password hiçbir zaman store edilmez, sadece hash'i tutulur
/// </summary>
public sealed class Password : ValueObject
{
    /// <summary>
    /// Private constructor - Factory method ile oluşturulmalı
    /// </summary>
    private Password(string? hashedValue)
    {
        HashedValue = hashedValue ?? throw new ArgumentNullException(nameof(hashedValue));
    }

    /// <summary>
    /// Hash'lenmiş password değeri
    /// Plain text password hiçbir zaman expose edilmez
    /// </summary>
    public string? HashedValue { get; }

    /// <summary>
    /// Yeni password oluşturma factory method
    /// Plain text password'ü alır, validate eder, hash'ler ve store eder
    /// </summary>
    /// <param name="plainTextPassword">Plain text password</param>
    /// <returns>Hash'lenmiş Password object'i</returns>
    public static Password? Create(string plainTextPassword)
    {
        ValidatePasswordStrength(plainTextPassword);

        // Simple hashing for now - Production'da BCrypt kullanılacak
        var hashedPassword = HashPassword(plainTextPassword);
        return new Password(hashedPassword);
    }

    /// <summary>
    /// Existing hash'ten password restore etme
    /// Database'den hash'lenmiş password okunurken kullanılır
    /// </summary>
    /// <param name="hashedPassword">Hash'lenmiş password</param>
    /// <returns>Password object'i</returns>
    public static Password FromHash(string? hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword))
            throw new ArgumentException("Hashed password cannot be empty.", nameof(hashedPassword));

        return new Password(hashedPassword);
    }

    /// <summary>
    /// Password verification
    /// Plain text password ile hash'i karşılaştırır
    /// </summary>
    /// <param name="plainTextPassword">Kontrol edilecek plain text password</param>
    /// <returns>Password doğruysa true, yanlışsa false</returns>
    public bool Verify(string plainTextPassword)
    {
        if (string.IsNullOrWhiteSpace(plainTextPassword))
            return false;

        var hashToCheck = HashPassword(plainTextPassword);
        return hashToCheck == HashedValue;
    }

    /// <summary>
    /// Password strength validation
    /// Business rules burada define edilir
    /// </summary>
    private static void ValidatePasswordStrength(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty or whitespace.", nameof(password));

        if (password.Length < 8)
            throw new ArgumentException("Password must be at least 8 characters long.", nameof(password));

        if (password.Length > 128)
            throw new ArgumentException("Password cannot be longer than 128 characters.", nameof(password));

        // En az bir büyük harf
        if (!password.Any(char.IsUpper))
            throw new ArgumentException("Password must contain at least one uppercase letter.", nameof(password));

        // En az bir küçük harf
        if (!password.Any(char.IsLower))
            throw new ArgumentException("Password must contain at least one lowercase letter.", nameof(password));

        // En az bir rakam
        if (!password.Any(char.IsDigit))
            throw new ArgumentException("Password must contain at least one number.", nameof(password));

        // En az bir özel karakter
        var specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (!password.Any(c => specialChars.Contains(c)))
            throw new ArgumentException("Password must contain at least one special character.", nameof(password));

        // Yaygın password'ler kontrolü
        var commonPasswords = new[] { "password", "123456", "qwerty", "admin", "letmein", "welcome" };
        if (commonPasswords.Any(cp => password.ToLowerInvariant().Contains(cp)))
            throw new ArgumentException("Password contains commonly used patterns.", nameof(password));
    }

    /// <summary>
    /// Password strength score hesaplama
    /// UI'da strength indicator göstermek için kullanılabilir
    /// </summary>
    /// <param name="password">Score hesaplanacak password</param>
    /// <returns>0-100 arası strength score</returns>
    public static int CalculateStrengthScore(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            return 0;

        int score = 0;

        // Uzunluk puanı
        if (password.Length >= 8) score += 20;
        if (password.Length >= 12) score += 15;
        if (password.Length >= 16) score += 10;

        // Karakter çeşitliliği puanı
        if (password.Any(char.IsUpper)) score += 15;
        if (password.Any(char.IsLower)) score += 15;
        if (password.Any(char.IsDigit)) score += 15;
        if (password.Any(c => "!@#$%^&*()_+-=[]{}|;:,.<>?".Contains(c))) score += 15;

        // Karmaşıklık puanı
        var uniqueChars = password.Distinct().Count();
        if (uniqueChars >= password.Length * 0.7) score += 5;

        return Math.Min(score, 100);
    }

    /// <summary>
    /// Simple password hashing
    /// Production'da BCrypt, Argon2 veya PBKDF2 kullanılmalı
    /// </summary>
    private static string? HashPassword(string password)
    {
        // Bu basit implementation sadece development için
        // Production'da gerçek hashing algoritması kullanılacak
        var salt = "Assist.Identity.Salt"; // Production'da random salt kullanılmalı
        var combined = password + salt;

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(combined));
        return Convert.ToBase64String(hashBytes);
    }

    /// <summary>
    /// Equality components
    /// </summary>
    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return HashedValue;
    }

    /// <summary>
    /// String representation - Security için hash'i göstermez
    /// </summary>
    public override string ToString() => "[PROTECTED]";
}