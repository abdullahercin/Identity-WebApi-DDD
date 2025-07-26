namespace Assist.Identity.Application.Contracts;

/// <summary>
/// Password Hashing Service Contract
/// Password hashing ve verification operations
/// BCrypt, Argon2 gibi farklı algorithms destekler
/// </summary>
public interface IPasswordHashingService
{
    /// <summary>
    /// Password hashing
    /// Plain text password'ü hash'ler
    /// </summary>
    /// <param name="password">Plain text password</param>
    /// <returns>Hashed password</returns>
    string HashPassword(string password);

    /// <summary>
    /// Password verification
    /// Plain text password ile hash'i karşılaştırır
    /// </summary>
    /// <param name="password">Plain text password</param>
    /// <param name="hashedPassword">Hashed password</param>
    /// <returns>Password doğruysa true</returns>
    bool VerifyPassword(string password, string hashedPassword);

    /// <summary>
    /// Hash strength kontrolü
    /// Eski hash'lerin güçlendirilmesi gerekip gerekmediğini kontrol eder
    /// </summary>
    /// <param name="hashedPassword">Kontrol edilecek hash</param>
    /// <returns>Hash güçlendirmesi gerekiyorsa true</returns>
    bool NeedsRehashing(string hashedPassword);
}