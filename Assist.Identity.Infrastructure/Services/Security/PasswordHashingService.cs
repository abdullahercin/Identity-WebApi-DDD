using Assist.Identity.Application.Contracts;

namespace Assist.Identity.Infrastructure.Services.Security;

/// <summary>
/// Password Hashing Service Implementation
/// 
/// This service implements secure password hashing using BCrypt algorithm.
/// BCrypt is industry standard for password hashing because:
/// 1. It's designed to be slow (prevents brute force attacks)
/// 2. It includes salt automatically (prevents rainbow table attacks)
/// 3. It's adaptive (can increase difficulty over time)
/// 
/// Key Learning Points:
/// 1. How to implement security-focused infrastructure services
/// 2. Industry best practices for password handling
/// 3. Why we never store plain text passwords
/// 4. How to handle hash strength evolution over time
/// 5. Simple service implementation pattern (no async, no external dependencies)
/// 
/// Security Note: This is a critical security component!
/// Any bugs here could compromise entire system security.
/// </summary>
public class PasswordHashingService : IPasswordHashingService
{
    // BCrypt work factor (cost parameter)
    // Higher values = more secure but slower hashing
    // 12 is good balance for 2024 - takes ~300ms on modern hardware
    private const int DefaultWorkFactor = 12;

    /// <summary>
    /// Hash a plain text password into secure hash
    /// 
    /// Uses BCrypt algorithm which:
    /// - Automatically generates unique salt for each password
    /// - Uses configurable work factor for adjustable security
    /// - Produces hash that includes salt + work factor + hash
    /// 
    /// Example: "mypassword123" → "$2a$12$N9qo8uLOickgx2ZMRZoMye...."
    /// </summary>
    /// <param name="password">Plain text password from user</param>
    /// <returns>BCrypt hash string (safe to store in database)</returns>
    /// <exception cref="ArgumentException">If password is null/empty</exception>
    public string HashPassword(string password)
    {
        // Input validation - critical for security service
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        }

        // Additional security validation
        if (password.Length > 72) // BCrypt limitation
        {
            throw new ArgumentException("Password cannot exceed 72 characters for BCrypt.", nameof(password));
        }

        try
        {
            // BCrypt.Net.HashPassword automatically:
            // 1. Generates random salt
            // 2. Combines password + salt
            // 3. Applies BCrypt algorithm with specified work factor
            // 4. Returns complete hash string containing salt + work factor + hash
            return BCrypt.Net.BCrypt.HashPassword(password, DefaultWorkFactor);
        }
        catch (Exception ex)
        {
            // Log the error but don't expose internal details
            // In production, you'd use proper logging framework
            System.Diagnostics.Debug.WriteLine($"Password hashing failed: {ex.Message}");
            throw new InvalidOperationException("Password hashing failed.", ex);
        }
    }

    /// <summary>
    /// Verify plain text password against stored hash
    /// 
    /// This is used during login process to check if user entered correct password.
    /// BCrypt.Verify automatically:
    /// - Extracts salt and work factor from stored hash
    /// - Hashes the provided password using same salt + work factor
    /// - Compares result with stored hash using timing-safe comparison
    /// 
    /// Security Note: Uses constant-time comparison to prevent timing attacks
    /// </summary>
    /// <param name="password">Plain text password from user login</param>
    /// <param name="hashedPassword">Stored hash from database</param>
    /// <returns>True if password matches, false otherwise</returns>
    /// <exception cref="ArgumentException">If either parameter is null/empty</exception>
    public bool VerifyPassword(string password, string hashedPassword)
    {
        // Input validation
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        }

        if (string.IsNullOrWhiteSpace(hashedPassword))
        {
            throw new ArgumentException("Hashed password cannot be null or empty.", nameof(hashedPassword));
        }

        try
        {
            // BCrypt.Verify handles all the complexity:
            // 1. Parses stored hash to extract salt + work factor
            // 2. Hashes input password with same parameters
            // 3. Performs constant-time comparison
            // 4. Returns true/false
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
        catch (Exception ex)
        {
            // Hash format might be invalid or corrupted
            // Log error but don't expose details to potential attacker
            System.Diagnostics.Debug.WriteLine($"Password verification failed: {ex.Message}");

            // Return false for invalid hashes rather than throwing
            // This prevents information leakage about hash validity
            return false;
        }
    }

    /// <summary>
    /// Check if existing hash needs to be rehashed with stronger parameters
    /// 
    /// This is important for security evolution:
    /// - If we increase DefaultWorkFactor, old hashes become "weak"
    /// - This method identifies hashes that need upgrading
    /// - Typically called after successful login to upgrade hash if needed
    /// 
    /// Example usage:
    /// 1. User logs in successfully
    /// 2. Check if hash needs rehashing
    /// 3. If yes, hash password again with current parameters
    /// 4. Store new hash, replace old one
    /// </summary>
    /// <param name="hashedPassword">Existing hash from database</param>
    /// <returns>True if hash should be updated, false if current hash is sufficient</returns>
    /// <exception cref="ArgumentException">If hashedPassword is null/empty</exception>
    public bool NeedsRehashing(string hashedPassword)
    {
        // Input validation
        if (string.IsNullOrWhiteSpace(hashedPassword))
        {
            throw new ArgumentException("Hashed password cannot be null or empty.", nameof(hashedPassword));
        }

        try
        {
            // Parse BCrypt hash to extract work factor
            // BCrypt hash format: $2a$12$saltandhash...
            // Where 12 is the work factor
            if (!TryParseWorkFactor(hashedPassword, out int currentWorkFactor))
            {
                // If we can't parse work factor, assume hash needs updating
                return true;
            }

            // Compare current work factor with our desired work factor
            // If stored hash uses lower work factor, it needs rehashing
            return currentWorkFactor < DefaultWorkFactor;
        }
        catch (Exception ex)
        {
            // If parsing fails, assume hash needs updating for safety
            System.Diagnostics.Debug.WriteLine($"Hash parsing failed: {ex.Message}");
            return true;
        }
    }

    /// <summary>
    /// Helper method to extract work factor from BCrypt hash
    /// 
    /// BCrypt hash format: $2a$WF$salthash...
    /// Where WF is work factor (like "12")
    /// 
    /// This is internal implementation detail for NeedsRehashing method.
    /// </summary>
    /// <param name="hashedPassword">BCrypt hash string</param>
    /// <param name="workFactor">Extracted work factor</param>
    /// <returns>True if parsing successful, false otherwise</returns>
    private static bool TryParseWorkFactor(string hashedPassword, out int workFactor)
    {
        workFactor = 0;

        try
        {
            // BCrypt hash format: $2a$12$...
            // Split by '$' and get the work factor part
            var parts = hashedPassword.Split('$');

            // Valid BCrypt hash should have at least 4 parts
            // [empty], "2a", "12", "saltandhash"
            if (parts.Length < 4)
            {
                return false;
            }

            // Work factor is in parts[2]
            return int.TryParse(parts[2], out workFactor);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Get current default work factor
    /// 
    /// Utility method for testing and configuration purposes.
    /// Allows other parts of system to know what work factor we're using.
    /// </summary>
    /// <returns>Current default work factor</returns>
    public int GetCurrentWorkFactor()
    {
        return DefaultWorkFactor;
    }
}