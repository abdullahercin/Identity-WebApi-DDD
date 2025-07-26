namespace Assist.Identity.Application.DTOs.Requests;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Reset Password Request DTO
/// Password reset confirmation için
/// </summary>
public class ResetPasswordRequest
{
    /// <summary>
    /// Reset token (email'den gelen)
    /// </summary>
    [Required(ErrorMessage = "Reset token is required")]
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// New password
    /// </summary>
    [Required(ErrorMessage = "New password is required")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 128 characters")]
    public string NewPassword { get; set; } = string.Empty;

    /// <summary>
    /// Password confirmation
    /// </summary>
    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare(nameof(NewPassword), ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;
}