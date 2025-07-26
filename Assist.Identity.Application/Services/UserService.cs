namespace Assist.Identity.Application.Services;

using AutoMapper;
using Assist.Identity.Application.Abstractions;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;
using Assist.Identity.Application.Models;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Domain.ValueObjects;
using Assist.Identity.Domain.Exceptions;

/// <summary>
/// User Service Implementation
/// User management use case'lerinin concrete implementation'ı
/// Domain logic'i orchestrate eder, infrastructure services'leri koordine eder
/// </summary>
public class UserService : IUserService
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly ICacheService _cacheService;
    private readonly IEmailService _emailService;
    private readonly IPasswordHashingService _passwordHashingService;
    private readonly IMapper _mapper;

    public UserService(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        ICacheService cacheService,
        IEmailService emailService,
        IPasswordHashingService passwordHashingService,
        IMapper mapper)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _cacheService = cacheService;
        _emailService = emailService;
        _passwordHashingService = passwordHashingService;
        _mapper = mapper;
    }

    #region User CRUD Operations

    public async Task<ApiResponse<UserResponse>> CreateUserAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // Business rule: Email unique olmalı
            var emailVO = Email.Create(request.Email);
            if (await _userRepository.EmailExistsAsync(emailVO, cancellationToken: cancellationToken))
            {
                return ApiResponse<UserResponse>.ErrorResult("A user with this email already exists", "USER_ALREADY_EXISTS");
            }

            // Domain entity oluşturma - Business logic domain'de
            var user = User.Create(
                request.Email,
                request.Password,
                request.FirstName,
                request.LastName,
                request.PhoneNumber);

            // Default role assignment
            var roleNames = request.RoleNames?.Any() == true ? request.RoleNames : new List<string> { "User" };

            foreach (var roleName in roleNames)
            {
                var role = await _roleRepository.GetByNameAsync(roleName, cancellationToken);
                if (role == null)
                {
                    return ApiResponse<UserResponse>.ErrorResult($"Role '{roleName}' does not exist", "ROLE_NOT_FOUND");
                }

                user.AssignRole(role);
            }

            // Persistence
            var createdUser = await _userRepository.AddAsync(user, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveByPatternAsync("users:*", cancellationToken);

            // Email sending (fire and forget)
            _ = Task.Run(async () =>
            {
                try
                {
                    await _emailService.SendWelcomeEmailAsync(createdUser, cancellationToken: default);
                }
                catch
                {
                    // Log error but don't fail the operation
                }
            }, cancellationToken);

            // Response mapping
            var response = _mapper.Map<UserResponse>(createdUser);
            response.Roles = roleNames;

            return ApiResponse<UserResponse>.SuccessResult(response, "User created successfully");
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<UserResponse>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (DomainException ex)
        {
            return ApiResponse<UserResponse>.ErrorResult(ex.Message, ex.ErrorCode);
        }
        catch (Exception ex)
        {
            // Log exception
            return ApiResponse<UserResponse>.ErrorResult("An error occurred while creating user", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<UserResponse>> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            // Cache-first approach
            var cacheKey = $"user:{userId}";
            var cachedUser = await _cacheService.GetAsync<UserResponse>(cacheKey, cancellationToken);

            if (cachedUser != null)
            {
                return ApiResponse<UserResponse>.SuccessResult(cachedUser);
            }

            // Database'den getir
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<UserResponse>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Response mapping
            var response = _mapper.Map<UserResponse>(user);
            response.Roles = user.GetRoleNames().ToList();
            response.Permissions = user.GetPermissions().ToList();

            // Cache'e kaydet
            await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(30), cancellationToken);

            return ApiResponse<UserResponse>.SuccessResult(response);
        }
        catch (Exception ex)
        {
            return ApiResponse<UserResponse>.ErrorResult("An error occurred while retrieving user", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<UserResponse>> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        try
        {
            var emailVO = Email.Create(email);
            var user = await _userRepository.GetByEmailAsync(emailVO, cancellationToken);

            if (user == null)
            {
                return ApiResponse<UserResponse>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            var response = _mapper.Map<UserResponse>(user);
            response.Roles = user.GetRoleNames().ToList();
            response.Permissions = user.GetPermissions().ToList();

            return ApiResponse<UserResponse>.SuccessResult(response);
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<UserResponse>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<UserResponse>.ErrorResult("An error occurred while retrieving user", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<UserResponse>> UpdateUserAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<UserResponse>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Email değişikliği kontrolü
            if (!string.IsNullOrEmpty(request.Email) && request.Email != user.Email.Value)
            {
                var emailVO = Email.Create(request.Email);
                if (await _userRepository.EmailExistsAsync(emailVO, userId, cancellationToken))
                {
                    return ApiResponse<UserResponse>.ErrorResult("Email is already in use", "EMAIL_ALREADY_EXISTS");
                }
                // Email change logic - domain method gerekecek
            }

            // Profile update - Domain method'ları eklenebilir
            // Şimdilik reflection ile update (production'da domain method'ları kullanılmalı)

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveAsync($"user:{userId}", cancellationToken);
            await _cacheService.RemoveByPatternAsync("users:*", cancellationToken);

            var response = _mapper.Map<UserResponse>(user);
            return ApiResponse<UserResponse>.SuccessResult(response, "User updated successfully");
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<UserResponse>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<UserResponse>.ErrorResult("An error occurred while updating user", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> DeactivateUserAsync(Guid userId, string? reason = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Domain method ile deactivation
            user.Deactivate(reason: reason);

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Cache cleanup
            await _cacheService.ClearUserCacheAsync(userId, cancellationToken);
            await _cacheService.RemoveByPatternAsync("users:*", cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "User deactivated successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while deactivating user", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> ReactivateUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Domain method ile reactivation
            user.Reactivate();

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveAsync($"user:{userId}", cancellationToken);
            await _cacheService.RemoveByPatternAsync("users:*", cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "User reactivated successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while reactivating user", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Password Management

    public async Task<ApiResponse<bool>> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Application layer'da current password validation (artık tek parametre)
            if (!user.Password.Verify(request.CurrentPassword))
            {
                return ApiResponse<bool>.ErrorResult("Current password is incorrect", "INVALID_PASSWORD");
            }

            // Business rule: Yeni password eskisiyle aynı olmamalı (artık tek parametre)
            if (user.Password.Verify(request.NewPassword))
            {
                return ApiResponse<bool>.ErrorResult("New password cannot be the same as current password", "SAME_PASSWORD");
            }

            // Domain method ile password change - Clean approach
            user.ChangePassword(request.NewPassword, "self-service");

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Security: User cache'ini temizle
            await _cacheService.ClearUserCacheAsync(userId, cancellationToken);

            // Security notification email (fire and forget)
            _ = Task.Run(async () =>
            {
                try
                {
                    await _emailService.SendPasswordChangedNotificationAsync(user, cancellationToken: default);
                }
                catch
                {
                    // Log error but don't fail the operation
                }
            }, cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Password changed successfully");
        }
        catch (InvalidOperationException ex)
        {
            return ApiResponse<bool>.ErrorResult(ex.Message, "INVALID_OPERATION");
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<bool>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while changing password", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> RequestPasswordResetAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var emailVO = Email.Create(request.Email);
            var user = await _userRepository.GetByEmailAsync(emailVO, cancellationToken);

            // Security: Always return success to prevent email enumeration
            if (user == null)
            {
                return ApiResponse<bool>.SuccessResult(true, "If the email exists, a reset link has been sent");
            }

            // Generate reset token (implement in infrastructure)
            var resetToken = Guid.NewGuid().ToString();

            // Store reset token with expiration (string olarak store et)
            await _cacheService.SetAsync($"password_reset:{resetToken}", user.Id.ToString(), TimeSpan.FromHours(1), cancellationToken);

            // Send reset email
            await _emailService.SendPasswordResetEmailAsync(user, resetToken, cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "If the email exists, a reset link has been sent");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while processing password reset request", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // Token validation - string olarak retrieve et ve parse et
            var userIdString = await _cacheService.GetAsync<string>($"password_reset:{request.Token}", cancellationToken);

            if (string.IsNullOrEmpty(userIdString) || !Guid.TryParse(userIdString, out var userId))
            {
                return ApiResponse<bool>.ErrorResult("Invalid or expired reset token", "INVALID_TOKEN");
            }

            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Password reset - Domain method ile
            user.ChangePassword(request.NewPassword, "password_reset");

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Token'ı invalidate et
            await _cacheService.RemoveAsync($"password_reset:{request.Token}", cancellationToken);

            // Security: Clear user sessions
            await _cacheService.ClearUserCacheAsync(userId, cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Password reset successfully");
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<bool>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while resetting password", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Email Management

    public async Task<ApiResponse<bool>> ConfirmEmailAsync(Guid userId, string token, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Token validation logic (implement in infrastructure)
            // Şimdilik basit approach

            // Domain method ile email confirmation
            user.ConfirmEmail();

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveAsync($"user:{userId}", cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Email confirmed successfully");
        }
        catch (InvalidOperationException ex)
        {
            return ApiResponse<bool>.ErrorResult(ex.Message, "INVALID_OPERATION");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while confirming email", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> ResendEmailConfirmationAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            if (user.EmailConfirmed)
            {
                return ApiResponse<bool>.ErrorResult("Email is already confirmed", "EMAIL_ALREADY_CONFIRMED");
            }

            // Generate confirmation token
            var confirmationToken = Guid.NewGuid().ToString();

            // Send confirmation email
            await _emailService.SendEmailConfirmationAsync(user, confirmationToken, cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Confirmation email sent");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while sending confirmation email", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region User Search & Listing

    public async Task<PaginatedResponse<UserResponse>> GetUsersAsync(int pageNumber = 1, int pageSize = 10, string? searchTerm = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var pagedUsers = await _userRepository.GetPagedAsync(pageNumber, pageSize, searchTerm, cancellationToken);

            var userResponses = _mapper.Map<List<UserResponse>>(pagedUsers.Items);

            // Her user için roles ve permissions bilgilerini ekle
            foreach (var userResponse in userResponses)
            {
                var user = pagedUsers.Items.First(u => u.Id == userResponse.Id);
                userResponse.Roles = user.GetRoleNames().ToList();
                userResponse.Permissions = user.GetPermissions().ToList();
            }

            var pagedResult = new PagedResult<UserResponse>
            {
                Items = userResponses,
                TotalCount = pagedUsers.TotalCount,
                PageNumber = pagedUsers.PageNumber,
                PageSize = pagedUsers.PageSize,
                TotalPages = pagedUsers.TotalPages
            };

            return PaginatedResponse<UserResponse>.SuccessResult(pagedResult);
        }
        catch (Exception ex)
        {
            return PaginatedResponse<UserResponse>.ErrorResult("An error occurred while retrieving users", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<List<UserResponse>>> GetActiveUsersAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var users = await _userRepository.GetActiveUsersAsync(cancellationToken);
            var userResponses = _mapper.Map<List<UserResponse>>(users);

            return ApiResponse<List<UserResponse>>.SuccessResult(userResponses);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<UserResponse>>.ErrorResult("An error occurred while retrieving active users", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<List<UserResponse>>> GetUsersByRoleAsync(string roleName, CancellationToken cancellationToken = default)
    {
        try
        {
            var users = await _userRepository.GetUsersByRoleAsync(roleName, cancellationToken);
            var userResponses = _mapper.Map<List<UserResponse>>(users);

            return ApiResponse<List<UserResponse>>.SuccessResult(userResponses);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<UserResponse>>.ErrorResult("An error occurred while retrieving users by role", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region User Statistics

    public async Task<ApiResponse<int>> GetTotalUserCountAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var count = await _userRepository.GetTotalUserCountAsync(cancellationToken);
            return ApiResponse<int>.SuccessResult(count);
        }
        catch (Exception ex)
        {
            return ApiResponse<int>.ErrorResult("An error occurred while retrieving user count", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<UserStatistics>> GetUserStatisticsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Cache'den dene
            var cacheKey = "user_statistics";
            var cachedStats = await _cacheService.GetAsync<UserStatistics>(cacheKey, cancellationToken);

            if (cachedStats != null)
            {
                return ApiResponse<UserStatistics>.SuccessResult(cachedStats);
            }

            // Statistics hesaplama (implement repository methods)
            var totalUsers = await _userRepository.GetTotalUserCountAsync(cancellationToken);

            var statistics = new UserStatistics
            {
                TotalUsers = totalUsers,
                // Diğer statistics repository method'larından gelecek
                ActiveUsers = totalUsers, // Placeholder
                InactiveUsers = 0,
                UnconfirmedEmails = 0,
                LockedAccounts = 0,
                NewUsersThisMonth = 0,
                NewUsersThisWeek = 0
            };

            // Cache'e kaydet (5 dakika)
            await _cacheService.SetAsync(cacheKey, statistics, TimeSpan.FromMinutes(5), cancellationToken);

            return ApiResponse<UserStatistics>.SuccessResult(statistics);
        }
        catch (Exception ex)
        {
            return ApiResponse<UserStatistics>.ErrorResult("An error occurred while retrieving user statistics", "INTERNAL_ERROR");
        }
    }

    #endregion
}