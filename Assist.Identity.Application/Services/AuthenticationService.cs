namespace Assist.Identity.Application.Services;

using AutoMapper;
using Assist.Identity.Application.Abstractions;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;
using Assist.Identity.Application.DTOs.Common;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Domain.ValueObjects;
using Assist.Identity.Domain.Exceptions;

/// <summary>
/// Authentication Service Implementation
/// Authentication use case'lerinin concrete implementation'ı
/// </summary>
public class AuthenticationService : IAuthenticationService
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly ITokenService _tokenService;
    private readonly ICacheService _cacheService;
    private readonly IPasswordHashingService _passwordHashingService;
    private readonly IMapper _mapper;

    public AuthenticationService(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        ITokenService tokenService,
        ICacheService cacheService,
        IPasswordHashingService passwordHashingService,
        IMapper mapper)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _tokenService = tokenService;
        _cacheService = cacheService;
        _passwordHashingService = passwordHashingService;
        _mapper = mapper;
    }

    #region Authentication Operations

    public async Task<ApiResponse<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var emailVO = Email.Create(request.Email);
            var user = await _userRepository.GetByEmailAsync(emailVO, cancellationToken);

            if (user == null)
            {
                return ApiResponse<AuthResponse>.ErrorResult("Invalid credentials", "INVALID_CREDENTIALS");
            }

            // Domain method ile login - Business rules burada check edilir
            user.Login(request.Password, request.IpAddress, request.UserAgent);

            // User roles ve permissions
            var roles = user.GetRoleNames().ToList();
            var permissions = user.GetPermissions().ToList();

            // Token generation
            var accessToken = await _tokenService.GenerateAccessTokenAsync(user, roles, permissions, cancellationToken);
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync(cancellationToken);

            // Refresh token persist
            var refreshTokenEntity = RefreshToken.Create(
                user.Id,
                refreshToken,
                DateTime.UtcNow.AddDays(request.RememberMe ? 30 : 7));

            user.RefreshTokens.Add(refreshTokenEntity);
            await _userRepository.UpdateAsync(user, cancellationToken);

            // Session info
            var sessionInfo = new SessionInfo
            {
                StartedAt = DateTime.UtcNow,
                IpAddress = request.IpAddress,
                UserAgent = request.UserAgent,
                ExpiresAt = DateTime.UtcNow.AddDays(request.RememberMe ? 30 : 7)
            };

            // User session cache
            await _cacheService.SetUserCacheAsync(user.Id, "session", sessionInfo, sessionInfo.ExpiresAt - DateTime.UtcNow, cancellationToken);

            // Response preparation
            var response = new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddMinutes(60), // JWT expiration
                User = _mapper.Map<UserResponse>(user),
                Roles = roles,
                Permissions = permissions,
                Session = sessionInfo
            };

            response.User.Roles = roles;
            response.User.Permissions = permissions;

            return ApiResponse<AuthResponse>.SuccessResult(response, "Login successful");
        }
        catch (InvalidOperationException ex)
        {
            return ApiResponse<AuthResponse>.ErrorResult(ex.Message, "AUTHENTICATION_FAILED");
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<AuthResponse>.ErrorResult("Invalid input", "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<AuthResponse>.ErrorResult("An error occurred during login", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<AuthResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // User creation (UserService'deki logic'i kullanabiliriz)
            var emailVO = Email.Create(request.Email);
            if (await _userRepository.EmailExistsAsync(emailVO, cancellationToken: cancellationToken))
            {
                return ApiResponse<AuthResponse>.ErrorResult("A user with this email already exists", "USER_ALREADY_EXISTS");
            }

            // Domain entity oluşturma
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
                if (role != null)
                {
                    user.AssignRole(role);
                }
            }

            // Persistence
            var createdUser = await _userRepository.AddAsync(user, cancellationToken);

            // Auto-login after registration
            var loginRequest = new LoginRequest
            {
                Email = request.Email,
                Password = request.Password,
                RememberMe = false
            };

            return await LoginAsync(loginRequest, cancellationToken);
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<AuthResponse>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<AuthResponse>.ErrorResult("An error occurred during registration", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // Token validation logic implement edilmeli
            // Şimdilik placeholder

            return ApiResponse<AuthResponse>.ErrorResult("Refresh token functionality not implemented", "NOT_IMPLEMENTED");
        }
        catch (Exception ex)
        {
            return ApiResponse<AuthResponse>.ErrorResult("An error occurred during token refresh", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> LogoutAsync(Guid userId, string? refreshToken = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Specific refresh token revoke
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var tokenEntity = user.RefreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);
                tokenEntity?.Revoke();
            }
            else
            {
                // Revoke all refresh tokens
                foreach (var token in user.RefreshTokens.Where(rt => rt.IsActive))
                {
                    token.Revoke();
                }
            }

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Clear user cache
            await _cacheService.ClearUserCacheAsync(userId, cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Logout successful");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred during logout", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> LogoutFromAllDevicesAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            // Revoke all refresh tokens
            foreach (var token in user.RefreshTokens.Where(rt => rt.IsActive))
            {
                token.Revoke();
            }

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Clear all user cache
            await _cacheService.ClearUserCacheAsync(userId, cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Logged out from all devices");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred during logout", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Token Management

    public async Task<ApiResponse<bool>> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            var isValid = await _tokenService.ValidateTokenAsync(token, cancellationToken);
            return ApiResponse<bool>.SuccessResult(isValid);
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred during token validation", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> RevokeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            await _tokenService.RevokeTokenAsync(token, cancellationToken);
            return ApiResponse<bool>.SuccessResult(true, "Token revoked");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred during token revocation", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<UserResponse>> GetCurrentUserAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            var userInfo = await _tokenService.GetUserInfoFromTokenAsync(token, cancellationToken);
            if (userInfo == null)
            {
                return ApiResponse<UserResponse>.ErrorResult("Invalid token", "INVALID_TOKEN");
            }

            var user = await _userRepository.GetByIdAsync(userInfo.UserId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<UserResponse>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            var response = _mapper.Map<UserResponse>(user);
            response.Roles = user.GetRoleNames().ToList();
            response.Permissions = user.GetPermissions().ToList();

            return ApiResponse<UserResponse>.SuccessResult(response);
        }
        catch (Exception ex)
        {
            return ApiResponse<UserResponse>.ErrorResult("An error occurred while retrieving current user", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Session Management

    public async Task<ApiResponse<List<UserSession>>> GetActiveSessionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            // Session management logic implement edilmeli
            // Şimdilik placeholder
            var sessions = new List<UserSession>();

            return ApiResponse<List<UserSession>>.SuccessResult(sessions);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<UserSession>>.ErrorResult("An error occurred while retrieving sessions", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> TerminateSessionAsync(Guid userId, string sessionId, CancellationToken cancellationToken = default)
    {
        try
        {
            // Session termination logic implement edilmeli
            // Şimdilik placeholder

            return ApiResponse<bool>.SuccessResult(true, "Session terminated");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while terminating session", "INTERNAL_ERROR");
        }
    }

    #endregion
}
