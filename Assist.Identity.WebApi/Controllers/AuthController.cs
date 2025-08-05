using Assist.Identity.Application.Abstractions;
using Assist.Identity.Application.DTOs.Requests;
using Assist.Identity.Application.DTOs.Responses;
using Microsoft.AspNetCore.Mvc;

namespace Assist.Identity.WebApi.Controllers;

/// <summary>
/// Authentication Controller
/// 
/// Bu controller tüm authentication işlemlerini yönetir:
/// - User Registration (Kullanıcı kayıt)
/// - User Login (Kullanıcı giriş)
/// - Token Refresh (Token yenileme)
/// - Logout (Çıkış)
/// - Password Reset (Şifre sıfırlama)
/// 
/// Clean Architecture prensiplerine uygun olarak:
/// - Business logic Application layer'da (Services)
/// - Controller sadece HTTP concerns'ları handle eder
/// - Request/Response transformation
/// - HTTP status code mapping
/// - Input validation coordination
/// 
/// Security considerations:
/// - Rate limiting uygulanabilir
/// - Request logging yapılır
/// - Sensitive data log'lanmaz
/// - HTTPS only endpoints
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly ILogger<AuthController> _logger;

    /// <summary>
    /// AuthController constructor
    /// </summary>
    /// <param name="authenticationService">Authentication business logic service</param>
    /// <param name="logger">Controller logging service</param>
    public AuthController(
        IAuthenticationService authenticationService,
        ILogger<AuthController> logger)
    {
        _authenticationService = authenticationService;
        _logger = logger;
    }

    /// <summary>
    /// User Registration Endpoint
    /// 
    /// Yeni kullanıcı kayıt işlemini gerçekleştirir.
    /// 
    /// Business Flow:
    /// 1. Input validation (Model validation + custom business rules)
    /// 2. Email uniqueness check
    /// 3. Password hashing and security validation
    /// 4. User domain entity creation
    /// 5. Default role assignment
    /// 6. Database persistence
    /// 7. Welcome email sending (optional)
    /// 8. User cache initialization
    /// 9. JWT token generation and return
    /// 
    /// Security Notes:
    /// - Password complexity validation domain'de yapılır
    /// - Email format validation VO'da yapılır
    /// - Rate limiting consideration: Max 5 requests per minute per IP
    /// - Sensitive data (password) log'lanmaz
    /// 
    /// Error Scenarios:
    /// - Email already exists → 409 Conflict
    /// - Invalid input → 400 Bad Request
    /// - Server error → 500 Internal Server Error
    /// </summary>
    /// <param name="request">User registration data</param>
    /// <param name="cancellationToken">Cancellation token for async operations</param>
    /// <returns>Authentication response with JWT token and user info</returns>
    [HttpPost("register")]
    public async Task<ActionResult<ApiResponse<AuthResponse>>> RegisterAsync(
        [FromBody] RegisterRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Request context'i log'la (debugging için)
            _logger.LogInformation("User registration attempt for email: {Email}", request.Email);

            // IP Address ve User Agent bilgilerini request'e ekle
            request.IpAddress = GetClientIpAddress();
            request.UserAgent = GetUserAgent();

            // Authentication service ile registration işlemini başlat
            var result = await _authenticationService.RegisterAsync(request, cancellationToken);

            // Success case
            if (result.Success)
            {
                _logger.LogInformation("User registration successful for email: {Email}, UserId: {UserId}",
                    request.Email, result.Data?.User?.Id);

                return StatusCode(201, result); // 201 Created
            }

            // Business error cases (Domain rules, validations, etc.)
            _logger.LogWarning("User registration failed for email: {Email}, Error: {Error}",
                request.Email, result.Message);

            return result.ErrorCode switch
            {
                "USER_ALREADY_EXISTS" => Conflict(result), // 409 Conflict
                "VALIDATION_ERROR" => BadRequest(result),  // 400 Bad Request
                "WEAK_PASSWORD" => BadRequest(result),     // 400 Bad Request
                "INVALID_EMAIL" => BadRequest(result),     // 400 Bad Request
                _ => StatusCode(500, result)               // 500 Internal Server Error
            };
        }
        catch (ArgumentException ex)
        {
            // Input validation errors
            _logger.LogWarning("Invalid registration request for email: {Email}, Error: {Error}",
                request?.Email, ex.Message);

            var errorResponse = ApiResponse<AuthResponse>.ErrorResult(
                "Invalid registration data provided",
                "VALIDATION_ERROR");

            return BadRequest(errorResponse);
        }
        catch (Exception ex)
        {
            // Unexpected errors
            _logger.LogError(ex, "Unexpected error during registration for email: {Email}", request?.Email);

            var errorResponse = ApiResponse<AuthResponse>.ErrorResult(
                "An unexpected error occurred during registration",
                "INTERNAL_ERROR");

            return StatusCode(500, errorResponse);
        }
    }

    #region Private Helper Methods

    /// <summary>
    /// İstemci IP adresini güvenli şekilde alır
    /// 
    /// Proxy'ler ve load balancer'lar için X-Forwarded-For header'ını kontrol eder.
    /// Security note: Bu bilgi spoof edilebilir, kritik security decisions için kullanılmamalı.
    /// </summary>
    /// <returns>Client IP address or fallback value</returns>
    private string GetClientIpAddress()
    {
        try
        {
            // X-Forwarded-For header'ı kontrol et (proxy/load balancer için)
            var forwardedFor = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                // İlk IP'yi al (client IP)
                var firstIp = forwardedFor.Split(',')[0].Trim();
                if (System.Net.IPAddress.TryParse(firstIp, out _))
                {
                    return firstIp;
                }
            }

            // Direct connection IP
            var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            if (!string.IsNullOrEmpty(remoteIp))
            {
                return remoteIp;
            }

            return "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }

    /// <summary>
    /// User Agent bilgisini güvenli şekilde alır
    /// 
    /// Browser/client identification için kullanılır.
    /// Security logging ve analytics için yararlıdır.
    /// </summary>
    /// <returns>User Agent string or fallback value</returns>
    private string GetUserAgent()
    {
        try
        {
            var userAgent = HttpContext.Request.Headers.UserAgent.FirstOrDefault();
            return string.IsNullOrEmpty(userAgent) ? "Unknown" : userAgent;
        }
        catch
        {
            return "Unknown";
        }
    }

    #endregion
}