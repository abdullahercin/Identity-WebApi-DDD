namespace Assist.Identity.Application.DTOs.Responses;

/// <summary>
/// Generic API Response DTO
/// Standardized API response format
/// </summary>
/// <typeparam name="T">Response data type</typeparam>
public class ApiResponse<T>
{
    /// <summary>
    /// Success indicator
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Response data
    /// </summary>
    public T? Data { get; set; }

    /// <summary>
    /// Error message (if any)
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Error code (if any)
    /// </summary>
    public string? ErrorCode { get; set; }

    /// <summary>
    /// Timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Request ID (for tracing)
    /// </summary>
    public string? RequestId { get; set; }

    /// <summary>
    /// Success response factory
    /// </summary>
    public static ApiResponse<T> SuccessResult(T data, string? message = null)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Data = data,
            Message = message
        };
    }

    /// <summary>
    /// Error response factory
    /// </summary>
    public static ApiResponse<T> ErrorResult(string message, string? errorCode = null)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            ErrorCode = errorCode
        };
    }
}