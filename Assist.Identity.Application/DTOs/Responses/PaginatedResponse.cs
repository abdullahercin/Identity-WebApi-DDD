using Assist.Identity.Application.DTOs.Responses;

using Assist.Identity.Application.Models;

/// <summary>
/// Paginated Response DTO
/// Sayfalanmış veri döndürme için
/// PagedResult model'ini kullanarak consistency sağlar
/// </summary>
/// <typeparam name="T">Item type</typeparam>
public class PaginatedResponse<T> : ApiResponse<List<T>>
{
    /// <summary>
    /// Pagination information - PagedResult'tan direk property'ler
    /// </summary>
    public int TotalCount { get; set; }
    public int PageNumber { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }
    public bool HasPreviousPage { get; set; }
    public bool HasNextPage { get; set; }

    /// <summary>
    /// Success paginated response factory
    /// PagedResult'ı direkt kullanarak duplication'ı önler
    /// </summary>
    public static PaginatedResponse<T> SuccessResult(PagedResult<T> pagedResult)
    {
        return new PaginatedResponse<T>
        {
            Success = true,
            Data = pagedResult.Items.ToList(),

            // PagedResult properties'larını direkt map et
            TotalCount = pagedResult.TotalCount,
            PageNumber = pagedResult.PageNumber,
            PageSize = pagedResult.PageSize,
            TotalPages = pagedResult.TotalPages,
            HasPreviousPage = pagedResult.HasPreviousPage,
            HasNextPage = pagedResult.HasNextPage
        };
    }

    /// <summary>
    /// Error paginated response factory
    /// </summary>
    public static PaginatedResponse<T> ErrorResult(string message, string? errorCode = null)
    {
        return new PaginatedResponse<T>
        {
            Success = false,
            Message = message,
            ErrorCode = errorCode,
            Data = new List<T>(),
            TotalCount = 0,
            PageNumber = 1,
            PageSize = 10,
            TotalPages = 0,
            HasPreviousPage = false,
            HasNextPage = false
        };
    }

    /// <summary>
    /// Empty paginated response factory
    /// </summary>
    public static PaginatedResponse<T> EmptyResult(int pageNumber = 1, int pageSize = 10)
    {
        return new PaginatedResponse<T>
        {
            Success = true,
            Data = new List<T>(),
            TotalCount = 0,
            PageNumber = pageNumber,
            PageSize = pageSize,
            TotalPages = 0,
            HasPreviousPage = false,
            HasNextPage = false,
            Message = "No data found"
        };
    }
}