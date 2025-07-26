namespace Assist.Identity.Application.Models;

/// <summary>
/// Paged Result Model
/// Pagination için kullanılan generic model
/// </summary>
/// <typeparam name="T">Sayfalanacak item türü</typeparam>
public class PagedResult<T>
{
    public IEnumerable<T> Items { get; set; } = new List<T>();
    public int TotalCount { get; set; }
    public int PageNumber { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }

    public bool HasPreviousPage => PageNumber > 1;
    public bool HasNextPage => PageNumber < TotalPages;

    /// <summary>
    /// Empty result factory
    /// </summary>
    public static PagedResult<T> Empty(int pageNumber, int pageSize)
    {
        return new PagedResult<T>
        {
            Items = new List<T>(),
            TotalCount = 0,
            PageNumber = pageNumber,
            PageSize = pageSize,
            TotalPages = 0
        };
    }
}