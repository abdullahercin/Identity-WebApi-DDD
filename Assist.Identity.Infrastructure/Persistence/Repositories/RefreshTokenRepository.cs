using Microsoft.EntityFrameworkCore;
using Assist.Identity.Domain.Entities;
using Assist.Identity.Application.Contracts;
using Assist.Identity.Infrastructure.Persistence.Contexts;

namespace Assist.Identity.Infrastructure.Persistence.Repositories;

/// <summary>
/// Refresh Token Repository Implementation
/// </summary>
public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly IdentityDbContext _context;

    public RefreshTokenRepository(IdentityDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    #region Basic CRUD Operations

    public async Task<RefreshToken?> GetByIdAsync(Guid tokenId, CancellationToken cancellationToken = default)
    {
        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Id == tokenId, cancellationToken);
    }

    public async Task<RefreshToken?> GetByTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token cannot be empty", nameof(token));

        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == token, cancellationToken);
    }

    public async Task<RefreshToken> AddAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default)
    {
        if (refreshToken == null)
            throw new ArgumentNullException(nameof(refreshToken));

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync(cancellationToken);
        return refreshToken;
    }

    public async Task<RefreshToken> UpdateAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default)
    {
        if (refreshToken == null)
            throw new ArgumentNullException(nameof(refreshToken));

        _context.RefreshTokens.Update(refreshToken);
        await _context.SaveChangesAsync(cancellationToken);
        return refreshToken;
    }

    public async Task DeleteAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default)
    {
        if (refreshToken == null)
            throw new ArgumentNullException(nameof(refreshToken));

        _context.RefreshTokens.Remove(refreshToken);
        await _context.SaveChangesAsync(cancellationToken);
    }

    #endregion

    #region User-specific Operations

    public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.RefreshTokens
            .Where(rt => rt.UserId == userId &&
                        rt.IsActive &&
                        rt.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(rt => rt.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task RevokeAllUserTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var userTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.IsActive)
            .ToListAsync(cancellationToken);

        foreach (var token in userTokens)
        {
            token.Revoke();
        }

        if (userTokens.Any())
        {
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task RevokeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token cannot be empty", nameof(token));

        var refreshToken = await GetByTokenAsync(token, cancellationToken);
        if (refreshToken != null && refreshToken.IsActive)
        {
            refreshToken.Revoke();
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    #endregion

    #region Maintenance Operations

    public async Task<int> CleanupExpiredTokensAsync(CancellationToken cancellationToken = default)
    {
        var expiredTokens = await _context.RefreshTokens
            .Where(rt => rt.ExpiresAt <= DateTime.UtcNow)
            .ToListAsync(cancellationToken);

        if (expiredTokens.Any())
        {
            _context.RefreshTokens.RemoveRange(expiredTokens);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return expiredTokens.Count;
    }

    public async Task<int> CleanupOldUserTokensAsync(Guid userId, int keepCount = 5, CancellationToken cancellationToken = default)
    {
        var userTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId)
            .OrderByDescending(rt => rt.CreatedAt)
            .Skip(keepCount)
            .ToListAsync(cancellationToken);

        if (userTokens.Any())
        {
            _context.RefreshTokens.RemoveRange(userTokens);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return userTokens.Count;
    }

    #endregion

    #region Validation & Security

    public async Task<bool> IsTokenValidAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        var refreshToken = await GetByTokenAsync(token, cancellationToken);

        return refreshToken != null &&
               refreshToken.IsActive &&
               refreshToken.ExpiresAt > DateTime.UtcNow;
    }

    public async Task IncrementUsageCountAsync(string token, CancellationToken cancellationToken = default)
    {
        // Usage tracking feature henüz RefreshToken entity'de yok
        // Şimdilik boş implementation, gelecekte eklenebilir
        await Task.CompletedTask;

        // TODO: RefreshToken entity'ye UsageCount property eklenirse implement et
        // var refreshToken = await GetByTokenAsync(token, cancellationToken);
        // if (refreshToken != null)
        // {
        //     refreshToken.IncrementUsage();
        //     await _context.SaveChangesAsync(cancellationToken);
        // }
    }

    #endregion
}