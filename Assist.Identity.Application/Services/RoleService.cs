namespace Assist.Identity.Application.Services;

using Abstractions;
using Contracts;
using DTOs.Requests;
using DTOs.Responses;
using Models;
using Domain.Entities;
using AutoMapper;

/// <summary>
/// Role Service Implementation
/// Role management use case'lerinin concrete implementation'ı
/// </summary>
public class RoleService : IRoleService
{
    private readonly IRoleRepository _roleRepository;
    private readonly IUserRepository _userRepository;
    private readonly ICacheService _cacheService;
    private readonly IMapper _mapper;

    public RoleService(
        IRoleRepository roleRepository,
        IUserRepository userRepository,
        ICacheService cacheService,
        IMapper mapper)
    {
        _roleRepository = roleRepository;
        _userRepository = userRepository;
        _cacheService = cacheService;
        _mapper = mapper;
    }

    #region Role CRUD Operations

    public async Task<ApiResponse<RoleResponse>> CreateRoleAsync(CreateRoleRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // Business rule: Role name unique olmalı
            if (await _roleRepository.RoleExistsAsync(request.Name, cancellationToken: cancellationToken))
            {
                return ApiResponse<RoleResponse>.ErrorResult("A role with this name already exists", "ROLE_ALREADY_EXISTS");
            }

            // Domain entity oluşturma
            var role = Role.Create(request.Name, request.Description);

            // Permission assignment logic implement edilecek
            // foreach (var permissionName in request.PermissionNames)
            // {
            //     var permission = await _permissionRepository.GetByNameAsync(permissionName);
            //     if (permission != null)
            //     {
            //         role.AddPermission(permission);
            //     }
            // }

            // Persistence
            var createdRole = await _roleRepository.AddAsync(role, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveByPatternAsync("roles:*", cancellationToken);

            // Response mapping
            var response = _mapper.Map<RoleResponse>(createdRole);

            return ApiResponse<RoleResponse>.SuccessResult(response, "Role created successfully");
        }
        catch (ArgumentException ex)
        {
            return ApiResponse<RoleResponse>.ErrorResult(ex.Message, "VALIDATION_ERROR");
        }
        catch (Exception ex)
        {
            return ApiResponse<RoleResponse>.ErrorResult("An error occurred while creating role", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<RoleResponse>> GetRoleByIdAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        try
        {
            var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
            if (role == null)
            {
                return ApiResponse<RoleResponse>.ErrorResult("Role not found", "ROLE_NOT_FOUND");
            }

            var response = _mapper.Map<RoleResponse>(role);
            response.Permissions = role.GetPermissionNames().ToList();

            return ApiResponse<RoleResponse>.SuccessResult(response);
        }
        catch (Exception ex)
        {
            return ApiResponse<RoleResponse>.ErrorResult("An error occurred while retrieving role", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<RoleResponse>> GetRoleByNameAsync(string roleName, CancellationToken cancellationToken = default)
    {
        try
        {
            var role = await _roleRepository.GetByNameAsync(roleName, cancellationToken);
            if (role == null)
            {
                return ApiResponse<RoleResponse>.ErrorResult("Role not found", "ROLE_NOT_FOUND");
            }

            var response = _mapper.Map<RoleResponse>(role);
            response.Permissions = role.GetPermissionNames().ToList();

            return ApiResponse<RoleResponse>.SuccessResult(response);
        }
        catch (Exception ex)
        {
            return ApiResponse<RoleResponse>.ErrorResult("An error occurred while retrieving role", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<RoleResponse>> UpdateRoleAsync(Guid roleId, CreateRoleRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
            if (role == null)
            {
                return ApiResponse<RoleResponse>.ErrorResult("Role not found", "ROLE_NOT_FOUND");
            }

            // Name uniqueness check
            if (await _roleRepository.RoleExistsAsync(request.Name, roleId, cancellationToken))
            {
                return ApiResponse<RoleResponse>.ErrorResult("A role with this name already exists", "ROLE_ALREADY_EXISTS");
            }

            // Update logic (domain method'ları implement edilmeli)
            // role.UpdateDetails(request.Name, request.Description);

            await _roleRepository.UpdateAsync(role, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveByPatternAsync("roles:*", cancellationToken);

            var response = _mapper.Map<RoleResponse>(role);
            return ApiResponse<RoleResponse>.SuccessResult(response, "Role updated successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<RoleResponse>.ErrorResult("An error occurred while updating role", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> DeleteRoleAsync(Guid roleId, CancellationToken cancellationToken = default)
    {
        try
        {
            var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
            if (role == null)
            {
                return ApiResponse<bool>.ErrorResult("Role not found", "ROLE_NOT_FOUND");
            }

            // Business rule: Role'ü kullanan user varsa silinemez
            var usersWithRole = await _userRepository.GetUsersByRoleAsync(role.Name, cancellationToken);
            if (usersWithRole.Any())
            {
                return ApiResponse<bool>.ErrorResult("Cannot delete role that is assigned to users", "ROLE_IN_USE");
            }

            await _roleRepository.DeleteAsync(role, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveByPatternAsync("roles:*", cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Role deleted successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while deleting role", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Role Assignment Operations

    public async Task<ApiResponse<bool>> AssignRoleToUserAsync(AssignRoleRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(request.UserId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            var role = await _roleRepository.GetByNameAsync(request.RoleName, cancellationToken);
            if (role == null)
            {
                return ApiResponse<bool>.ErrorResult("Role not found", "ROLE_NOT_FOUND");
            }

            // Domain method ile role assignment
            user.AssignRole(role);

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveAsync($"user:{request.UserId}", cancellationToken);
            await _cacheService.RemoveByPatternAsync($"user:{request.UserId}:*", cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Role assigned successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while assigning role", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> RemoveRoleFromUserAsync(Guid userId, string roleName, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            var role = await _roleRepository.GetByNameAsync(roleName, cancellationToken);
            if (role == null)
            {
                return ApiResponse<bool>.ErrorResult("Role not found", "ROLE_NOT_FOUND");
            }

            // Domain method ile role removal
            user.RemoveRole(role);

            await _userRepository.UpdateAsync(user, cancellationToken);

            // Cache invalidation
            await _cacheService.RemoveAsync($"user:{userId}", cancellationToken);
            await _cacheService.RemoveByPatternAsync($"user:{userId}:*", cancellationToken);

            return ApiResponse<bool>.SuccessResult(true, "Role removed successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while removing role", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<List<RoleResponse>>> GetUserRolesAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var roles = await _roleRepository.GetRolesByUserIdAsync(userId, cancellationToken);
            var roleResponses = _mapper.Map<List<RoleResponse>>(roles);

            return ApiResponse<List<RoleResponse>>.SuccessResult(roleResponses);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<RoleResponse>>.ErrorResult("An error occurred while retrieving user roles", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Role Listing & Search

    public async Task<ApiResponse<List<RoleResponse>>> GetAllRolesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var roles = await _roleRepository.GetActiveRolesAsync(cancellationToken);
            var roleResponses = _mapper.Map<List<RoleResponse>>(roles);

            return ApiResponse<List<RoleResponse>>.SuccessResult(roleResponses);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<RoleResponse>>.ErrorResult("An error occurred while retrieving roles", "INTERNAL_ERROR");
        }
    }

    public async Task<PaginatedResponse<RoleResponse>> GetRolesAsync(int pageNumber = 1, int pageSize = 10, string? searchTerm = null, CancellationToken cancellationToken = default)
    {
        try
        {
            // Pagination logic implement edilmeli (IRoleRepository'de method yok)
            var roles = await _roleRepository.GetActiveRolesAsync(cancellationToken);
            var roleResponses = _mapper.Map<List<RoleResponse>>(roles);

            // Manual pagination (geçici)
            var totalCount = roleResponses.Count;
            var pagedRoles = roleResponses
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            var pagedResult = new PagedResult<RoleResponse>
            {
                Items = pagedRoles,
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
            };

            return PaginatedResponse<RoleResponse>.SuccessResult(pagedResult);
        }
        catch (Exception ex)
        {
            return PaginatedResponse<RoleResponse>.ErrorResult("An error occurred while retrieving roles", "INTERNAL_ERROR");
        }
    }

    #endregion

    #region Permission Management

    public async Task<ApiResponse<bool>> AddPermissionToRoleAsync(Guid roleId, string permissionName, CancellationToken cancellationToken = default)
    {
        try
        {
            // Permission management logic implement edilecek
            return ApiResponse<bool>.ErrorResult("Permission management not implemented", "NOT_IMPLEMENTED");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while adding permission", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> RemovePermissionFromRoleAsync(Guid roleId, string permissionName, CancellationToken cancellationToken = default)
    {
        try
        {
            // Permission management logic implement edilecek
            return ApiResponse<bool>.ErrorResult("Permission management not implemented", "NOT_IMPLEMENTED");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while removing permission", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<List<string>>> GetUserPermissionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<List<string>>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            var permissions = user.GetPermissions().ToList();
            return ApiResponse<List<string>>.SuccessResult(permissions);
        }
        catch (Exception ex)
        {
            return ApiResponse<List<string>>.ErrorResult("An error occurred while retrieving user permissions", "INTERNAL_ERROR");
        }
    }

    public async Task<ApiResponse<bool>> CheckUserPermissionAsync(Guid userId, string permissionName, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult("User not found", "USER_NOT_FOUND");
            }

            var hasPermission = user.HasPermission(permissionName);
            return ApiResponse<bool>.SuccessResult(hasPermission);
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResult("An error occurred while checking permission", "INTERNAL_ERROR");
        }
    }

    #endregion
}