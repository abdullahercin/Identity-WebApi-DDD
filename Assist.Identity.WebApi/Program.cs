using Assist.Identity.Application.Extensions;
using Assist.Identity.Infrastructure.Configuration;
using Assist.Identity.Infrastructure.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// JWT Authentication - using configuration
var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>();
if (jwtSettings == null)
{
    throw new InvalidOperationException("JWT configuration is missing");
}

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = jwtSettings.Issuer;
        options.Audience = jwtSettings.Audience;
        options.RequireHttpsMetadata = false; // Development only

        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            ClockSkew = TimeSpan.Zero
        };
    });

// Authorization policies
builder.Services.AddAuthorization(options =>
{
    // Default policy: require authenticated user
    options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    // Admin policy: require Admin role
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));

    // Manager policy: require Manager or Admin role
    options.AddPolicy("ManagerOrAdmin", policy =>
        policy.RequireRole("Manager", "Admin"));
});

// Clean Architecture Layers
builder.Services.AddApplicationServices();                    // Application Layer

// Infrastructure Services Integration
// Bu tek satır tüm Infrastructure layer'ını integrate eder:
// - Redis connection ve configuration
// - Email service configuration  
// - Cache service registration
// - Password hashing service
// - JWT token service
// - Health checks
// - Configuration validation
builder.Services.AddInfrastructureServices(builder.Configuration);

builder.Services.AddPersistenceServices(builder.Configuration);

// CORS (if needed for frontend)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Health check endpoints for monitoring
// Production'da load balancer ve monitoring systems bu endpoint'leri kullanır
app.MapHealthChecks("/health");
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});
app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("live")
});


// CORS
app.UseCors("AllowAll");

app.UseHttpsRedirection();

app.UseAuthentication();  // JWT Authentication middleware
app.UseAuthorization();   // Authorization middleware

app.MapControllers();

try
{
    app.Logger.LogInformation("Starting Assist Identity API...");

    // Log configuration summary
    app.Logger.LogInformation("Configuration Summary:");
    app.Logger.LogInformation("- JWT Issuer: {JwtIssuer}", jwtSettings.Issuer);
    app.Logger.LogInformation("- JWT Audience: {JwtAudience}", jwtSettings.Audience);
    app.Logger.LogInformation("- Access Token Expiration: {AccessTokenExpiration} minutes", jwtSettings.AccessTokenExpirationMinutes);
    app.Logger.LogInformation("- Refresh Token Expiration: {RefreshTokenExpiration} days", jwtSettings.RefreshTokenExpirationDays);

    app.Run();
}
catch (Exception ex)
{
    app.Logger.LogCritical(ex, "Application startup failed");
    throw;
}
