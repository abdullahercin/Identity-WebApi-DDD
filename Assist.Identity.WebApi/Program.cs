using Assist.Identity.Application.Extensions;
using Assist.Identity.Infrastructure.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Clean Architecture Layers
builder.Services.AddApplicationServices();                    // Application Layer
builder.Services.AddInfrastructureServices(builder.Configuration); // Infrastructure Layer

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

// CORS
app.UseCors("AllowAll");

app.UseHttpsRedirection();

app.UseAuthentication();  // JWT Authentication middleware
app.UseAuthorization();   // Authorization middleware

app.MapControllers();

app.Run();
