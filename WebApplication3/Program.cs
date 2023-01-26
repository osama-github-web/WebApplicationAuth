//using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication3.Context;
using WebApplication3.Models;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager configuration = builder.Configuration;
// Add services to the container.

//For Entity Framework
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(configuration.GetConnectionString("ConnStr")));

//For Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();
//Jwt Authentication Confiiguration Start

    builder.Services.Configure<IdentityOptions>(options =>
    {
        // Default Password settings.
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        //options.Password.RequiredLength = 3;
        //options.Password.RequiredUniqueChars = 1;
    });
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey= true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});

builder.Services.AddControllers();
//Jwt Authentication Configuration End
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();
app.MapControllers();

#region token
//app.MapGet("security/message", () => { return "Hello World";  }).RequireAuthorization();
//app.MapPost("/Security/CreateToken",
//    [AllowAnonymous] 
//    (User user) =>
//    {
//        if(user.UserName == "osama" && user.Password == "osama")
//        {
//            var issuer = builder.Configuration["Jwt:Issuer"];
//            var audience = builder.Configuration["Jwt:Audience"];
//            var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:key"]);

//            var tokenDescriptor = new SecurityTokenDescriptor
//            {
//                Subject = new ClaimsIdentity(new[]
//                {
//                    new Claim("Id", Guid.NewGuid().ToString()),
//                    new Claim(JwtRegisteredClaimNames.Sub , user.UserName),
//                    new Claim(JwtRegisteredClaimNames.Email , user.UserName),
//                    new Claim(JwtRegisteredClaimNames.Name, user.UserName),
//                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
//                }),
//                Expires = DateTime.UtcNow.AddMinutes(20),
//                Issuer = issuer,
//                Audience = audience,
//                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256Signature)
//            };
//            var tokenHandler = new JwtSecurityTokenHandler();
//            var token = tokenHandler.CreateToken(tokenDescriptor);
//            var jwtToken = tokenHandler.WriteToken(token);
//            var stringToken = tokenHandler.WriteToken(token);
//            return Results.Ok(stringToken);
//        }
//        return Results.Unauthorized();
//    }
//    );
#endregion

app.UseAuthentication();
app.UseAuthorization();
app.Run();
