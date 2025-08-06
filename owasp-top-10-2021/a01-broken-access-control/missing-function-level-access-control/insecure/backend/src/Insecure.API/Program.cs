using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var logger = LoggerFactory.Create(config =>
{
    config.AddConsole();
    config.AddConfiguration(builder.Configuration.GetSection("Logging"));
}).CreateLogger("Program");

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidAudiences = builder.Configuration.GetSection("Authentication:Schemes:Bearer:ValidAudiences").Get<string[]>(),
            ValidIssuer = builder.Configuration["Authentication:Schemes:Bearer:ValidIssuer"],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                if (kid != builder.Configuration["Authentication:Schemes:Bearer:ValidKid"])
                {
                    throw new SecurityTokenException("Invalid key identifier (kid)");
                }

                try
                {
                    var response = new HttpClient().GetStringAsync(builder.Configuration["Authentication:Schemes:Bearer:ValidJwksUri"]).Result;
                    var keys = new JsonWebKeySet(response).GetSigningKeys();
                    var matchingKeys = keys.Where(key => key.KeyId == kid).ToList();

                    if (matchingKeys.Count == 0)
                    {
                        throw new SecurityTokenException("No matching key found");
                    }

                    return matchingKeys;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, ex.Message);
                    throw;
                }

            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
