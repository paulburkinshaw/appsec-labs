using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

IHostEnvironment env = builder.Environment;

var logger = LoggerFactory.Create(config =>
{
    config.AddConsole();
    config.AddConfiguration(builder.Configuration.GetSection("Logging"));
}).CreateLogger("Program");

logger.LogInformation($"Environment: {env.EnvironmentName}");
logger.LogInformation($"ContentRootPath: {env.ContentRootPath}");
logger.LogInformation($"IsDevelopment: {env.IsDevelopment}");

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var config = builder.Configuration;

// Generate RSA key pair
using (var publicPrivate = new RSACryptoServiceProvider(2048))
{
    config["Authentication:Schemes:Bearer:RsaKeyPair:PublicKey:Value"] = publicPrivate.ExportRSAPublicKeyPem();
    config["Authentication:Schemes:Bearer:RsaKeyPair:PrivateKey:Value"] = publicPrivate.ExportRSAPrivateKeyPem();
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapControllers();

app.UseAuthentication();
app.UseAuthorization();

app.Run();