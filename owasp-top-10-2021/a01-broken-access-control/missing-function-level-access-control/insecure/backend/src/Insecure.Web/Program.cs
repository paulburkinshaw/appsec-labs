var builder = WebApplication.CreateBuilder(args);

var config = builder.Configuration;

var logger = LoggerFactory.Create(config =>
{
    config.AddConsole();
    config.AddConfiguration(builder.Configuration.GetSection("Logging"));
}).CreateLogger("Program");

builder.Services.AddHttpClient("Insecure.API", client =>
{
    client.BaseAddress = new Uri(config["Services:Insecure.API:Url"]);
});
builder.Services.AddHttpClient("Authentication.API", client =>
{
    client.BaseAddress = new Uri(config["Services:Authentication.API:Url"]);
});

// Add services to the container.
builder.Services.AddRazorPages();

// set up the in-memory session provider with a default in-memory implementation of IDistributedCache
//builder.Services.AddDistributedMemoryCache();
//builder.Services.AddSession(options =>
//{
//    options.IdleTimeout = TimeSpan.FromMinutes(1);
//    options.Cookie.HttpOnly = true;
//    options.Cookie.IsEssential = true;
//});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

app.UseRouting();

// app.UseSession();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
