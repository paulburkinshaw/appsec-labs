using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Secure.Web.Models;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace Secure.Web.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private IHttpClientFactory _httpClientFactory { get; set; }
        private readonly IMemoryCache _memoryCache;

        public ViewModel ViewModel = new ViewModel();

        public string Username { get; set; }

        public IndexModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, IMemoryCache memoryCache)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _memoryCache = memoryCache;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = User.Identity ?? throw new UnauthorizedAccessException();
            var role = User.FindFirst(ClaimTypes.Role)?.Value ?? throw new UnauthorizedAccessException("Role not found in claims.");

            Username = user?.Name;

            if (!_memoryCache.TryGetValue($"jwt:{user.Name}", out string jwt))
            {
                _logger.LogWarning("JWT not found in cache for user {Username}. Redirecting to login.", Username);
                return RedirectToPage("/Account/Login");              
            }

            var dashboardEndpoint = role switch
            {
                "User" => "user/dashboard",
                "Admin" => "admin/dashboard"
            };

            var httpClient = _httpClientFactory.CreateClient("Secure.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

            using HttpResponseMessage response = await httpClient.GetAsync(dashboardEndpoint);
            if (response.IsSuccessStatusCode)
            {
                var dashboardViewModel = await response.Content.ReadFromJsonAsync<ViewModel>();
                if (dashboardViewModel != null)
                {
                    ViewModel = dashboardViewModel;
                    return Page();                   
                }                    
                else
                {
                    _logger.LogWarning("DashboardViewModel deserialization returned null for user {Username}.", Username);
                    return RedirectToPage("/Error");
                }               
            }
            else
            {
                _logger.LogInformation($"Failed to load user/dashboard. Status code: {response.StatusCode}");
                return RedirectToPage("/Error");
            }
               
        }

    }
}
