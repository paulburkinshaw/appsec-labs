using Secure.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace Secure.Web.Pages
{
    public class DashboardModel : PageModel
    {
        private readonly ILogger<DashboardModel> _logger;
        private IHttpClientFactory _httpClientFactory { get; set; }

        public DashboardViewModel ViewModel = new DashboardViewModel();

        public string Username { get; set; }

        public DashboardModel(ILogger<DashboardModel> logger, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        public async Task OnGetAsync()
        {       
            var jwt = HttpContext.Request.Query["jwt"].ToString();
            var jsonWebToken = new JsonWebToken(jwt ?? string.Empty);      
           
            var roleClaims = jsonWebToken.Claims.Where(x => x.Type == ClaimTypes.Role);
            var roleClaim = roleClaims.Where(x => x.Value == "User" || x.Value == "Admin").FirstOrDefault();

            var dashboardEndpoint = roleClaim?.Value switch
            {
                "User" => "user/dashboard",
                "Admin" => "admin/dashboard",
                _ => throw new UnauthorizedAccessException()
            };

            var httpClient = _httpClientFactory.CreateClient("Secure.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

            using HttpResponseMessage response = await httpClient.GetAsync(dashboardEndpoint);
            if (response.IsSuccessStatusCode)
            {
                var dashboardViewModel = await response.Content.ReadFromJsonAsync<DashboardViewModel>();

                if (dashboardViewModel != null)
                    ViewModel = dashboardViewModel;
                else
                    _logger.LogWarning("DashboardViewModel deserialization returned null.");
            }
            else
                _logger.LogInformation($"Failed to load user/dashboard. Status code: {response.StatusCode}");
        }
    }
}
