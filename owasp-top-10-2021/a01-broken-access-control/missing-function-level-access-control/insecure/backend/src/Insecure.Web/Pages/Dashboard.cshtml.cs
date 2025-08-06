using Insecure.Web.Models;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace Insecure.Web.Pages
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
            if (roleClaims == null || !roleClaims.Any(x => x.Value == "User" || x.Value == "Admin"))
                throw new UnauthorizedAccessException();

            var dashboardEndpoint = roleClaims.FirstOrDefault()?.Value switch
            {
                "User" => "user/dashboard",
                "Admin" => "admin/dashboard"
            };

            var httpClient = _httpClientFactory.CreateClient("Insecure.API" ?? "");
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
