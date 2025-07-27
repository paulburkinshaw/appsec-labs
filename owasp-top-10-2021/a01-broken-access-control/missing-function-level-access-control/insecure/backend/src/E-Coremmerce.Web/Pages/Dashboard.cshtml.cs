using ECoremmerce.Web.Models;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.JsonWebTokens;

namespace ECoremmerce.Web.Pages
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
            var jtw = HttpContext.Session.GetString("JWT");

            var jsonWebToken = new JsonWebToken(jtw ?? string.Empty);
            var name = jsonWebToken.Claims.Single(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value;
            var role = jsonWebToken.Claims.Single(x => x.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")?.Value;
         
            Username = name ?? "Unknown User";

            var httpClient = _httpClientFactory.CreateClient("ECoremmerce.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jtw);

            var endpoint = role switch
            {
                "User" => "user/dashboard",
                "Admin" => "admin/dashboard",
                _ => throw new UnauthorizedAccessException("User does not have the required role to access this page.")
            };
           
            using HttpResponseMessage response = await httpClient.GetAsync(endpoint);

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
