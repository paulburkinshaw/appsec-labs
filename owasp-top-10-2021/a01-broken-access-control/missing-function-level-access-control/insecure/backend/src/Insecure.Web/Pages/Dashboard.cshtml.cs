using Insecure.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Net.Http.Headers;

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
            var role = jsonWebToken.Claims.Single(x => x.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")?.Value;
    
            var httpClient = _httpClientFactory.CreateClient("Insecure.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

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
