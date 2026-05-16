using Insecure.API.Models;
using Insecure.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace Insecure.Web.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private IHttpClientFactory _httpClientFactory { get; set; }
        private readonly IMemoryCache _memoryCache;

        [BindProperty]
        public ViewModel ViewModel { get; set; } = new();

        public IndexModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, IMemoryCache memoryCache)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _memoryCache = memoryCache;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            #region Signin
            if (User.Identity == null)
                throw new UnauthorizedAccessException();

            var jwt = _memoryCache.Get<string>($"jwt:{User.Identity.Name}");
            if (String.IsNullOrEmpty(jwt))
            {
                _logger.LogWarning("JWT not found in cache for user {Username}. Redirecting to login.", User.Identity.Name);
                return RedirectToPage("/Account/Login");
            }

            ViewModel.Username = User.Identity.Name;
            #endregion

        
            #region Send API Request
            await SendApiRequest(jwt);
            #endregion

            return Page();
        }

        private async Task SendApiRequest(string jwt)
        {          
            var httpClient = _httpClientFactory.CreateClient("Insecure.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            using HttpResponseMessage response = await httpClient.GetAsync("user/dashboard");

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Failed to load user/dashboard. Status code: {response.StatusCode}");
                RedirectToPage("/Error");
            }

            var dashboard = await response.Content.ReadFromJsonAsync<Dashboard>();
            ViewModel.WorkItems = dashboard?.WorkItems ?? new List<WorkItem>();
        }
    }
}
