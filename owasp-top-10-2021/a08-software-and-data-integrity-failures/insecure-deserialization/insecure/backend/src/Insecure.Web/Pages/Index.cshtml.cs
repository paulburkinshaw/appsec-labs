using Insecure.API.Models;
using Insecure.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text;

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

        JsonSerializerSettings JsonSerializerSettings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All,
            TypeNameAssemblyFormatHandling = TypeNameAssemblyFormatHandling.Full
        };

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

            #region Get Cookie  
            var dashboardSortSettings = new DashboardSortSettings();
            var cookieValue = Request.Cookies["dashboardSortSettings"];
            if (!string.IsNullOrEmpty(cookieValue))
            {
                try
                {
                    dashboardSortSettings = JsonConvert.DeserializeObject<DashboardSortSettings>(cookieValue, JsonSerializerSettings);
                    if (dashboardSortSettings == null)
                        throw new Exception($"unable to deserialize cookie value: {cookieValue}");

                    ViewModel.DashboardSortSettings = dashboardSortSettings;
                }
                catch (JsonSerializationException ex)
                {
                    // Oops: developer tries to help debug by including full deserialized object in error
                    var deserializedObj = JsonConvert.DeserializeObject(cookieValue, JsonSerializerSettings);
                    throw new JsonSerializationException(
                        $"Dashboard settings type mismatch. Full object: {JsonConvert.SerializeObject(deserializedObj)}",
                        ex
                    );
                }
            }
            #endregion

            #region Send API Request
            await SendApiRequest(jwt, dashboardSortSettings);
            #endregion

            return Page();
        }

        public async Task<IActionResult> OnPostSortAsync()
        {
            if (ViewModel.DashboardSortSettings == null)
                throw new ArgumentNullException(nameof(ViewModel.DashboardSortSettings));

            var jwt = _memoryCache.Get<string>($"jwt:{User?.Identity?.Name}");
            if (String.IsNullOrEmpty(jwt))
            {
                _logger.LogWarning("JWT not found in cache for user {Username}. Redirecting to login.", User?.Identity?.Name);
                return RedirectToPage("/Account/Login");
            }

            // Set Cookie         
            Response.Cookies.Append("dashboardSortSettings", JsonConvert.SerializeObject(ViewModel.DashboardSortSettings, JsonSerializerSettings));

            await SendApiRequest(jwt, ViewModel.DashboardSortSettings);
            return Page();
        }

        private async Task SendApiRequest(string jwt, DashboardSortSettings dashboardSortSettings)
        {
            string dashboardSortSettingsStr = JsonConvert.SerializeObject(dashboardSortSettings, JsonSerializerSettings);

            using StringContent jsonContent = new(
            dashboardSortSettingsStr,
            Encoding.UTF8,
            "application/json");

            var httpClient = _httpClientFactory.CreateClient("Insecure.API" ?? "");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            using HttpResponseMessage response = await httpClient.PostAsync("user/dashboard", jsonContent);

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
